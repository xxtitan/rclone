package netdisk115

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/rclone/rclone/backend/115netdisk/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/lib/pool"
	"github.com/rclone/rclone/lib/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type marshaledSHA1State []byte

func (s marshaledSHA1State) MarshalBinary() ([]byte, error) { return s, nil }

func TestOSSHashContext(t *testing.T) {
	h := sha1.New()
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	require.NoError(t, err)
	for _, length := range []uint64{0, 64, 1 << 29, (1 << 29) + 64, 5 << 30} {
		t.Run(strconv.FormatUint(length, 10), func(t *testing.T) {
			binary.BigEndian.PutUint64(state[88:], length)
			encoded, err := ossSHA1Context(marshaledSHA1State(state))
			require.NoError(t, err)
			body, err := base64.StdEncoding.DecodeString(encoded)
			require.NoError(t, err)
			var fields map[string]string
			require.NoError(t, json.Unmarshal(body, &fields))
			assert.Equal(t, "1732584193", fields["h0"])
			assert.Equal(t, strconv.FormatUint(uint64(uint32(length*8)), 10), fields["Nl"])
			assert.Equal(t, strconv.FormatUint(length>>29, 10), fields["Nh"])
		})
	}
	_, err = h.Write([]byte("unaligned"))
	require.NoError(t, err)
	_, err = ossSHA1Context(h.(encoding.BinaryMarshaler))
	require.Error(t, err)
	_, err = ossSHA1Context(marshaledSHA1State(state[:8]))
	require.Error(t, err)
}

func TestMultipartUpload(t *testing.T) {
	for _, test := range []struct {
		name                string
		stream              bool
		retry               bool
		fail                bool
		truncate            bool
		refresh             bool
		cancel              bool
		unaligned           bool
		completeRefreshFail bool
		account             bool
		limitedMemory       bool
	}{
		{name: "parallel seekable"},
		{name: "parallel stream", stream: true},
		{name: "parallel stream with limited memory", stream: true, limitedMemory: true},
		{name: "retry part", retry: true},
		{name: "account network retries", stream: true, account: true, retry: true},
		{name: "abort on part failure", fail: true},
		{name: "abort on short stream", stream: true, truncate: true},
		{name: "refresh shared credentials", refresh: true},
		{name: "cancel active parts", stream: true, cancel: true},
		{name: "align part boundaries", unaligned: true},
		{name: "abort after completion credential refresh fails", completeRefreshFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("TMPDIR", tempDir)
			const chunkSize = 128 * 1024
			data := make([]byte, 4*chunkSize+17)
			for i := range data {
				data[i] = byte(i / chunkSize)
			}
			var mu sync.Mutex
			active, peak, aborts, completes, refreshes := 0, 0, 0, 0, 0
			attempts := make(map[int]int)
			parts := make(map[int][]byte)
			ready := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ctx = accounting.WithStatsGroup(ctx, t.Name())
			if test.limitedMemory {
				var config *fs.ConfigInfo
				ctx, config = fs.AddConfig(ctx)
				config.MaxBufferMemory = 1
			}
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				switch {
				case r.URL.Path == "/3.0/gettoken.php":
					mu.Lock()
					refreshes++
					mu.Unlock()
					assert.Equal(t, http.MethodPost, r.Method)
					assert.NoError(t, r.ParseForm())
					assert.Equal(t, "123", r.Form.Get("userid"))
					if test.completeRefreshFail {
						assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"StatusCode": "500"}))
						return
					}
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
						"StatusCode": "200", "endpoint": server.URL, "AccessKeyId": "renewed", "AccessKeySecret": "secret",
						"SecurityToken": "renewed-token", "Expiration": time.Now().Add(time.Hour).Format(time.RFC3339),
					}))
				case r.Method == http.MethodPost && query.Has("uploads"):
					assert.False(t, query.Has("sequential"))
					assert.True(t, query.Has("x-oss-enable-sha1"))
					assert.True(t, query.Has("withHashContext"))
					_, err := io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>test-bucket</Bucket><Key>test-object</Key><UploadId>test-upload</UploadId></InitiateMultipartUploadResult>`)
					assert.NoError(t, err)
				case r.Method == http.MethodPut:
					assert.Equal(t, "test-upload", query.Get("uploadId"))
					number, err := strconv.Atoi(query.Get("partNumber"))
					assert.NoError(t, err)
					body, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					mu.Lock()
					attempts[number]++
					attempt := attempts[number]
					active++
					peak = max(peak, active)
					if active == 4 || (test.truncate && active == 3) {
						select {
						case <-ready:
						default:
							close(ready)
						}
					}
					mu.Unlock()
					defer func() { mu.Lock(); active--; mu.Unlock() }()
					select {
					case <-ready:
					case <-ctx.Done():
						return
					}
					if test.cancel {
						cancel()
						return
					}
					if test.refresh && strings.HasPrefix(r.Header.Get("Authorization"), "OSS key:") {
						w.WriteHeader(http.StatusForbidden)
						_, err = io.WriteString(w, `<Error><Code>SecurityTokenExpired</Code><Message>expired credentials</Message></Error>`)
						assert.NoError(t, err)
						return
					}
					if test.refresh {
						assert.Equal(t, "renewed-token", r.Header.Get("x-oss-security-token"))
					}
					if number == 2 && (test.fail || (test.retry && attempt == 1)) {
						status, code := http.StatusBadRequest, "InvalidArgument"
						if test.retry {
							status, code = http.StatusServiceUnavailable, "ServiceUnavailable"
						}
						w.WriteHeader(status)
						_, err = fmt.Fprintf(w, "<Error><Code>%s</Code><Message>part failure</Message></Error>", code)
						assert.NoError(t, err)
						return
					}
					start := (number - 1) * chunkSize
					assert.Equal(t, data[start:min(start+chunkSize, len(data))], body)
					if number > 1 {
						encoded, err := base64.StdEncoding.DecodeString(r.Header.Get("x-oss-hash-ctx"))
						assert.NoError(t, err)
						var fields map[string]string
						assert.NoError(t, json.Unmarshal(encoded, &fields))
						assert.Equal(t, "sha1", fields["hash_type"])
						assert.Equal(t, "0", fields["num"])
						assert.Empty(t, fields["data"])
						state := make([]byte, 96)
						copy(state, "sha\x01")
						for i := range 5 {
							word, err := strconv.ParseUint(fields["h"+strconv.Itoa(i)], 10, 32)
							assert.NoError(t, err)
							binary.BigEndian.PutUint32(state[4+i*4:], uint32(word))
						}
						low, err := strconv.ParseUint(fields["Nl"], 10, 32)
						assert.NoError(t, err)
						high, err := strconv.ParseUint(fields["Nh"], 10, 32)
						assert.NoError(t, err)
						prefixSize := (high<<32 | low) / 8
						assert.Equal(t, uint64(start), prefixSize)
						binary.BigEndian.PutUint64(state[88:], prefixSize)
						h := sha1.New()
						assert.NoError(t, h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state))
						_, err = h.Write(body)
						assert.NoError(t, err)
						want := sha1.Sum(data[:start+len(body)])
						assert.Equal(t, want[:], h.Sum(nil))
					} else {
						assert.Empty(t, r.Header.Get("x-oss-hash-ctx"))
					}
					mu.Lock()
					parts[number] = body
					mu.Unlock()
					checksum := md5.Sum(body)
					w.Header().Set("ETag", hex.EncodeToString(checksum[:]))
					w.Header().Set("x-oss-hash-crc64ecma", strconv.FormatUint(crc64.Checksum(body, oss.CrcTable()), 10))
				case r.Method == http.MethodPost:
					mu.Lock()
					defer mu.Unlock()
					completes++
					assert.Zero(t, active)
					if test.completeRefreshFail {
						w.WriteHeader(http.StatusForbidden)
						_, err := io.WriteString(w, `<Error><Code>SecurityTokenExpired</Code><Message>expired credentials</Message></Error>`)
						assert.NoError(t, err)
						return
					}
					var completion struct {
						Parts []oss.UploadPart `xml:"Part"`
					}
					assert.NoError(t, xml.NewDecoder(r.Body).Decode(&completion))
					assert.Len(t, completion.Parts, 5)
					var assembled []byte
					for i, part := range completion.Parts {
						assert.Equal(t, i+1, part.PartNumber)
						assembled = append(assembled, parts[part.PartNumber]...)
					}
					assert.Equal(t, data, assembled)
					assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("callback")), r.Header.Get("x-oss-callback"))
					assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("variables")), r.Header.Get("x-oss-callback-var"))
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"state": true, "data": map[string]any{"file_id": "123", "pick_code": "pickcode", "file_size": len(data)}}))
				case r.Method == http.MethodDelete:
					mu.Lock()
					defer mu.Unlock()
					aborts++
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected OSS request: %s %s", r.Method, r.URL)
				}
			}))
			defer server.Close()
			f := &Fs{}
			hc := server.Client()
			hc.Transport = &rewriteTransport{target: server.URL, underlying: hc.Transport}
			client, err := newClient(rest.NewClient(hc), hc, &Options{Cookie: "UID=123_device; CID=client; SEID=session"})
			require.NoError(t, err)
			f.client = client
			var in io.Reader = bytes.NewReader(data)
			if test.truncate {
				in = bytes.NewReader(data[:3*chunkSize+1])
			}
			if test.stream {
				in = struct{ io.Reader }{in}
			}
			if test.account {
				tr := accounting.Stats(ctx).NewTransferRemoteSize("multipart.bin", int64(len(data)), nil, nil)
				defer tr.Done(ctx, nil)
				in = tr.Account(ctx, io.NopCloser(in))
			}
			initData := api.InitUploadData{Bucket: "test-bucket", Object: "test-object", Callback: api.CallbackValue{Value: &api.Callback{Callback: "callback", CallbackVar: "variables"}}}
			token := api.UploadTokenData{Endpoint: server.URL, AccessKeyID: "key", AccessKeySecret: "secret", SecurityToken: "token"}
			partSize := int64(chunkSize)
			if test.unaligned {
				partSize -= 17
			}
			result, err := f.uploadMultipartToOSS(ctx, in, initData, token, int64(len(data)), partSize, "")
			if test.fail || test.truncate || test.cancel || test.completeRefreshFail {
				require.Error(t, err)
				if test.cancel {
					assert.True(t, errors.Is(err, context.Canceled))
				}
				assert.Equal(t, 1, aborts)
				if test.completeRefreshFail {
					assert.Equal(t, 1, completes)
					assert.Equal(t, 1, refreshes)
					require.ErrorContains(t, err, "STS request did not return StatusCode 200")
				} else {
					assert.Zero(t, completes)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "123", result.FileID)
				assert.Equal(t, 1, completes)
				assert.Zero(t, aborts)
				assert.Equal(t, 4, peak)
				if test.retry {
					assert.Equal(t, 2, attempts[2])
				}
				if test.account {
					assert.Equal(t, int64(len(data)+chunkSize), accounting.Stats(ctx).GetBytes())
				}
				if test.refresh {
					assert.Equal(t, 1, refreshes)
					assert.Equal(t, 2, attempts[1])
					assert.Equal(t, 2, attempts[2])
					assert.Equal(t, 2, attempts[3])
				}
			}
			files, err := os.ReadDir(tempDir)
			require.NoError(t, err)
			assert.Empty(t, files, "staged parts must be removed")
		})
	}
}

func TestOSSHTTPSettings(t *testing.T) {
	data := []byte("network settings")
	callback := func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, data, body)
		w.Header().Set("x-oss-hash-crc64ecma", strconv.FormatUint(crc64.Checksum(body, oss.CrcTable()), 10))
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"state": true, "data": map[string]any{
			"file_id": "123", "pick_code": "pickcode", "file_size": len(data)}}))
	}
	for _, mode := range []string{"proxy", "TLS"} {
		t.Run(mode, func(t *testing.T) {
			ctx, config := fs.AddConfig(context.Background())
			config.LowLevelRetries = 1
			config.UserAgent = "upload-test"
			var endpoint string
			var proxyRequests atomic.Int32
			if mode == "proxy" {
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("upload bypassed the configured proxy")
					callback(w, r)
				}))
				defer target.Close()
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					proxyRequests.Add(1)
					assert.True(t, r.URL.IsAbs())
					assert.Equal(t, "upload-test", r.UserAgent())
					callback(w, r)
				}))
				defer proxy.Close()
				config.HTTPProxy = proxy.URL
				endpoint = target.URL
			} else {
				server := httptest.NewTLSServer(http.HandlerFunc(callback))
				defer server.Close()
				config.InsecureSkipVerify = true
				endpoint = server.URL
			}
			initData := api.InitUploadData{Bucket: "test-bucket", Object: "test-object", Callback: api.CallbackValue{Value: &api.Callback{Callback: "callback", CallbackVar: "variables"}}}
			token := api.UploadTokenData{Endpoint: endpoint, AccessKeyID: "key", AccessKeySecret: "secret", SecurityToken: "token"}
			_, err := (&Fs{}).uploadToOSS(ctx, bytes.NewReader(data), initData, token, int64(len(data)), "")
			require.NoError(t, err)
			if mode == "proxy" {
				assert.Equal(t, int32(1), proxyRequests.Load())
			}
		})
	}
}

func TestPrepareUploadAccounting(t *testing.T) {
	ctx := accounting.WithStatsGroup(context.Background(), t.Name())
	data := []byte("hash preparation must not count as a transfer")
	tr := accounting.Stats(ctx).NewTransferRemoteSize("prepared.bin", int64(len(data)), nil, nil)
	defer tr.Done(ctx, nil)
	in := tr.Account(ctx, io.NopCloser(bytes.NewReader(data)))
	prepared, err := prepareFileForUpload(ctx, in, nil, int64(len(data)))
	require.NoError(t, err)
	defer prepared.cleanup()
	assert.Zero(t, accounting.Stats(ctx).GetBytes())
	for attempt := range 2 {
		require.NoError(t, prepared.rewindForUpload())
		body, err := io.ReadAll(prepared.reader)
		require.NoError(t, err)
		assert.Equal(t, data, body)
		assert.Equal(t, int64((attempt+1)*len(data)), accounting.Stats(ctx).GetBytes())
	}
}

func TestMultipartBufferMemoryLimit(t *testing.T) {
	const childEnv = "RCLONE_TEST_MULTIPART_MEMORY_LIMIT"
	if os.Getenv(childEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMultipartBufferMemoryLimit$")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "limited memory upload must finish: %s", output)
		return
	}
	// Initialise the process-wide pool limit before creating the async input buffer.
	config := fs.GetConfig(context.Background())
	config.MaxBufferMemory = 32 * fs.Mebi
	config.BufferSize = 16 * fs.Mebi
	ctx := accounting.WithStatsGroup(context.Background(), t.Name())
	data := make([]byte, 21*mib)
	tr := accounting.Stats(ctx).NewTransferRemoteSize("buffered.bin", int64(len(data)), nil, nil)
	defer tr.Done(ctx, nil)
	in := tr.Account(ctx, io.NopCloser(bytes.NewReader(data))).WithBuffer()
	defer func() { assert.NoError(t, in.Close()) }()
	require.Eventually(t, func() bool { return pool.Global().InUse() >= 16 }, time.Second, time.Millisecond)
	reader, start, cleanup, err := stageUploadPart(ctx, in.OldStream(), 20*mib)
	require.NoError(t, err)
	defer cleanup()
	_, err = reader.Seek(start, io.SeekStart)
	require.NoError(t, err)
	n, err := io.Copy(io.Discard, reader)
	require.NoError(t, err)
	assert.Equal(t, int64(20*mib), n)
}
