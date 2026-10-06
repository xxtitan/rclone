package open115

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/chunksize"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fs/operations"
	"github.com/rclone/rclone/fstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func integrationFS(t *testing.T) *Fs {
	t.Helper()
	fstest.Initialise()
	remote := *fstest.RemoteName
	if remote == "" {
		remote = "TestOpen115:"
	}
	scope, _, err := fstest.RandomRemoteName(remote)
	require.NoError(t, err)
	raw, err := fs.NewFs(context.Background(), scope)
	if errors.Is(err, fs.ErrorNotFoundInConfigFile) {
		t.Skip("TestOpen115 is not configured")
	}
	require.NoError(t, err)
	f := raw.(*Fs)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		err := operations.Purge(ctx, f, "")
		if !errors.Is(err, fs.ErrorDirNotFound) {
			assert.NoError(t, err)
		}
	})
	return f
}

func uploadContents(t *testing.T, f *Fs, name string, data []byte) fs.Object {
	t.Helper()
	source := object.NewMemoryObject(name, time.Now(), data)
	obj, err := f.Put(context.Background(), bytes.NewReader(data), source)
	require.NoError(t, err)
	return obj
}

func verifyContents(t *testing.T, obj fs.Object, want []byte) {
	t.Helper()
	reader, err := obj.Open(context.Background())
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	assert.Equal(t, want, data)
}

func TestIntegrationMultipart(t *testing.T) {
	f := integrationFS(t)
	for _, test := range []struct {
		name   string
		size   int
		stream bool
	}{
		{name: "seekable", size: 21*mib + 1},
		{name: "stream", size: 41*mib + 1, stream: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, test.size)
			_, err := rand.Read(data)
			require.NoError(t, err)
			name := test.name + ".bin"
			source := object.NewMemoryObject(name, time.Now(), data)
			var in io.Reader = bytes.NewReader(data)
			if test.stream {
				in = struct{ io.Reader }{in}
			}
			obj, err := f.Put(context.Background(), in, source)
			require.NoError(t, err)
			verifyContents(t, obj, data)
			reader, err := obj.Open(context.Background(), &fs.RangeOption{Start: 20*mib - 32, End: 20*mib + 32})
			require.NoError(t, err)
			part, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.NoError(t, reader.Close())
			assert.Equal(t, data[20*mib-32:20*mib+33], part)
		})
	}
}

func TestIntegrationMultipartParallel(t *testing.T) {
	f := integrationFS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const name = "parallel-multipart.bin"
	data := make([]byte, 61*mib+17)
	_, err := rand.Read(data)
	require.NoError(t, err)
	digest := sha1.Sum(data)
	sha1Hash := strings.ToUpper(hex.EncodeToString(digest[:]))
	_, _, directoryID, err := f.createObject(ctx, name, time.Now(), int64(len(data)))
	require.NoError(t, err)
	initData, err := f.initializeUpload(ctx, name, directoryID, int64(len(data)), sha1Hash, func(start, end int64) (string, error) {
		check := sha1.Sum(data[start : end+1])
		return strings.ToUpper(hex.EncodeToString(check[:])), nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, initData.Status, "random input must use an ordinary upload")
	token, err := f.getValidUploadToken(ctx)
	require.NoError(t, err)
	target, err := url.Parse(token.Endpoint)
	require.NoError(t, err)
	target.Host = initData.Bucket + "." + target.Host
	proxy := httputil.NewSingleHostReverseProxy(target)
	var mu sync.Mutex
	active, peak, partRequests := 0, 0, 0
	proxy.Director = func(r *http.Request) {
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/"+initData.Bucket)
		r.URL.RawPath = ""
		r.Host = target.Host
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Query().Has("partNumber") {
			mu.Lock()
			active++
			partRequests++
			peak = max(peak, active)
			mu.Unlock()
			defer func() { mu.Lock(); active--; mu.Unlock() }()
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	token.Endpoint = server.URL
	result, err := f.uploadMultipartToOSS(ctx, bytes.NewReader(data), *initData, *token, int64(len(data)), int64(chunksize.Calculator(f, int64(len(data)), 10000, 20*fs.Mebi)), sha1Hash)
	require.NoError(t, err)
	mu.Lock()
	observedPeak, observedRequests := peak, partRequests
	mu.Unlock()
	assert.Greater(t, observedPeak, 1, "OSS part requests must overlap")
	assert.LessOrEqual(t, observedPeak, uploadConcurrency)
	assert.GreaterOrEqual(t, observedRequests, 4)
	obj, err := f.NewObject(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, result.FileID, objectID(obj))
	assert.Equal(t, int64(len(data)), obj.Size())
	gotSHA1, err := obj.Hash(ctx, hash.SHA1)
	require.NoError(t, err)
	assert.Equal(t, sha1Hash, strings.ToUpper(gotSHA1))
	verifyContents(t, obj, data)
	t.Logf("Verified %d bytes, %d part requests, peak concurrency %d, and complete downloaded contents", len(data), observedRequests, observedPeak)
}
