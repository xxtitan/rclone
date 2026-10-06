package netdisk115

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fstest/fstests"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration runs the standard backend compatibility suite.
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{RemoteName: "Test115Netdisk:", NilObject: (*Object)(nil)})
}

func TestCookieConfiguration(t *testing.T) {
	ctx := context.Background()
	reg := fs.MustFind("115netdisk")
	assert.Equal(t, "115 Netdisk", reg.Description)
	assert.Nil(t, reg.Options.Get("cookie_file"))
	m := configmap.Simple{}
	out, err := configure(ctx, "test", m, fs.ConfigIn{})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	require.Len(t, out.Option.Examples, 2)
	assert.Equal(t, "qr", out.Option.Examples[0].Value)
	assert.Equal(t, "cookie", out.Option.Examples[1].Value)
	out, err = configure(ctx, "test", m, fs.ConfigIn{State: out.State, Result: "cookie"})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	assert.Equal(t, "cookie", out.Option.Name)
	assert.True(t, out.Option.Required)
	assert.True(t, out.Option.Sensitive)
	for _, value := range []string{"UID=123_device; CID=client; SEID=session; extra=preserved",
		`{"UID":"123_device","CID":"client","SEID":"session","extra":"preserved"}`} {
		out, err := configure(ctx, "test", m, fs.ConfigIn{State: "cookie", Result: value})
		require.NoError(t, err)
		assert.Nil(t, out)
		assert.Equal(t, value, m["cookie"])
		out, err = configure(ctx, "test", m, fs.ConfigIn{})
		require.NoError(t, err)
		assert.Nil(t, out)
	}
	for _, value := range []string{"", "UID=123_device; CID=client", "invalid header"} {
		previous := m["cookie"]
		_, err := configure(ctx, "test", m, fs.ConfigIn{State: "cookie", Result: value})
		require.Error(t, err)
		assert.Equal(t, previous, m["cookie"], "invalid input must preserve the saved credentials")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	m = configmap.Simple{}
	_, err = configure(ctx, "test", m, fs.ConfigIn{State: "auth_choice", Result: "qr"})
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, m)
}

func TestCookieImport(t *testing.T) {
	for _, value := range []string{`{"cookies":{"UID":"123_device","CID":"client","SEID":"session","extra":"preserved"}}`,
		`{"UID":"123_device","CID":"client","SEID":"session","extra":"preserved"}`, "UID=123_device; CID=client; SEID=session; extra=preserved"} {
		cookies, err := loadCookies(&Options{Cookie: value})
		require.NoError(t, err)
		assert.Equal(t, "preserved", cookies["extra"])
		assert.Equal(t, "UID=123_device; CID=client; SEID=session; extra=preserved; 115_lang=zh", cookieHeader(cookies, nil))
	}
	_, err := loadCookies(&Options{Cookie: "UID=123_device; CID=client"})
	require.Error(t, err)
	_, err = loadCookies(&Options{Cookie: "UID=123_device; CID=client; SEID=session\r\nX-Test=yes"})
	require.Error(t, err)
}

func TestDownloadCookieReplacement(t *testing.T) {
	old := map[string]string{"UID": "123_device", "CID": "client", "SEID": "session", "0123456789abcdef0123456789abcdef": "old"}
	header := cookieHeader(old, map[string]string{"abcdef0123456789abcdef0123456789": "new"})
	assert.NotContains(t, header, "=old")
	assert.Contains(t, header, "abcdef0123456789abcdef0123456789=new")
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	retry, err := shouldRetry(ctx, nil, nil, ctx.Err())
	assert.False(t, retry)
	require.ErrorIs(t, err, context.Canceled)
}

func TestUnknownSizeDoesNotReadInput(t *testing.T) {
	f := &Fs{}
	in := &unreadableReader{}
	_, err := f.PutUnchecked(context.Background(), in, object.NewStaticObjectInfo("unknown.bin", time.Now(), -1, true, nil, nil))
	require.Error(t, err)
	assert.False(t, in.read)
}

type unreadableReader struct{ read bool }

func (r *unreadableReader) Read([]byte) (int, error) { r.read = true; return 0, context.Canceled }

func TestRawRequestFieldSafety(t *testing.T) {
	_, err := indexedIDs(nil)
	require.Error(t, err)
	_, err = indexedIDs([]string{""})
	require.Error(t, err)
	form, err := indexedIDs([]string{"123", "456"})
	require.NoError(t, err)
	assert.Equal(t, "123", form.Get("fid[0]"))
	assert.Equal(t, "456", form.Get("fid[1]"))
	_, err = json.Marshal(form)
	require.NoError(t, err)
}

func TestEncodedBodyHasContentLength(t *testing.T) {
	payload := []byte{0, 1, 2, 3, 0xff, 0x80}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, int64(len(payload)), r.ContentLength)
		assert.Empty(t, r.TransferEncoding)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, payload, body)
		_, err = w.Write([]byte(`{"state":true}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	c, err := newClient(rest.NewClient(server.Client()), server.Client(), &Options{Cookie: "UID=123_device; CID=client; SEID=session"})
	require.NoError(t, err)
	_, _, err = c.raw(context.Background(), &rest.Opts{Method: "POST", RootURL: server.URL, ContentType: "application/x-www-form-urlencoded", Body: bytes.NewReader(payload)})
	require.NoError(t, err)
}

func TestScopedTransportUserAgent(t *testing.T) {
	want := "Mozilla/5.0; Mac OS X/13.0; 115Life/37.3.1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, want, r.UserAgent())
		_, err := w.Write([]byte(`{"state":true}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	parent := context.Background()
	original := fs.GetConfig(parent).UserAgent
	ctx, config := fs.AddConfig(parent)
	config.UserAgent = want
	hc := fshttp.NewClient(ctx)
	c, err := newClient(rest.NewClient(hc), hc, &Options{Cookie: "UID=123_device; CID=client; SEID=session", UserAgent: want})
	require.NoError(t, err)
	_, _, err = c.raw(ctx, &rest.Opts{Method: "GET", RootURL: server.URL})
	require.NoError(t, err)
	assert.Equal(t, original, fs.GetConfig(parent).UserAgent)
}

func TestSavedSessionAccountConsistency(t *testing.T) {
	_, err := loadCookies(&Options{Cookie: `{"userId":456,"cookies":{"UID":"123_device","CID":"client","SEID":"session"}}`})
	require.Error(t, err)
	_, err = loadCookies(&Options{Cookie: `{"userId":123,"cookies":{"UID":"123_device","CID":"client","SEID":"session"}}`})
	require.NoError(t, err)
}

func TestCleanUpSelectsAllRecycleIDs(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			assert.Equal(t, "/rb", r.URL.Path)
			_, err := w.Write([]byte(`{"state":true,"count":"2","rb_pass":0,"data":[{"id":"10"},{"id":"20"}]}`))
			require.NoError(t, err)
			return
		}
		posts++
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "/rb/secret_del", r.URL.Path)
		assert.Equal(t, "10,20", r.Form.Get("tid"))
		assert.Equal(t, "000000", r.Form.Get("password"))
		_, err := w.Write([]byte(`{"state":true}`))
		require.NoError(t, err)
	}))
	defer server.Close()
	hc := server.Client()
	hc.Transport = &rewriteTransport{target: server.URL, underlying: hc.Transport}
	c, err := newClient(rest.NewClient(hc), hc, &Options{Cookie: "UID=123_device; CID=client; SEID=session"})
	require.NoError(t, err)
	f := &Fs{client: c, pacer: fs.NewPacer(context.Background(), pacer.NewDefault())}
	require.NoError(t, f.CleanUp(context.Background()))
	assert.Equal(t, 1, posts)
}

func TestDeletePendingReadback(t *testing.T) {
	for _, test := range []struct {
		name      string
		message   string
		entries   string
		wantPosts int
		wantReads int
		wantError bool
	}{
		{name: "already deleted", message: "删除操作尚未执行完成，请稍后再试", entries: `[]`, wantPosts: 1, wantReads: 1},
		{name: "retry remaining selection", message: "删除操作尚未执行完成，请稍后再试", entries: `[{"fid":"20","cid":"30","n":"remaining.bin","s":1}]`, wantPosts: 2, wantReads: 1},
		{name: "authentication failure", message: "请重新登录", wantPosts: 1, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			posts, reads := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					reads++
					assert.Equal(t, "/files", r.URL.Path)
					assert.Equal(t, "30", r.URL.Query().Get("cid"))
					_, err := io.WriteString(w, `{"state":true,"cid":"30","offset":0,"count":`+map[bool]string{true: "1", false: "0"}[test.entries != `[]`]+`,"data":`+test.entries+`}`)
					require.NoError(t, err)
					return
				}
				posts++
				require.NoError(t, r.ParseForm())
				assert.Equal(t, "/rb/delete", r.URL.Path)
				assert.Equal(t, "30", r.Form.Get("pid"))
				if posts == 1 {
					assert.Equal(t, "10", r.Form.Get("fid[0]"))
					assert.Equal(t, "20", r.Form.Get("fid[1]"))
					require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"state": false, "errno": 990009, "error": test.message}))
					return
				}
				assert.Equal(t, "20", r.Form.Get("fid[0]"))
				assert.NotContains(t, r.Form, "fid[1]")
				_, err := io.WriteString(w, `{"state":true}`)
				require.NoError(t, err)
			}))
			defer server.Close()
			hc := server.Client()
			hc.Transport = &rewriteTransport{target: server.URL, underlying: hc.Transport}
			c, err := newClient(rest.NewClient(hc), hc, &Options{Cookie: "UID=123_device; CID=client; SEID=session"})
			require.NoError(t, err)
			f := &Fs{client: c, pacer: fs.NewPacer(context.Background(), pacer.NewDefault())}
			_, err = f.deleteFiles(context.Background(), []string{"10", "20"}, "30")
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.wantPosts, posts)
			assert.Equal(t, test.wantReads, reads)
		})
	}
}

type rewriteTransport struct {
	target     string
	underlying http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	endpoint, err := url.Parse(t.target)
	if err != nil {
		return nil, err
	}
	clone := request.Clone(request.Context())
	clone.URL.Scheme, clone.URL.Host = endpoint.Scheme, endpoint.Host
	transport := t.underlying
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(clone)
}
