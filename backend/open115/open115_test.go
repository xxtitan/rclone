package open115

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/backend/open115/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fstest"
	"github.com/rclone/rclone/fstest/fstests"
	"github.com/rclone/rclone/lib/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigRequiresAppIDForQRCodeAuthorization(t *testing.T) {
	m := configmap.Simple{}
	regInfo := fs.MustFind("open115")
	assert.Equal(t, fs.OptionHideConfigurator, regInfo.Options.Get("app_id").Hide)
	assert.Equal(t, fs.OptionHideConfigurator, regInfo.Options.Get("refresh_token").Hide)
	assert.Equal(t, fs.OptionHideConfigurator, regInfo.Options.Get(config.ConfigToken).Hide)
	out, err := regInfo.Config(context.Background(), "test", m, fs.ConfigIn{
		State:  "choose_auth_type_done",
		Result: "auth",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	assert.Equal(t, "authorize", out.State)
	assert.Equal(t, "app_id", out.Option.Name)
	assert.True(t, out.Option.Required)
	assert.Contains(t, out.Option.Help, "https://open.115.com/")
}

func TestConfigRequiresRefreshTokenForTokenAuthorization(t *testing.T) {
	out, err := fs.MustFind("open115").Config(context.Background(), "test", configmap.Simple{}, fs.ConfigIn{
		State:  "choose_auth_type_done",
		Result: "token",
	})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	assert.Equal(t, "authorize_token", out.State)
	assert.Equal(t, "refresh_token", out.Option.Name)
	assert.True(t, out.Option.IsPassword)
}

func TestConfigRunsAuthorizationAfterAdvanced(t *testing.T) {
	regInfo := fs.MustFind("open115")
	m := configmap.Simple{}
	out, err := fs.BackendConfig(context.Background(), "test", m, regInfo, configmap.Simple{}, fs.ConfigIn{State: fs.ConfigAll})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	assert.Equal(t, "config_fs_advanced", out.Option.Name)
	advancedState := out.State

	advanced, err := fs.BackendConfig(context.Background(), "test", m, regInfo, configmap.Simple{}, fs.ConfigIn{State: advancedState, Result: "true"})
	require.NoError(t, err)
	require.NotNil(t, advanced.Option)
	assert.Equal(t, config.ConfigEncoding, advanced.Option.Name)

	out, err = fs.BackendConfig(context.Background(), "test", m, regInfo, configmap.Simple{}, fs.ConfigIn{State: advancedState, Result: "false"})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	assert.Equal(t, "auth_type", out.Option.Name)

	out, err = fs.BackendConfig(context.Background(), "test", m, regInfo, configmap.Simple{}, fs.ConfigIn{State: out.State, Result: "auth"})
	require.NoError(t, err)
	require.NotNil(t, out.Option)
	assert.Equal(t, "app_id", out.Option.Name)
}

type failReader struct {
	read bool
}

func (r *failReader) Read([]byte) (int, error) {
	r.read = true
	return 0, errors.New("unexpected read")
}

type readerOnly struct {
	r *bytes.Reader
}

func (r *readerOnly) Read(p []byte) (int, error) {
	return r.r.Read(p)
}

type noHashObject struct {
	fs.Object
}

func (o noHashObject) Hash(context.Context, hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

func mustSHA1(t *testing.T, data []byte) string {
	sha1Hash, err := calculateSHA1(bytes.NewReader(data))
	require.NoError(t, err)
	return sha1Hash
}

func TestPrepareFileForUploadUsesSourceSHA1(t *testing.T) {
	ctx := context.Background()
	data := []byte("source data")
	src := object.NewMemoryObject("file.txt", time.Now(), data)
	in := &failReader{}

	prepared, err := prepareFileForUpload(ctx, in, src, int64(len(data)))
	require.NoError(t, err)
	defer prepared.cleanup()

	assert.Equal(t, mustSHA1(t, data), prepared.sha1Hash)
	assert.Nil(t, prepared.readSeeker)
	assert.Same(t, in, prepared.reader)
	assert.False(t, in.read)
}

func TestPrepareFileForUploadCalculatesSHA1FromSourceObject(t *testing.T) {
	ctx := context.Background()
	data := []byte("source object data")
	src := noHashObject{Object: object.NewMemoryObject("file.txt", time.Now(), data)}
	in := &failReader{}

	prepared, err := prepareFileForUpload(ctx, in, src, int64(len(data)))
	require.NoError(t, err)
	defer prepared.cleanup()

	assert.Equal(t, mustSHA1(t, data), prepared.sha1Hash)
	assert.Nil(t, prepared.readSeeker)
	assert.Same(t, in, prepared.reader)
	assert.False(t, in.read)
}

func TestPreparedUploadSignCheckUsesSourceRange(t *testing.T) {
	ctx := context.Background()
	data := []byte("0123456789abcdef")
	src := object.NewMemoryObject("file.txt", time.Now(), data)
	in := &failReader{}

	prepared, err := prepareFileForUpload(ctx, in, src, int64(len(data)))
	require.NoError(t, err)
	defer prepared.cleanup()

	sha1Hash, err := prepared.calculateSignCheckSHA1(ctx, src, 2, 5)
	require.NoError(t, err)

	assert.Equal(t, mustSHA1(t, []byte("2345")), sha1Hash)
	assert.Nil(t, prepared.readSeeker)
	assert.False(t, in.read)
}

func TestPrepareFileForUploadFallsBackToTempFile(t *testing.T) {
	ctx := context.Background()
	data := []byte("stream-only data")
	in := &readerOnly{r: bytes.NewReader(data)}

	prepared, err := prepareFileForUpload(ctx, in, nil, int64(len(data)))
	require.NoError(t, err)
	defer prepared.cleanup()

	assert.Equal(t, mustSHA1(t, data), prepared.sha1Hash)
	require.NotNil(t, prepared.readSeeker)
	require.NoError(t, prepared.rewindForUpload())

	got, err := io.ReadAll(prepared.reader)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestSourceObjectUnwrapsOverrideRemote(t *testing.T) {
	src := object.NewMemoryObject("file.txt", time.Now(), []byte("data"))
	wrapped := fs.NewOverrideRemote(src, "renamed.txt")

	assert.Same(t, src, sourceObject(wrapped))
}

func TestParseSignCheckRange(t *testing.T) {
	start, end, err := parseSignCheckRange("2-5", 6)
	require.NoError(t, err)
	assert.Equal(t, int64(2), start)
	assert.Equal(t, int64(5), end)
	for _, signCheck := range []string{"", "-1-2", "-1", "3-2", "0-6", "x-1"} {
		_, _, err := parseSignCheckRange(signCheck, 6)
		assert.Error(t, err, signCheck)
	}
}

func TestValidateInitUploadData(t *testing.T) {
	callback := api.Callback{Callback: "callback", CallbackVar: "vars"}
	for _, data := range []api.InitUploadData{
		{Status: 1, Bucket: "bucket", Object: "object", Callback: api.CallbackValue{Value: &callback}},
		{Status: 2, FileID: "id", PickCode: "pick"},
	} {
		require.NoError(t, validateInitUploadData(&data))
	}
	for _, data := range []api.InitUploadData{{Status: 0}, {Status: 1}, {Status: 2, FileID: "id"}, {Status: 7}} {
		assert.Error(t, validateInitUploadData(&data))
	}
}

func TestParseUploadResult(t *testing.T) {
	body, err := json.Marshal(api.UploadResultResponse{
		Response: api.Response{},
		Data: api.UploadResult{
			FileID:   "id",
			PickCode: "pick",
			FileSize: "4",
			SHA1:     "aabb",
		},
	})
	require.NoError(t, err)
	result, err := parseUploadResult(body, 4, "AABB")
	require.NoError(t, err)
	assert.Equal(t, "id", result.FileID)

	_, err = parseUploadResult([]byte(`{"state":true,"data":{"file_id":"","pick_code":"pick","file_size":4}}`), 4, "")
	assert.Error(t, err)
	_, err = parseUploadResult([]byte(`{"state":true,"data":{"file_id":"id","pick_code":"pick","file_size":3}}`), 4, "")
	assert.Error(t, err)
}

func TestPutUncheckedRejectsUnknownSizeWithoutReading(t *testing.T) {
	in := &failReader{}
	src := object.NewStaticObjectInfo("file.txt", time.Now(), -1, true, nil, nil)
	_, err := new(Fs).PutUnchecked(context.Background(), in, src)
	require.Error(t, err)
	assert.False(t, in.read)
}

func TestValidateUploadToken(t *testing.T) {
	now := time.Now()
	token := api.UploadTokenData{
		Endpoint:        "endpoint",
		AccessKeyID:     "id",
		AccessKeySecret: "secret",
		SecurityToken:   "token",
		Expiration:      now.Add(2 * time.Minute).Format(time.RFC3339),
	}
	require.NoError(t, validateUploadToken(&token, now))
	token.Expiration = now.Format(time.RFC3339)
	assert.ErrorIs(t, validateUploadToken(&token, now), errUploadTokenExpired)
	token.Expiration = "bad"
	assert.Error(t, validateUploadToken(&token, now))
}

func TestShouldRetryAPIResponse(t *testing.T) {
	for _, code := range []int{open115InternalErrorCode, open115OperationPendingCode} {
		retry, err := shouldRetry(context.Background(), nil, &api.Response{Code: code}, nil)
		assert.True(t, retry)
		assert.Error(t, err)
	}
	retry, err := shouldRetry(context.Background(), nil, &api.Response{Code: open115AccessLimitCode}, nil)
	assert.False(t, retry)
	assert.Error(t, err)
}

func TestHasAuthError(t *testing.T) {
	assert.True(t, hasAuthError(&api.TokenResponse{Response: api.Response{Code: 99}}))
	assert.True(t, hasAuthError(&api.TokenResponse{Response: api.Response{Code: 40140116}}))
	assert.True(t, hasAuthError(&api.TokenResponse{Response: api.Response{Errno: 40140120}}))
	assert.False(t, hasAuthError(&api.TokenResponse{Response: api.Response{Code: 1001}}))
}

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestOpen115:",
		NilObject:  (*Object)(nil),
	})
}

func TestIntegrationDuplicateFiles(t *testing.T) {
	fstest.Initialise()
	remote := *fstest.RemoteName
	if remote == "" {
		remote = "TestOpen115:"
	}
	subRemote, _, err := fstest.RandomRemoteName(remote)
	require.NoError(t, err)
	fRaw, err := fs.NewFs(context.Background(), subRemote)
	if errors.Is(err, fs.ErrorNotFoundInConfigFile) {
		t.Skipf("remote %q is not configured", remote)
	}
	require.NoError(t, err)
	f, ok := fRaw.(*Fs)
	require.True(t, ok)
	defer func() {
		entries, _ := f.List(context.Background(), "")
		for _, entry := range entries {
			if obj, ok := entry.(fs.Object); ok {
				_ = obj.Remove(context.Background())
			}
		}
		_ = f.Rmdir(context.Background(), "")
	}()

	var uploaded []fs.Object
	for _, data := range [][]byte{[]byte("first duplicate"), []byte("second duplicate")} {
		src := object.NewMemoryObject("duplicate.bin", time.Now(), data)
		obj, err := f.PutUnchecked(context.Background(), bytes.NewReader(data), src)
		require.NoError(t, err)
		uploaded = append(uploaded, obj)
	}
	require.NotEqual(t, objectID(uploaded[0]), objectID(uploaded[1]))
	entries, err := f.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, entries, 2)

	replacement := []byte("replacement duplicate")
	src := object.NewMemoryObject("duplicate.bin", time.Now(), replacement)
	newObj, err := f.Put(context.Background(), bytes.NewReader(replacement), src)
	require.NoError(t, err)
	entries, err = f.List(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.NotEmpty(t, objectID(newObj))
}

func TestIntegrationServerSideReplace(t *testing.T) {
	fstest.Initialise()
	remote := *fstest.RemoteName
	if remote == "" {
		remote = "TestOpen115:"
	}
	subRemote, _, err := fstest.RandomRemoteName(remote)
	require.NoError(t, err)
	fRaw, err := fs.NewFs(context.Background(), subRemote)
	if errors.Is(err, fs.ErrorNotFoundInConfigFile) {
		t.Skipf("remote %q is not configured", remote)
	}
	require.NoError(t, err)
	f := fRaw.(*Fs)
	defer func() {
		entries, _ := f.List(context.Background(), "")
		for _, entry := range entries {
			if obj, ok := entry.(fs.Object); ok {
				_ = obj.Remove(context.Background())
			}
		}
		_ = f.Rmdir(context.Background(), "")
	}()
	upload := func(name, contents string) fs.Object {
		data := []byte(contents)
		src := object.NewMemoryObject(name, time.Now(), data)
		obj, err := f.Put(context.Background(), bytes.NewReader(data), src)
		require.NoError(t, err)
		return obj
	}

	copySource := upload("copy-source.bin", "new copy contents")
	copyPrevious := upload("copy-destination.bin", "old copy contents")
	copyResult, err := f.Copy(context.Background(), copySource, "copy-destination.bin")
	require.NoError(t, err)
	assert.NotEqual(t, objectID(copyPrevious), objectID(copyResult))
	copyStored, err := f.NewObject(context.Background(), "copy-destination.bin")
	require.NoError(t, err)
	assert.Equal(t, objectID(copyResult), objectID(copyStored))

	moveSource := upload("move-source.bin", "new move contents")
	upload("move-destination.bin", "old move contents")
	moveResult, err := f.Move(context.Background(), moveSource, "move-destination.bin")
	require.NoError(t, err)
	assert.Equal(t, objectID(moveSource), objectID(moveResult))
	_, err = f.NewObject(context.Background(), "move-source.bin")
	assert.ErrorIs(t, err, fs.ErrorObjectNotFound)
	moveStored, err := f.NewObject(context.Background(), "move-destination.bin")
	require.NoError(t, err)
	assert.Equal(t, objectID(moveSource), objectID(moveStored))

	entries, err := f.List(context.Background(), "")
	require.NoError(t, err)
	for _, entry := range entries {
		assert.NotContains(t, entry.Remote(), ".rclone-")
	}
}

func recycleBinCount(ctx context.Context, f *Fs) (int64, error) {
	opts := rest.Opts{
		Method:     http.MethodGet,
		RootURL:    baseAPI,
		Path:       "/open/rb/list",
		Parameters: url.Values{"limit": {"1"}, "offset": {"0"}},
	}
	var resp struct {
		api.Response
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := f.callAPI(ctx, opts, &resp, &resp.Response); err != nil {
		return 0, err
	}
	raw, ok := resp.Data["count"]
	if !ok {
		return 0, errors.New("recycle bin response has no count")
	}
	return strconv.ParseInt(strings.Trim(string(raw), `"`), 10, 64)
}

func TestIntegrationCleanUp(t *testing.T) {
	if os.Getenv("RCLONE_OPEN115_TEST_CLEANUP") != "1" {
		t.Skip("set RCLONE_OPEN115_TEST_CLEANUP=1 to permanently empty the account recycle bin")
	}
	fstest.Initialise()
	remote := *fstest.RemoteName
	if remote == "" {
		remote = "TestOpen115:"
	}
	subRemote, _, err := fstest.RandomRemoteName(remote)
	require.NoError(t, err)
	fRaw, err := fs.NewFs(context.Background(), subRemote)
	require.NoError(t, err)
	f, ok := fRaw.(*Fs)
	require.True(t, ok)

	data := []byte("open115 cleanup integration marker")
	src := object.NewMemoryObject("cleanup-marker.bin", time.Now(), data)
	obj, err := f.Put(context.Background(), bytes.NewReader(data), src)
	require.NoError(t, err)
	require.NoError(t, obj.Remove(context.Background()))

	deadline := time.Now().Add(30 * time.Second)
	for {
		err = f.Rmdir(context.Background(), "")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	require.NoError(t, err)
	require.NoError(t, f.CleanUp(context.Background()))

	require.Eventually(t, func() bool {
		count, countErr := recycleBinCount(context.Background(), f)
		return countErr == nil && count == 0
	}, 30*time.Second, time.Second)
}
