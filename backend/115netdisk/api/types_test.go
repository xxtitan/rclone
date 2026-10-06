package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBusinessFailureWithZeroCode(t *testing.T) {
	var response Response
	require.NoError(t, json.Unmarshal([]byte(`{"state":false,"errno":0,"error":"密钥错误"}`), &response))
	assert.False(t, response.Success())
	assert.Contains(t, response.ErrorDetails(), "密钥错误")
	require.NoError(t, json.Unmarshal([]byte(`{"state":true,"errno":"","error":""}`), &response))
	assert.True(t, response.Success())
	require.NoError(t, json.Unmarshal([]byte(`{}`), &response))
	assert.False(t, response.Success())
}

func TestExactIdentifiersAndSizes(t *testing.T) {
	var response FileListResponse
	require.NoError(t, json.Unmarshal([]byte(`{"state":true,"errNo":0,"cid":"123","count":2,"offset":0,"limit":1000,"data":[{"cid":"9007199254740993","pid":"123","n":"folder"},{"fid":"9007199254740994","cid":"123","n":"file.bin","s":"9007199254740993","pc":"pick","sha":"0123456789abcdef0123456789abcdef01234567","te":"1700000000"}]}`), &response))
	require.Len(t, response.Data, 2)
	assert.Equal(t, "9007199254740993", response.Data[0].FID)
	assert.Equal(t, "9007199254740994", response.Data[1].FID)
	assert.Equal(t, "9007199254740993", response.Data[1].FS.String())
	assert.Equal(t, int64(1700000000), response.Data[1].UPT)
}

func TestCacheHitIsNotEmptyDirectory(t *testing.T) {
	var response FileListResponse
	require.NoError(t, json.Unmarshal([]byte(`{"state":true,"cid":"123","use_cache":1,"data":[]}`), &response))
	assert.True(t, response.UseCache)
	assert.False(t, response.CountPresent)
}

func TestInvalidFileMetadata(t *testing.T) {
	for _, body := range []string{`{"state":true,"data":[{"fid":"123","cid":"0","n":"bad"}]}`, `{"state":true,"data":[{"fid":"123","cid":"0","n":"bad","s":-1}]}`, `{"state":true,"data":[{"fid":"123","cid":"0","n":"bad","s":1.5}]}`} {
		var response FileListResponse
		require.Error(t, json.Unmarshal([]byte(body), &response))
	}
}

func TestTopLevelCreateAndCallbackData(t *testing.T) {
	var folder FolderCreateResponse
	require.NoError(t, json.Unmarshal([]byte(`{"state":true,"errno":"","cid":"123","cname":"folder"}`), &folder))
	require.NotNil(t, folder.Data)
	assert.Equal(t, "123", folder.Data.FileID.String())
	var callback UploadResultResponse
	require.NoError(t, json.Unmarshal([]byte(`{"state":true,"code":0,"data":{"file_id":"123","pick_code":"pick","file_size":1024}}`), &callback))
	assert.Equal(t, "123", callback.Data.FileID)
	assert.Equal(t, "1024", callback.Data.FileSize.String())
}
