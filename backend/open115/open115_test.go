package open115

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fstest/fstests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "open115:",
		NilObject:  (*Object)(nil),
	})
}
