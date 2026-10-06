// Package netdisk115 provides an interface to the 115 Cloud Storage
package netdisk115

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/rclone/rclone/lib/random"

	"github.com/rclone/rclone/fs/fserrors"

	"github.com/rclone/rclone/lib/rest"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/rclone/rclone/backend/115netdisk/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/fs/chunksize"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/multipart"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/readers"
)

const (
	minSleep           = 100 * time.Millisecond // minSleep is the minimum sleep time between retries.
	maxSleep           = 5 * time.Second        // maxSleep is the maximum sleep time between retries.
	decayConstant      = 2                      // decayConstant is the backoff factor.
	rootID             = "0"                    // rootID is the ID of the root directory.
	fileCategoryFolder = "0"
	mib                = 1024 * 1024
	uploadConcurrency  = 4
)

// init registers the backend.
func init() {
	Register("115netdisk")
}

// Options configures the macOS client protocol and saved session.
type Options struct {
	// Cookie stores a Cookie header or dictionary JSON.
	Cookie string `config:"cookie"`
	// ClientVersion selects the macOS protocol version.
	ClientVersion string `config:"client_version"`
	// UserAgent overrides API and content request identity.
	UserAgent string `config:"user_agent"`
	// SecurityKey authorizes account-wide permanent recycle deletion.
	SecurityKey string `config:"security_key"`
	// Enc converts between rclone and API leaf names.
	Enc encoder.MultiEncoder `config:"encoding"`
}

// Fs is a directory-ID-based 115 netdisk filesystem.
type Fs struct {
	name     string
	root     string
	opt      Options
	features *fs.Features
	pacer    *fs.Pacer
	client   *client
	dirCache *dircache.DirCache
}

// setRoot sets the root directory path.
func (f *Fs) setRoot(root string) {
	f.root = strings.Trim(root, "/")
}

// Object represents an 115 drive file or directory.
type Object struct {
	fs       *Fs       // fs is the parent Fs.
	remote   string    // remote is the remote path.
	id       string    // id is the file ID.
	modTime  time.Time // modTime is the modification time.
	size     int64     // size is the file size.
	sha1     string    // sha1 is the SHA1 hash.
	pickCode string    // pickCode is the file pick code.
}

func objectID(obj fs.Object) string {
	if obj == nil {
		return ""
	}
	if o, ok := obj.(*Object); ok {
		return o.id
	}
	return ""
}

func removePreviousObjectAfterUpload(ctx context.Context, previous, current fs.Object) error {
	if previous == nil {
		return nil
	}
	previousID := objectID(previous)
	currentID := objectID(current)
	if previousID == "" {
		return errors.New("failed to remove previous object after successful upload: previous object id is empty")
	}
	if currentID == "" {
		return errors.New("failed to remove previous object after successful upload: uploaded object id is empty")
	}
	if previousID == currentID {
		return nil
	}
	if err := previous.Remove(ctx); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		rollbackErr := current.Remove(cleanupCtx)
		return errors.Join(fmt.Errorf("failed to remove previous object after successful upload: %w", err), rollbackErr)
	}
	return nil
}

// ------------------------------------------------------------

// Name returns the name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root returns the root path of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("115 drive: %s", f.name)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// NewFs constructs a new Fs object from the name and root configuration.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}
	root = strings.Trim(root, "/")
	ctx, clientConfig := fs.AddConfig(ctx)
	if opt.ClientVersion == "" {
		opt.ClientVersion = defaultClientVersion
	}
	if opt.UserAgent == "" {
		opt.UserAgent = "Mozilla/5.0; Mac OS X/13.0; 115Life/" + opt.ClientVersion
	}
	clientConfig.UserAgent = opt.UserAgent
	fc := fshttp.NewClient(ctx)
	rc := rest.NewClient(fc)
	c, err := newClient(rc, fc, opt)
	if err != nil {
		return nil, err
	}
	f := &Fs{
		name:   name,
		root:   root,
		opt:    *opt,
		pacer:  fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		client: c,
	}
	// Set up path handling
	f.setRoot(root)
	// Set features
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
		NoMultiThreading:        true,
		DuplicateFiles:          true,
	}).Fill(ctx, f)

	// Create the root directory cache
	f.dirCache = dircache.New(f.root, rootID, f)

	// Find the current root
	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		if !errors.Is(err, fs.ErrorDirNotFound) {
			return nil, err
		}
		// Assume it is a file
		newRoot, remote := dircache.SplitPath(root)
		tempF := *f
		tempF.dirCache = dircache.New(newRoot, rootID, &tempF)
		tempF.root = newRoot
		// Make new Fs which is the parent
		err = tempF.dirCache.FindRoot(ctx, false)
		if err != nil {
			if !errors.Is(err, fs.ErrorDirNotFound) {
				return nil, err
			}
			// No root so return old f
			return f, nil
		}
		_, err := tempF.newObjectWithInfo(ctx, remote, nil)
		if err != nil {
			if errors.Is(err, fs.ErrorObjectNotFound) {
				// File doesn't exist so return old f
				return f, nil
			}
			return nil, err
		}
		f.features.Fill(ctx, &tempF)
		// XXX: update the old f here instead of returning tempF, since
		// `features` were already filled with functions having *f as a receiver.
		// See https://github.com/rclone/rclone/issues/2182
		f.dirCache = tempF.dirCache
		f.root = tempF.root
		// return an error with a fs which points to the parent
		return f, fs.ErrorIsFile
	}
	return f, nil
}

// FindLeaf finds a file or directory named leaf in the directory directoryID.
func (f *Fs) FindLeaf(ctx context.Context, directoryID, leafName string) (string, bool, error) {
	entries, err := f.listAll(ctx, directoryID)
	if err != nil {
		return "", false, err
	}
	var fileID string
	for _, item := range entries {
		if f.opt.Enc.ToStandardName(item.FN) == leafName {
			if item.FC == fileCategoryFolder {
				return item.FID, true, nil
			}
			fileID = item.FID
		}
	}
	return fileID, false, nil
}

// CreateDir creates the directory named dirName in the directory with directoryID.
func (f *Fs) CreateDir(ctx context.Context, dirID, dirName string) (string, error) {
	resp, err := f.createFolder(ctx, dirID, dirName)
	if err != nil {
		existingID, found, findErr := f.FindLeaf(ctx, dirID, dirName)
		if findErr == nil && found {
			return existingID, nil
		}
		return "", err
	}

	if resp.Data == nil {
		return "", fmt.Errorf("failed to create directory: %s", resp.Response.ErrorDetails())
	}
	return resp.Data.FileID.String(), nil
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	cid, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}
	items, err := f.listAll(ctx, cid)
	if err != nil {
		return nil, err
	}
	entries := make(fs.DirEntries, 0, len(items))
	for _, item := range items {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(item.FN))
		if item.FC == fileCategoryFolder {
			f.dirCache.Put(remote, item.FID)
			entries = append(entries, fs.NewDir(remote, time.Unix(item.UPT, 0)).SetID(item.FID))
		} else {
			o, err := f.newObjectWithInfo(ctx, remote, &item)
			if err != nil {
				return nil, err
			}
			entries = append(entries, o)
		}
	}
	return entries, nil
}

// NewObject finds the Object at remote. It returns fs.ErrorNotFound if the object isn't present.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

// newObjectWithInfo creates an Object from remote and *api.FileInfo.
//
// info can be nil - if so it will be fetched.
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *api.FileInfo) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	if info != nil {
		// Initialize using provided info
		err := o.setMetaData(info)
		if err != nil {
			return nil, err
		}
		return o, nil
	}
	// Find the file
	err := o.readMetaData(ctx)
	if err != nil {
		return nil, err
	}

	return o, nil
}

// createObject creates a new Object for upload
//
// Used to create new objects
func (f *Fs) createObject(ctx context.Context, remote string, modTime time.Time, size int64) (o *Object, leaf string, directoryID string, err error) {
	// Create the directory for the object if it doesn't exist
	leaf, directoryID, err = f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, leaf, directoryID, err
	}
	// Temporary Object under construction
	o = &Object{
		fs:     f,
		remote: remote,
	}
	return o, leaf, directoryID, nil
}

// Put uploads the object
//
// Copy the reader data to the object specified by remote.
//
// It returns the object created and an error, if any.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	existingObj, err := f.NewObject(ctx, src.Remote())
	if err != nil && !errors.Is(err, fs.ErrorObjectNotFound) {
		return nil, err
	}

	newObj, err := f.PutUnchecked(ctx, in, src, options...)
	if err != nil {
		return nil, err
	}

	if err := removePreviousObjectAfterUpload(ctx, existingObj, newObj); err != nil {
		return newObj, err
	}

	return newObj, nil
}

// PutUnchecked uploads the object without checking if it exists
//
// This will create a duplicate if the object already exists.
//
// Copy the reader data to the object specified by remote.
//
// It returns the object created and an error, if any.
func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Get file path and size
	remote := src.Remote()
	size := src.Size()
	modTime := src.ModTime(ctx)
	if size < 0 {
		return nil, errors.New("115netdisk requires a known file size")
	}
	if size == 0 {
		return nil, fs.ErrorCantUploadEmptyFiles
	}

	// Create object and ensure directory exists
	_, _, directoryID, err := f.createObject(ctx, remote, modTime, size)
	if err != nil {
		return nil, err
	}

	// Execute file upload
	return f.upload(ctx, in, src, remote, directoryID, size)
}

// Mkdir creates the container if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// Rmdir removes the directory.
//
// Returns an error if it isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	dirID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return err
	}

	resp, err := f.getFileList(ctx, dirID, 1, 0)
	if err != nil {
		return err
	}

	if len(resp.Data) > 0 {
		return fs.ErrorDirectoryNotEmpty
	}

	// Delete directory
	_, parentID, err := f.dirCache.FindPath(ctx, dir, false)
	if err != nil {
		return err
	}
	_, err = f.deleteFiles(ctx, []string{dirID}, parentID)
	if err != nil {
		return err
	}

	f.dirCache.FlushDir(dir)
	return nil
}

// Precision returns the modification time precision.
func (f *Fs) Precision() time.Duration {
	return fs.ModTimeNotSupported
}

// Hashes returns the supported hash types.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.SHA1)
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (usage *fs.Usage, err error) {
	userInfo, err := f.getUserInfo(ctx)
	if err != nil {
		return nil, err
	}
	total, err := userInfo.Data.RTSpaceInfo.AllTotal.Size.Int64()
	if err != nil {
		return nil, fmt.Errorf("failed to parse total quota: %w", err)
	}
	used, err := userInfo.Data.RTSpaceInfo.AllUse.Size.Int64()
	if err != nil {
		return nil, fmt.Errorf("failed to parse used quota: %w", err)
	}
	free, err := userInfo.Data.RTSpaceInfo.AllRemain.Size.Int64()
	if err != nil {
		return nil, fmt.Errorf("failed to parse free quota: %w", err)
	}
	usage = &fs.Usage{
		Total: fs.NewUsageValue(total),
		Used:  fs.NewUsageValue(used),
		Free:  fs.NewUsageValue(free),
	}
	return usage, nil
}

// ---------------------------------------------------------------------------

// ID returns the ID of the object.
func (o *Object) ID() string {
	return o.id
}

// setMetaData sets the metadata from info.
func (o *Object) setMetaData(info *api.FileInfo) error {
	// Ensure it's not a directory
	if info.FC == fileCategoryFolder {
		return fs.ErrorIsDir
	}

	// Set metadata
	o.id = info.FID
	o.pickCode = info.PC
	o.sha1 = strings.ToLower(info.SHA1)

	// Set size
	size, err := strconv.ParseInt(string(info.FS), 10, 64)
	if err != nil {
		return fmt.Errorf("[setMetaData] failed to parse file size %q: %w", info.FS, err)
	}
	o.size = size

	// Set modification time
	o.modTime = time.Unix(int64(info.UPT), 0)

	return nil
}

// readMetaData gets the metadata for the object.
func (o *Object) readMetaData(ctx context.Context) error {
	leaf, cid, err := o.fs.dirCache.FindPath(ctx, o.remote, false)
	if errors.Is(err, fs.ErrorDirNotFound) {
		return fs.ErrorObjectNotFound
	}
	if err != nil {
		return err
	}
	entries, err := o.fs.listAll(ctx, cid)
	if err != nil {
		return err
	}
	isDir := false
	for _, item := range entries {
		if o.fs.opt.Enc.ToStandardName(item.FN) == leaf {
			if item.FC == fileCategoryFolder {
				isDir = true
				continue
			}
			return o.setMetaData(&item)
		}
	}
	if isDir {
		return fs.ErrorIsDir
	}
	return fs.ErrorObjectNotFound
}

// Fs returns the parent Fs.
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// String returns a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects modTime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Size returns the file size in bytes
func (o *Object) Size() int64 {
	return o.size
}

// Storable returns true if the object is storable.
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
//
// See Open in the Object interface for documentation.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	fs.FixRangeOption(options, o.size)
	return o.fs.download(ctx, o.id, o.pickCode, o.size, options...)
}

// Update the object with the contents of the io.Reader, modTime and size
//
// If existing is set then it updates the object rather than creating a new one.
//
// The new object may have been created if an error is returned.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	size := src.Size()
	modTime := src.ModTime(ctx)
	if size < 0 {
		return errors.New("115netdisk requires a known file size")
	}
	if size == 0 {
		return fs.ErrorCantUploadEmptyFiles
	}

	// Create object and ensure directory exists using the original remote path
	_, _, directoryID, err := o.fs.createObject(ctx, o.remote, modTime, size)
	if err != nil {
		return err
	}

	// Execute file upload with the original remote path
	newObj, err := o.fs.upload(ctx, in, src, o.remote, directoryID, size)
	if err != nil {
		return err
	}

	// Type assertion to ensure we can access internal fields
	newO, ok := newObj.(*Object)
	if !ok {
		return fmt.Errorf("object returned is of wrong type")
	}

	if err := removePreviousObjectAfterUpload(ctx, o, newO); err != nil {
		return err
	}

	// Copy properties from the new object
	*o = *newO

	return nil
}

// Hash returns the SHA-1 of an object returning a lowercase hex string
//
// See Hash in the Object interface for documentation.
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t == hash.SHA1 {
		return o.sha1, nil
	}
	return "", hash.ErrUnsupported
}

// Remove an object
//
// See Remove in the Object interface for documentation.
func (o *Object) Remove(ctx context.Context) error {
	// Delete file
	_, parentID, err := o.fs.dirCache.FindPath(ctx, o.remote, false)
	if err != nil {
		return err
	}
	_, err = o.fs.deleteFiles(ctx, []string{o.id}, parentID)
	return err
}

// ---------------------------------------------------------------------------

// DirMove moves src, srcRemote to this remote at dstRemote
// using server-side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok {
		return fmt.Errorf("can't move directories across different remotes: %w", fs.ErrorCantDirMove)
	}

	srcID, srcDirectoryID, srcLeaf, dstDirectoryID, dstLeaf, err := f.dirCache.DirMove(ctx, srcFs.dirCache, srcFs.root, srcRemote, f.root, dstRemote)
	if err != nil {
		return err
	}

	// Use enhanced move logic for directories
	err = f.performMoveDirs(ctx, srcDirectoryID, dstDirectoryID, srcLeaf, dstLeaf, []string{srcID})
	if err != nil {
		return err
	}

	// Flush directory cache
	srcFs.dirCache.FlushDir(srcRemote)
	return nil
}

// Copy src to this remote using server-side copy operations.
//
// This is stored with the remote path given.
//
// It returns the destination Object and a possible error.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fmt.Errorf("can't copy across different remotes: %w", fs.ErrorCantCopy)
	}

	// Get source directory info
	srcLeaf, srcDirID, err := srcObj.fs.dirCache.FindPath(ctx, srcObj.remote, false)
	if err != nil {
		return nil, err
	}

	// Create the destination object and ensure directory exists
	dstLeaf, dstDirID, err := f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, err
	}
	if path.Ext(srcLeaf) != path.Ext(dstLeaf) {
		return nil, fs.ErrorCantCopy
	}

	if srcDirID == dstDirID && srcLeaf == dstLeaf {
		return srcObj, nil
	}
	previous, err := f.NewObject(ctx, remote)
	if err != nil && !errors.Is(err, fs.ErrorObjectNotFound) {
		return nil, err
	}
	backupLeaf, err := f.parkDestination(ctx, previous, dstDirID, dstLeaf)
	if errors.Is(err, errDestinationHasDuplicates) {
		return nil, fs.ErrorCantCopy
	}
	if err != nil {
		return nil, err
	}
	restorePrevious := func(cleanupCtx context.Context) error {
		if backupLeaf == "" {
			return nil
		}
		return f.renameFile(cleanupCtx, objectID(previous), dstLeaf)
	}

	info, err := f.copyWithTempDir(ctx, srcDirID, dstDirID, dstLeaf, []string{srcObj.id})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return nil, errors.Join(err, restorePrevious(cleanupCtx))
	}
	newObjRaw, err := f.newObjectWithInfo(ctx, remote, info)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, rollbackErr := f.deleteFiles(cleanupCtx, []string{info.FID}, dstDirID)
		return nil, errors.Join(err, rollbackErr, restorePrevious(cleanupCtx))
	}
	if previous != nil {
		if removeErr := previous.Remove(ctx); removeErr != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			rollbackErr := newObjRaw.Remove(cleanupCtx)
			restoreErr := f.renameFile(cleanupCtx, objectID(previous), dstLeaf)
			return newObjRaw, errors.Join(fmt.Errorf("failed to remove previous destination object: %w", removeErr), rollbackErr, restoreErr)
		}
	}

	// Flush directory cache
	dstDir, _ := f.getNormalizedPath(remote)
	f.dirCache.FlushDir(dstDir)

	return newObjRaw, nil
}

// Move src to this remote using server-side move operations.
//
// This is stored with the remote path given.
//
// It returns the destination Object and a possible error.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fmt.Errorf("can't move across different remotes: %w", fs.ErrorCantMove)
	}

	// Get source directory info
	srcLeaf, srcDirID, err := srcObj.fs.dirCache.FindPath(ctx, srcObj.remote, false)
	if err != nil {
		return nil, err
	}

	// Create the destination object and ensure directory exists
	dstLeaf, dstDirID, err := f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, err
	}
	if path.Ext(srcLeaf) != path.Ext(dstLeaf) {
		return nil, fs.ErrorCantMove
	}

	if srcDirID == dstDirID && srcLeaf == dstLeaf {
		return srcObj, nil
	}
	previous, err := f.NewObject(ctx, remote)
	if err != nil && !errors.Is(err, fs.ErrorObjectNotFound) {
		return nil, err
	}
	if previous != nil && objectID(previous) == srcObj.id {
		previous = nil
	}
	backupLeaf, err := f.parkDestination(ctx, previous, dstDirID, dstLeaf)
	if errors.Is(err, errDestinationHasDuplicates) {
		return nil, fs.ErrorCantMove
	}
	if err != nil {
		return nil, err
	}
	restorePrevious := func(cleanupCtx context.Context) error {
		if backupLeaf == "" {
			return nil
		}
		return f.renameFile(cleanupCtx, objectID(previous), dstLeaf)
	}

	// Move file with enhanced logic for different scenarios
	err = f.performMoveFiles(ctx, srcDirID, dstDirID, srcLeaf, dstLeaf, []string{srcObj.id})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return nil, errors.Join(err, restorePrevious(cleanupCtx))
	}
	newObj := *srcObj
	newObj.fs = f
	newObj.remote = remote
	if previous != nil {
		if removeErr := previous.Remove(ctx); removeErr != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			rollbackErr := f.performMoveFiles(cleanupCtx, dstDirID, srcDirID, dstLeaf, srcLeaf, []string{srcObj.id})
			restoreErr := restorePrevious(cleanupCtx)
			cancel()
			return &newObj, errors.Join(fmt.Errorf("failed to remove previous destination object: %w", removeErr), rollbackErr, restoreErr)
		}
	}

	// Flush directory cache
	dstDir, _ := f.getNormalizedPath(remote)
	f.dirCache.FlushDir(dstDir)

	return &newObj, nil
}

// DirCacheFlush flushes the directory cache - used in testing as an
// optional interface
func (f *Fs) DirCacheFlush() {
	f.dirCache.ResetRoot()
}

// CleanUp permanently empties the entire account recycle bin.
func (f *Fs) CleanUp(ctx context.Context) error {
	var ids []string
	var securityEnabled bool
	for page := 0; page < 100000; page++ {
		query := url.Values{"limit": {"100"}, "offset": {strconv.Itoa(len(ids))}, "format": {"json"}}
		body, _, err := f.client.raw(ctx, &rest.Opts{Method: "GET", RootURL: baseAPI, Path: "/rb", Parameters: query})
		if err != nil {
			return err
		}
		var state api.Response
		if err = json.Unmarshal(body, &state); err != nil {
			return err
		}
		if !state.Success() {
			return &apiError{response: state}
		}
		var pageData struct {
			Count    api.Int `json:"count"`
			Password api.Int `json:"rb_pass"`
			Data     []struct {
				ID api.String `json:"id"`
			} `json:"data"`
		}
		if err = json.Unmarshal(body, &pageData); err != nil {
			return err
		}
		securityEnabled = securityEnabled || pageData.Password != 0
		for _, item := range pageData.Data {
			if item.ID == "" {
				return errors.New("recycle entry has no identity")
			}
			ids = append(ids, string(item.ID))
		}
		if int64(len(ids)) >= int64(pageData.Count) {
			break
		}
		if len(pageData.Data) == 0 {
			return errors.New("incomplete recycle listing")
		}
		if page == 99999 {
			return errors.New("recycle listing exceeded its page limit")
		}
	}
	if len(ids) == 0 {
		return nil
	}
	password := f.opt.SecurityKey
	if password == "" {
		if securityEnabled {
			return errors.New("configure security_key to empty the account recycle bin")
		}
		password = "000000"
	}
	var response api.FileOperationResponse
	return f.callAPIWithForm(ctx, rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/rb/secret_del"},
		url.Values{"password": {password}, "tid": {strings.Join(ids, ",")}}, &response, &response.Response)
}

func parseSignCheckRange(signCheck string, size int64) (start, end int64, err error) {
	parts := strings.Split(signCheck, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid sign_check format %q", signCheck)
	}

	start, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid sign_check start: %w", err)
	}

	end, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid sign_check end: %w", err)
	}
	if start < 0 || end < start || end >= size {
		return 0, 0, fmt.Errorf("sign_check range %d-%d is outside file size %d", start, end, size)
	}

	return start, end, nil
}

func (f *Fs) newOSSBucket(ctx context.Context, token api.UploadTokenData, bucketName string) (*oss.Bucket, error) {
	if f.opt.UserAgent != "" {
		var config *fs.ConfigInfo
		ctx, config = fs.AddConfig(ctx)
		config.UserAgent = f.opt.UserAgent
	}
	ossClient, err := oss.New(token.Endpoint, token.AccessKeyID, token.AccessKeySecret,
		oss.SecurityToken(token.SecurityToken), oss.HTTPClient(fshttp.NewClient(ctx)))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSS client: %w", err)
	}
	bucket, err := ossClient.Bucket(bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to get OSS bucket: %w", err)
	}
	return bucket, nil
}

func shouldRetryOSS(ctx context.Context, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	var serviceErr oss.ServiceError
	if errors.As(err, &serviceErr) {
		status := serviceErr.StatusCode
		return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500, err
	}
	return fserrors.ShouldRetry(err), err
}

func isOSSAuthError(err error) bool {
	var serviceErr oss.ServiceError
	if !errors.As(err, &serviceErr) || serviceErr.StatusCode != http.StatusForbidden {
		return false
	}
	return strings.Contains(serviceErr.Code, "InvalidAccessKeyId") || strings.Contains(serviceErr.Code, "SecurityToken") || strings.Contains(serviceErr.Code, "AccessDenied")
}

func parseUploadResult(body []byte, wantSize int64, wantSHA1 string) (*api.UploadResult, error) {
	var response api.UploadResultResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse OSS callback: %w", err)
	}
	if !response.Success() {
		return nil, fmt.Errorf("OSS callback failed: %s", response.ErrorDetails())
	}
	result := &response.Data
	if result.FileID == "" || result.PickCode == "" {
		return nil, errors.New("OSS callback returned empty file_id or pick_code")
	}
	size, err := result.FileSize.Int64()
	if err != nil {
		return nil, fmt.Errorf("failed to parse OSS callback file size: %w", err)
	}
	if size != wantSize {
		return nil, fmt.Errorf("OSS callback file size %d does not match upload size %d", size, wantSize)
	}
	if result.SHA1 != "" && !strings.EqualFold(result.SHA1, wantSHA1) {
		return nil, fmt.Errorf("OSS callback SHA1 %q does not match upload SHA1 %q", result.SHA1, wantSHA1)
	}
	return result, nil
}

func (f *Fs) refreshOSSBucket(ctx context.Context, bucketName string) (*oss.Bucket, error) {
	token, err := f.validUploadToken(ctx, true)
	if err != nil {
		return nil, err
	}
	return f.newOSSBucket(ctx, *token, bucketName)
}

// uploadToOSS uploads a file to Alibaba Cloud OSS.
func (f *Fs) uploadToOSS(ctx context.Context, in io.Reader, initData api.InitUploadData, token api.UploadTokenData, fileSize int64, sha1Hash string) (*api.UploadResult, error) {
	callback, err := initData.GetCallback()
	if err != nil {
		return nil, err
	}
	in, wrap := accounting.UnWrap(in)
	reader, cleanup, err := retryReadSeeker(ctx, in, fileSize)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	bucket, err := f.newOSSBucket(ctx, token, initData.Bucket)
	if err != nil {
		return nil, err
	}

	callbackStr := base64.StdEncoding.EncodeToString([]byte(callback.Callback))
	callbackVarStr := base64.StdEncoding.EncodeToString([]byte(callback.CallbackVar))
	ossPacer := fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))
	var callbackBody []byte
	refreshed := false
	err = ossPacer.Call(func() (bool, error) {
		if _, seekErr := reader.Seek(0, io.SeekStart); seekErr != nil {
			return false, fmt.Errorf("failed to rewind OSS upload: %w", seekErr)
		}
		callbackBody = nil
		uploadReader := readers.NewCountingReader(wrap(io.LimitReader(reader, fileSize)))
		putErr := bucket.PutObject(initData.Object, uploadReader,
			oss.Callback(callbackStr),
			oss.CallbackVar(callbackVarStr),
			oss.CallbackResult(&callbackBody),
			oss.WithContext(ctx),
		)
		if putErr == nil && int64(uploadReader.BytesRead()) != fileSize {
			putErr = fmt.Errorf("failed to read upload data: read %d bytes, expected %d", int64(uploadReader.BytesRead()), fileSize)
		}
		if isOSSAuthError(putErr) && !refreshed {
			bucket, putErr = f.refreshOSSBucket(ctx, initData.Bucket)
			refreshed = putErr == nil
			return refreshed, putErr
		}
		return shouldRetryOSS(ctx, putErr)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload to OSS: %w", err)
	}
	return parseUploadResult(callbackBody, fileSize, sha1Hash)
}

func retryReadSeeker(ctx context.Context, in io.Reader, size int64) (io.ReadSeeker, func(), error) {
	if rs, ok := in.(io.ReadSeeker); ok && isActuallySeekable(rs) {
		return rs, func() {}, nil
	}
	return copyReaderToTempFile(ctx, in, size)
}

func stageUploadPart(ctx context.Context, in io.Reader, size int64) (io.ReadSeeker, int64, func(), error) {
	if ra, ok := in.(io.ReaderAt); ok {
		if rs, ok := in.(io.ReadSeeker); ok && isActuallySeekable(rs) {
			start, err := rs.Seek(0, io.SeekCurrent)
			if err != nil {
				return nil, 0, func() {}, err
			}
			if _, err = rs.Seek(size, io.SeekCurrent); err != nil {
				return nil, 0, func() {}, err
			}
			return io.NewSectionReader(ra, start, size), 0, func() {}, nil
		}
	}
	var buffer io.ReadWriteSeeker
	var cleanup func()
	// A memory limit can block part reservation while unread source buffers hold pool memory.
	if size <= 20*mib && fs.GetConfig(ctx).MaxBufferMemory <= 0 && fs.GetConfig(context.Background()).MaxBufferMemory <= 0 {
		rw := multipart.NewRW().Reserve(size)
		buffer = rw
		cleanup = func() { _ = rw.Close() }
	} else {
		file, err := os.CreateTemp("", "rclone-115netdisk-part-*")
		if err != nil {
			return nil, 0, func() {}, fmt.Errorf("failed to create multipart temporary file: %w", err)
		}
		buffer = file
		cleanup = func() {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}
	written, err := io.CopyN(buffer, readers.NewContextReader(ctx, in), size)
	if err != nil {
		cleanup()
		return nil, 0, func() {}, fmt.Errorf("failed to stage upload part: read %d bytes, expected %d: %w", written, size, err)
	}
	return buffer, 0, cleanup, nil
}

type ossMultipartUpload struct {
	f      *Fs
	mu     sync.Mutex
	bucket *oss.Bucket
	init   oss.InitiateMultipartUploadResult
	pacer  *fs.Pacer
}

func (u *ossMultipartUpload) getBucket() *oss.Bucket {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.bucket
}

func (u *ossMultipartUpload) refreshBucket(ctx context.Context, previous *oss.Bucket) (*oss.Bucket, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.bucket == previous {
		bucket, err := u.f.refreshOSSBucket(ctx, u.init.Bucket)
		if err != nil {
			return nil, err
		}
		u.bucket = bucket
	}
	return u.bucket, nil
}

func (u *ossMultipartUpload) uploadPart(ctx context.Context, in io.ReadSeeker, wrap accounting.WrapFn, start, size int64, number int, hashContext string) (part oss.UploadPart, err error) {
	authRetried := false
	err = u.pacer.Call(func() (bool, error) {
		if _, err = in.Seek(start, io.SeekStart); err != nil {
			return false, fmt.Errorf("failed to rewind upload part %d: %w", number, err)
		}
		bucket := u.getBucket()
		counted := readers.NewCountingReader(wrap(io.LimitReader(in, size)))
		options := []oss.Option{oss.WithContext(ctx)}
		if hashContext != "" {
			options = append(options, oss.PartHashCtxHeader(hashContext))
		}
		part, err = bucket.UploadPart(u.init, counted, size, number, options...)
		if err == nil && int64(counted.BytesRead()) != size {
			err = fmt.Errorf("failed to read part %d data: read %d bytes, expected %d", number, int64(counted.BytesRead()), size)
		}
		if isOSSAuthError(err) && !authRetried {
			_, err = u.refreshBucket(ctx, bucket)
			authRetried = err == nil
			return authRetried, err
		}
		return shouldRetryOSS(ctx, err)
	})
	if err != nil {
		return part, fmt.Errorf("failed to upload part %d: %w", number, err)
	}
	return part, nil
}

func (u *ossMultipartUpload) uploadParts(ctx context.Context, in io.Reader, fileSize, chunkSize int64) ([]oss.UploadPart, error) {
	in, wrap := accounting.UnWrap(in)
	partCount := (fileSize + chunkSize - 1) / chunkSize
	parts := make([]oss.UploadPart, partCount)
	concurrency := min(uploadConcurrency, int(partCount))
	tokens := semaphore.NewWeighted(int64(concurrency))
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, gCtx := errgroup.WithContext(uploadCtx)
	hasher := sha1.New()
	var readErr error
	for number := range parts {
		if readErr = tokens.Acquire(gCtx, 1); readErr != nil {
			break
		}
		if readErr = gCtx.Err(); readErr != nil {
			tokens.Release(1)
			break
		}
		size := min(chunkSize, fileSize-int64(number)*chunkSize)
		reader, start, cleanup, err := stageUploadPart(gCtx, in, size)
		if err != nil {
			tokens.Release(1)
			readErr = err
			cancel()
			break
		}
		var hashContext string
		if number > 0 {
			hashContext, err = ossSHA1Context(hasher.(encoding.BinaryMarshaler))
		}
		if err == nil {
			_, err = reader.Seek(start, io.SeekStart)
		}
		if err == nil {
			_, err = io.CopyN(hasher, readers.NewContextReader(gCtx, reader), size)
		}
		if err != nil {
			cleanup()
			tokens.Release(1)
			readErr = fmt.Errorf("failed to hash upload part %d: %w", number+1, err)
			cancel()
			break
		}
		g.Go(func() error {
			defer func() { cleanup(); tokens.Release(1) }()
			fs.Debugf(u.f, "Uploading part %d/%d (%v)", number+1, partCount, fs.SizeSuffix(size))
			part, err := u.uploadPart(gCtx, reader, wrap, start, size, number+1, hashContext)
			if err != nil {
				return err
			}
			parts[number] = part
			return nil
		})
	}
	if err := errors.Join(readErr, g.Wait()); err != nil {
		return nil, err
	}
	return parts, nil
}

// uploadMultipartToOSS uploads independent parts concurrently and commits them in order.
func (f *Fs) uploadMultipartToOSS(ctx context.Context, in io.Reader, initData api.InitUploadData, token api.UploadTokenData, fileSize, chunkSize int64, sha1Hash string) (result *api.UploadResult, err error) {
	callback, err := initData.GetCallback()
	if err != nil {
		return nil, err
	}
	bucket, err := f.newOSSBucket(ctx, token, initData.Bucket)
	if err != nil {
		return nil, err
	}
	ossPacer := fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))
	authRetried := false
	var imur oss.InitiateMultipartUploadResult
	initOptions := []oss.Option{oss.EnableSha1(), oss.WithHashContext(), oss.WithContext(ctx)}
	// OSS prefix contexts describe complete SHA1 blocks.
	chunkSize = (chunkSize + sha1.BlockSize - 1) &^ (sha1.BlockSize - 1)
	if chunkSize > 5*int64(fs.Gibi) {
		return nil, errors.New("upload part size exceeds the OSS limit of 5 GiB")
	}
	err = ossPacer.Call(func() (bool, error) {
		imur, err = bucket.InitiateMultipartUpload(initData.Object, initOptions...)
		if isOSSAuthError(err) && !authRetried {
			bucket, err = f.refreshOSSBucket(ctx, initData.Bucket)
			authRetried = err == nil
			return authRetried, err
		}
		return shouldRetryOSS(ctx, err)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initiate multipart upload: %w", err)
	}
	completed := false
	defer func() {
		if completed {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		abortErr := bucket.AbortMultipartUpload(imur, oss.WithContext(cleanupCtx))
		if abortErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to abort multipart upload: %w", abortErr))
		}
	}()

	upload := &ossMultipartUpload{f: f, bucket: bucket, init: imur, pacer: ossPacer}
	parts, err := upload.uploadParts(ctx, in, fileSize, chunkSize)
	bucket = upload.getBucket()
	if err != nil {
		return nil, err
	}

	callbackStr := base64.StdEncoding.EncodeToString([]byte(callback.Callback))
	callbackVarStr := base64.StdEncoding.EncodeToString([]byte(callback.CallbackVar))
	var callbackBody []byte
	authRetried = false
	err = ossPacer.Call(func() (bool, error) {
		callbackBody = nil
		_, err = bucket.CompleteMultipartUpload(imur, parts,
			oss.Callback(callbackStr),
			oss.CallbackVar(callbackVarStr),
			oss.CallbackResult(&callbackBody),
			oss.WithContext(ctx),
		)
		if isOSSAuthError(err) && !authRetried {
			refreshed, refreshErr := f.refreshOSSBucket(ctx, initData.Bucket)
			if refreshErr != nil {
				return false, refreshErr
			}
			bucket = refreshed
			authRetried = true
			return true, nil
		}
		return shouldRetryOSS(ctx, err)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to complete multipart upload: %w", err)
	}
	result, err = parseUploadResult(callbackBody, fileSize, sha1Hash)
	if err != nil {
		return nil, err
	}
	completed = true
	return result, nil
}

// isActuallySeekable tests if a ReadSeeker is actually usable by attempting a Seek operation
func isActuallySeekable(rs io.ReadSeeker) bool {
	_, err := rs.Seek(0, io.SeekCurrent)
	return err == nil
}

// copyReaderToTempFile copies an upload stream to a temporary file and returns it as an io.ReadSeeker.
func copyReaderToTempFile(ctx context.Context, in io.Reader, size int64) (rs io.ReadSeeker, cleanup func(), err error) {
	// Create temporary file
	tempFile, err := os.CreateTemp("", "rclone-115netdisk-upload-*")
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Setup cleanup function
	cleanup = func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}

	// Read at most one byte beyond the declared size so a bad source can't fill the disk.
	written, err := io.Copy(tempFile, io.LimitReader(readers.NewContextReader(ctx, in), size+1))
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("failed to copy data to temporary file: %w", err)
	}

	// Check written size
	if written != size {
		cleanup()
		return nil, func() {}, fmt.Errorf("failed to copy all data to temporary file: written %d, expected %d", written, size)
	}

	// Reset file position
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("failed to seek temporary file: %w", err)
	}

	return tempFile, cleanup, nil
}

type preparedUpload struct {
	reader     io.Reader
	readSeeker io.ReadSeeker
	sha1Hash   string
	cleanup    func()
	size       int64
}

func (p *preparedUpload) ensureReadSeeker(ctx context.Context) (io.ReadSeeker, error) {
	if p.readSeeker != nil {
		return p.readSeeker, nil
	}
	in, wrap := accounting.UnWrap(p.reader)
	rs, cleanup, err := copyReaderToTempFile(ctx, in, p.size)
	if err != nil {
		return nil, err
	}
	oldCleanup := p.cleanup
	p.cleanup = func() {
		cleanup()
		oldCleanup()
	}
	p.reader = wrap(rs)
	p.readSeeker = rs
	return rs, nil
}

func (p *preparedUpload) rewindForUpload() error {
	if p.readSeeker == nil {
		return nil
	}
	_, err := p.readSeeker.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}
	_, wrap := accounting.UnWrap(p.reader)
	p.reader = wrap(p.readSeeker)
	return nil
}

// calculateSHA1 calculates the SHA1 hash of data
func calculateSHA1(r io.Reader) (string, error) {
	hashes, err := hash.StreamTypes(r, hash.NewHashSet(hash.SHA1))
	if err != nil {
		return "", err
	}
	return hashes[hash.SHA1], nil
}

// calculateSHA1FromReadSeeker calculates the SHA1 hash of a ReadSeeker
func calculateSHA1FromReadSeeker(ctx context.Context, rs io.ReadSeeker) (sha1Hash string, err error) {
	// Save current position
	currentPos, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("failed to get current position: %w", err)
	}

	// Ensure position is restored when function returns
	defer func() {
		if _, seekErr := rs.Seek(currentPos, io.SeekStart); seekErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to restore source position: %w", seekErr))
		}
	}()

	// Calculate SHA1 from beginning
	_, err = rs.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("failed to seek to start: %w", err)
	}

	return calculateSHA1(readers.NewContextReader(ctx, rs))
}

func calculateSHA1FromObject(ctx context.Context, obj fs.Object) (sha1Hash string, err error) {
	rc, err := obj.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open source object: %w", err)
	}
	defer fs.CheckClose(rc, &err)
	return calculateSHA1(readers.NewContextReader(ctx, rc))
}

func calculateSHA1RangeFromReadSeeker(ctx context.Context, rs io.ReadSeeker, start, size int64) (sha1Hash string, err error) {
	currentPos, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("failed to get current position: %w", err)
	}
	defer func() {
		if _, seekErr := rs.Seek(currentPos, io.SeekStart); seekErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to restore source position: %w", seekErr))
		}
	}()

	_, err = rs.Seek(start, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("failed to seek to range start: %w", err)
	}
	return calculateSHA1Range(readers.NewContextReader(ctx, rs), size)
}

func calculateSHA1RangeFromObject(ctx context.Context, obj fs.Object, start, end int64) (sha1Hash string, err error) {
	rc, err := obj.Open(ctx, &fs.RangeOption{Start: start, End: end})
	if err != nil {
		return "", fmt.Errorf("failed to open source range: %w", err)
	}
	defer fs.CheckClose(rc, &err)
	return calculateSHA1Range(readers.NewContextReader(ctx, rc), end-start+1)
}

func sourceObject(src fs.ObjectInfo) fs.Object {
	if obj, ok := src.(fs.Object); ok {
		return obj
	}
	if unwrapper, ok := src.(fs.ObjectUnWrapper); ok {
		return unwrapper.UnWrap()
	}
	return nil
}

func normalizeSHA1(sha1Hash string) (string, bool) {
	sha1Hash = strings.ToLower(strings.TrimSpace(sha1Hash))
	if len(sha1Hash) != 40 {
		return "", false
	}
	_, err := hex.DecodeString(sha1Hash)
	return sha1Hash, err == nil
}

func getSourceSHA1(ctx context.Context, src fs.ObjectInfo) (string, bool) {
	if src == nil {
		return "", false
	}
	sha1Hash, err := src.Hash(ctx, hash.SHA1)
	if err != nil {
		fs.Debugf(src, "Failed to get SHA1 from source object, falling back to upload stream: %v", err)
		return "", false
	}
	original := sha1Hash
	sha1Hash, ok := normalizeSHA1(original)
	if !ok && original != "" {
		fs.Debugf(src, "Ignoring invalid SHA1 from source object")
	}
	return sha1Hash, ok
}

func (p *preparedUpload) calculateSignCheckSHA1(ctx context.Context, src fs.ObjectInfo, start, end int64) (string, error) {
	if obj := sourceObject(src); obj != nil {
		sha1Hash, err := calculateSHA1RangeFromObject(ctx, obj, start, end)
		if err == nil {
			return sha1Hash, nil
		}
		fs.Debugf(src, "Failed to calculate sign check SHA1 from source range, falling back to upload stream: %v", err)
	}

	rs, err := p.ensureReadSeeker(ctx)
	if err != nil {
		return "", err
	}
	return calculateSHA1RangeFromReadSeeker(ctx, rs, start, end-start+1)
}

func newPreparedUpload(in io.Reader, sha1Hash string, size int64) *preparedUpload {
	var readSeeker io.ReadSeeker
	if rs, ok := in.(io.ReadSeeker); ok && isActuallySeekable(rs) {
		readSeeker = rs
	}
	return &preparedUpload{
		reader:     in,
		readSeeker: readSeeker,
		sha1Hash:   sha1Hash,
		cleanup:    func() {},
		size:       size,
	}
}

// initializeUpload initializes the upload process
func (f *Fs) initializeUpload(ctx context.Context, remote, directoryID string, size int64, fileSHA1 string, signCheck func(start, end int64) (string, error)) (*api.InitUploadData, error) {
	// Build upload initialization request
	// Encode the file name for the API
	encodedFileName := f.opt.Enc.FromStandardName(path.Base(remote))
	initReq := &api.InitUploadRequest{
		FileName: encodedFileName,
		FileSize: size,
		Target:   "U_1_" + directoryID, // Format: U_1_dirID
		FileID:   strings.ToUpper(fileSHA1),
	}

	// Execute upload initialization request
	initResp, err := f.initUpload(ctx, initReq)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize upload: %w", err)
	}

	initData := initResp.Data
	if initData.Status == 7 {
		// Parse authentication range
		start, end, err := parseSignCheckRange(initData.SignCheck, size)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sign check range: %w", err)
		}

		// Calculate SHA1 for the specified range
		signSHA1, err := signCheck(start, end)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate sign check SHA1: %w", err)
		}

		// Convert to uppercase
		sha1Value := strings.ToUpper(signSHA1)

		// Rebuild initialization request with authentication info
		initReq.SignKey = initData.SignKey
		initReq.SignVal = sha1Value

		// Resend initialization request
		initResp, err = f.initUpload(ctx, initReq)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize upload with authentication: %w", err)
		}
		initData = initResp.Data
	}
	if err := validateInitUploadData(&initData); err != nil {
		return nil, err
	}
	return &initData, nil
}

func validateInitUploadData(data *api.InitUploadData) error {
	switch data.Status {
	case 1:
		callback, err := data.GetCallback()
		if err != nil {
			return err
		}
		if data.Bucket == "" || data.Object == "" || callback.Callback == "" || callback.CallbackVar == "" {
			return errors.New("upload initialization returned incomplete OSS data")
		}
	case 2:
		if data.FileID == "" || data.PickCode == "" {
			return errors.New("rapid upload returned empty file_id or pick_code")
		}
	default:
		return fmt.Errorf("unsupported upload initialization status %d", data.Status)
	}
	return nil
}

// calculateSHA1Range calculates SHA1 hash for a specific length of data from a reader
func calculateSHA1Range(r io.Reader, size int64) (string, error) {
	counted := readers.NewCountingReader(io.LimitReader(r, size))
	sha1Hash, err := calculateSHA1(counted)
	if err != nil {
		return "", err
	}
	if n := int64(counted.BytesRead()); n != size {
		return "", fmt.Errorf("failed to read %d bytes, got %d: %w", size, n, io.EOF)
	}
	return sha1Hash, nil
}

// prepareFileForUpload prepares a file for upload, calculating SHA1 and returning necessary info.
func prepareFileForUpload(ctx context.Context, in io.Reader, src fs.ObjectInfo, size int64) (upload *preparedUpload, err error) {
	in, wrap := accounting.UnWrap(in)
	defer func() {
		if upload != nil {
			upload.reader = wrap(upload.reader)
		}
	}()
	if sha1Hash, ok := getSourceSHA1(ctx, src); ok {
		return newPreparedUpload(in, sha1Hash, size), nil
	}

	if obj := sourceObject(src); obj != nil {
		sha1Hash, err := calculateSHA1FromObject(ctx, obj)
		if err == nil {
			return newPreparedUpload(in, sha1Hash, size), nil
		}
		fs.Debugf(src, "Failed to calculate SHA1 from source object, falling back to upload stream: %v", err)
	}

	if rs, ok := in.(io.ReadSeeker); ok {
		if isActuallySeekable(rs) {
			sha1Hash, err := calculateSHA1FromReadSeeker(ctx, rs)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate SHA1: %w", err)
			}
			_, err = rs.Seek(0, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("failed to seek to start: %w", err)
			}
			return &preparedUpload{
				reader:     rs,
				readSeeker: rs,
				sha1Hash:   sha1Hash,
				cleanup:    func() {},
				size:       size,
			}, nil
		}
		// ReadSeeker interface exists but Seek doesn't work (e.g. *asyncreader.AsyncReader wrapped in *accounting.Account).
		// Fall through to temporary file approach.
	}

	rs, cleanup, err := copyReaderToTempFile(ctx, in, size)
	if err != nil {
		return nil, err
	}

	sha1Hash, err := calculateSHA1FromReadSeeker(ctx, rs)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to calculate SHA1: %w", err)
	}

	_, err = rs.Seek(0, io.SeekStart)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to seek to start: %w", err)
	}

	return &preparedUpload{
		reader:     rs,
		readSeeker: rs,
		sha1Hash:   sha1Hash,
		cleanup:    cleanup,
		size:       size,
	}, nil
}

// upload handles the file upload process
func (f *Fs) upload(ctx context.Context, in io.Reader, src fs.ObjectInfo, remote string,
	directoryID string, size int64) (fs.Object, error) {

	// Handle empty files
	if size == 0 {
		return nil, fs.ErrorCantUploadEmptyFiles
	}

	// Prepare file for upload
	prepared, err := prepareFileForUpload(ctx, in, src, size)
	if err != nil {
		return nil, err
	}
	// Ensure cleanup runs when function exits
	defer prepared.cleanup()

	// Initialize upload
	initData, err := f.initializeUpload(ctx, remote, directoryID, size, prepared.sha1Hash, func(start, end int64) (string, error) {
		return prepared.calculateSignCheckSHA1(ctx, src, start, end)
	})
	if err != nil {
		fs.Errorf(nil, "failed to initialize upload: %+v", err)
		return nil, err
	}

	// Check if fast upload succeeded
	if initData.Status == 2 {
		info, err := f.confirmUploaded(ctx, directoryID, f.opt.Enc.FromStandardName(path.Base(remote)), size, prepared.sha1Hash, initData.PickCode)
		if err != nil {
			return nil, err
		}
		return f.newObjectWithInfo(ctx, remote, info)
	}

	// Get upload token for OSS
	token, err := f.getValidUploadToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get upload token: %w", err)
	}

	// Reset file position for upload when the prepared reader is seekable.
	if err = prepared.rewindForUpload(); err != nil {
		return nil, err
	}

	// Calculate chunk size
	chunkSize := int64(chunksize.Calculator(f, size, 10000, 20*fs.Mebi))

	// Choose upload method based on file size
	var result *api.UploadResult
	if chunkSize >= size {
		result, err = f.uploadToOSS(ctx, prepared.reader, *initData, *token, size, prepared.sha1Hash)
	} else {
		result, err = f.uploadMultipartToOSS(ctx, prepared.reader, *initData, *token, size, chunkSize, prepared.sha1Hash)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to upload file to OSS: %w", err)
	}

	info, err := f.confirmUploaded(ctx, directoryID, f.opt.Enc.FromStandardName(path.Base(remote)), size, prepared.sha1Hash, result.PickCode)
	if err != nil {
		return nil, err
	}
	if info.FID != result.FileID || (result.CID != "" && result.CID != directoryID) {
		return nil, errors.New("upload callback has a different committed object identity or parent")
	}
	return f.newObjectWithInfo(ctx, remote, info)
}

func (f *Fs) renameFile(ctx context.Context, fileID, leaf string) error {
	resp, err := f.updateFile(ctx, fileID, map[string]string{
		"file_name": f.opt.Enc.FromStandardName(leaf),
	})
	if err != nil {
		return err
	}
	if resp.Data.FileName != "" && f.opt.Enc.ToStandardName(resp.Data.FileName) != leaf {
		return fmt.Errorf("server renamed object to %q instead of %q", f.opt.Enc.ToStandardName(resp.Data.FileName), leaf)
	}
	return nil
}

func temporaryLeaf(leaf string) string {
	ext := path.Ext(leaf)
	return strings.TrimSuffix(leaf, ext) + ".rclone-" + random.String(16) + ext
}

var errDestinationHasDuplicates = errors.New("destination has additional duplicate objects")

func (f *Fs) parkDestination(ctx context.Context, previous fs.Object, directoryID, leaf string) (string, error) {
	if previous == nil {
		return "", nil
	}
	previousID := objectID(previous)
	hasOther, err := f.hasOtherLeaf(ctx, directoryID, leaf, previousID)
	if err != nil {
		return "", err
	}
	if hasOther {
		return "", errDestinationHasDuplicates
	}
	backupLeaf := temporaryLeaf(leaf)
	if err := f.renameFile(ctx, previousID, backupLeaf); err != nil {
		return "", fmt.Errorf("failed to park destination object: %w", err)
	}
	hasOther, err = f.hasOtherLeaf(ctx, directoryID, leaf, previousID)
	if err == nil && !hasOther {
		return backupLeaf, nil
	}
	restoreErr := f.renameFile(ctx, previousID, leaf)
	if err != nil {
		return "", errors.Join(err, restoreErr)
	}
	if restoreErr != nil {
		return "", restoreErr
	}
	return "", errDestinationHasDuplicates
}

func (f *Fs) hasOtherLeaf(ctx context.Context, cid, leaf, excludedID string) (bool, error) {
	entries, err := f.listAll(ctx, cid)
	if err != nil {
		return false, err
	}
	for _, item := range entries {
		if item.FID != excludedID && f.opt.Enc.ToStandardName(item.FN) == leaf {
			return true, nil
		}
	}
	return false, nil
}

// performMoveFiles moves files with enhanced logic for different scenarios.
func (f *Fs) performMoveFiles(ctx context.Context, srcDirID, dstDirID, srcLeaf, dstLeaf string, fileIDs []string) error {
	// Decision logic based on source and destination
	// Case 1: Same directory, same name - no operation needed
	if srcDirID == dstDirID && srcLeaf == dstLeaf {
		return nil
	}

	// Case 2: Different directory, same name - direct move
	if srcDirID != dstDirID && srcLeaf == dstLeaf {
		_, err := f.moveFiles(ctx, fileIDs, dstDirID)
		return err
	}

	// Case 3: Same directory, different name - rename only
	if srcDirID == dstDirID && srcLeaf != dstLeaf {
		return f.renameFile(ctx, fileIDs[0], dstLeaf)
	}

	// Case 4: Different directory, different name - move then rename
	// First move to destination directory
	_, err := f.moveFiles(ctx, fileIDs, dstDirID)
	if err != nil {
		return fmt.Errorf("failed to move file to destination directory: %w", err)
	}

	// Then rename the file
	err = f.renameFile(ctx, fileIDs[0], dstLeaf)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, moveBackErr := f.moveFiles(cleanupCtx, fileIDs, srcDirID)
		renameBackErr := f.renameFile(cleanupCtx, fileIDs[0], srcLeaf)
		return errors.Join(fmt.Errorf("failed to rename moved file: %w", err), moveBackErr, renameBackErr)
	}

	return nil
}

// performMoveDirs moves directories with enhanced logic for different scenarios.
func (f *Fs) performMoveDirs(ctx context.Context, srcDirID, dstDirID, srcLeaf, dstLeaf string, dirIDs []string) error {
	// Decision logic based on source and destination
	// Case 1: Same directory, same name - no operation needed
	if srcDirID == dstDirID && srcLeaf == dstLeaf {
		return nil
	}

	// Case 2: Different directory, same name - direct move
	if srcDirID != dstDirID && srcLeaf == dstLeaf {
		_, err := f.moveFiles(ctx, dirIDs, dstDirID)
		return err
	}

	// Case 3: Same directory, different name - rename only
	if srcDirID == dstDirID && srcLeaf != dstLeaf {
		return f.renameFile(ctx, dirIDs[0], dstLeaf)
	}

	// Case 4: Different directory, different name - move then rename
	// First move to destination directory
	_, err := f.moveFiles(ctx, dirIDs, dstDirID)
	if err != nil {
		return fmt.Errorf("failed to move directory to destination: %w", err)
	}

	// Then rename the directory
	err = f.renameFile(ctx, dirIDs[0], dstLeaf)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, moveBackErr := f.moveFiles(cleanupCtx, dirIDs, srcDirID)
		renameBackErr := f.renameFile(cleanupCtx, dirIDs[0], srcLeaf)
		return errors.Join(fmt.Errorf("failed to rename moved directory: %w", err), moveBackErr, renameBackErr)
	}

	return nil
}

// moveFiles moves files.
func (f *Fs) moveFiles(ctx context.Context, ids []string, cid string) (*api.FileOperationResponse, error) {
	form, err := indexedIDs(ids)
	if err != nil {
		return nil, err
	}
	form.Set("pid", cid)
	var response api.FileOperationResponse
	err = f.callAPIWithForm(ctx, rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/files/move"}, form, &response, &response.Response)
	return &response, err
}

// getUploadToken gets the upload token
// copyWithTempDir copies through an empty directory so the new object ID is unambiguous.
func (f *Fs) copyWithTempDir(ctx context.Context, srcDirID, dstDirID, dstLeaf string, fileIDs []string) (*api.FileInfo, error) {
	// Generate a unique temporary directory name and create it
	tmpDir := "rclone-temp-dir-" + random.String(16)
	tempDirResp, err := f.createFolder(ctx, srcDirID, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	tempDirID := tempDirResp.Data.FileID.String()

	// Ensure cleanup of temporary directory
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if cleanupErr := f.cleanupTempDir(cleanupCtx, tempDirID, srcDirID); cleanupErr != nil {
			fs.Errorf(f, "Failed to cleanup temporary directory %s: %v", tempDirID, cleanupErr)
		}
	}()

	// Copy file to temporary directory
	err = f.performCopy(ctx, tempDirID, fileIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to copy to temporary directory: %w", err)
	}

	copiedFile, err := f.findCopiedFile(ctx, tempDirID)
	if err != nil {
		return nil, fmt.Errorf("failed to find copied file in temporary directory: %w", err)
	}

	// Rename the copied file
	err = f.renameFile(ctx, copiedFile.FID, dstLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to rename copied file: %w", err)
	}
	copiedFile.FN = f.opt.Enc.FromStandardName(dstLeaf)

	// Move the renamed file to destination directory
	_, err = f.moveFiles(ctx, []string{copiedFile.FID}, dstDirID)
	if err != nil {
		return nil, fmt.Errorf("failed to move renamed file to destination: %w", err)
	}
	copiedFile.PID = dstDirID

	return copiedFile, nil
}

// cleanupTempDir removes the temporary directory and any remaining files
func (f *Fs) cleanupTempDir(ctx context.Context, tempDirID, parentID string) error {
	// Delete the temporary directory (this should also delete any remaining files)
	_, err := f.deleteFiles(ctx, []string{tempDirID}, parentID)
	return err
}

// findCopiedFile returns the only file in a fresh temporary directory.
func (f *Fs) findCopiedFile(ctx context.Context, cid string) (*api.FileInfo, error) {
	entries, err := f.listAll(ctx, cid)
	if err != nil {
		return nil, err
	}
	var copied *api.FileInfo
	for _, item := range entries {
		if item.FC != fileCategoryFolder {
			if copied != nil {
				return nil, errors.New("temporary copy directory has multiple files")
			}
			value := item
			copied = &value
		}
	}
	if copied == nil {
		return nil, errors.New("copied file not found")
	}
	return copied, nil
}

// getNormalizedPath splits a path into a parent and a leaf.
// The parent is normalized to an empty string if it is "." or "/".
func (f *Fs) getNormalizedPath(p string) (parent, leaf string) {
	parent = path.Dir(p)
	if parent == "." || parent == "/" {
		parent = ""
	}
	leaf = path.Base(p)
	return
}

func (f *Fs) getFileList(ctx context.Context, cid string, limit, offset int64) (*api.FileListResponse, error) {
	query := url.Values{"aid": {"1"}, "cid": {cid}, "limit": {strconv.FormatInt(limit, 10)}, "offset": {strconv.FormatInt(offset, 10)},
		"cur": {"1"}, "stdir": {"1"}, "show_dir": {"1"}, "format": {"json"}, "o": {"file_name"}, "asc": {"1"}, "fc_mix": {"1"}, "natsort": {"1"}, "custom_order": {"1"}, "record_open_time": {"0"}, "last_utime": {"0"}}
	var response api.FileListResponse
	if err := f.callAPI(ctx, rest.Opts{Method: "GET", RootURL: baseAPI, Path: "/files", Parameters: query}, &response, &response.Response); err != nil {
		return nil, err
	}
	if string(response.CID) != cid {
		return nil, fmt.Errorf("directory response has a different identity: %w", fs.ErrorDirNotFound)
	}
	if response.UseCache || !response.CountPresent {
		return nil, errors.New("directory response is cached or has no count")
	}
	if response.Offset != offset {
		return nil, errors.New("directory pagination moved to a different offset")
	}
	return &response, nil
}

func (f *Fs) listAll(ctx context.Context, cid string) ([]api.FileInfo, error) {
	var entries []api.FileInfo
	seen := make(map[string]bool)
	for page := 0; page < 100000; page++ {
		response, err := f.getFileList(ctx, cid, defaultListPageSize, int64(len(entries)))
		if err != nil {
			return nil, err
		}
		for _, item := range response.Data {
			if seen[item.FID] {
				return nil, errors.New("directory changed or pagination repeated an object")
			}
			seen[item.FID] = true
			entries = append(entries, item)
		}
		if int64(len(entries)) >= response.Count {
			return entries, nil
		}
		if len(response.Data) == 0 {
			return nil, errors.New("directory pagination ended before the reported count")
		}
	}
	return nil, errors.New("directory pagination exceeds its bound")
}

func (f *Fs) createFolder(ctx context.Context, pid, name string) (*api.FolderCreateResponse, error) {
	var response api.FolderCreateResponse
	err := f.callAPIWithForm(ctx, rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/files/add"}, url.Values{"pid": {pid}, "cname": {f.opt.Enc.FromStandardName(name)}}, &response, &response.Response)
	if err != nil {
		return nil, err
	}
	if response.Data == nil || response.Data.FileID == "" {
		return nil, errors.New("directory creation did not return an identity")
	}
	entries, err := f.listAll(ctx, pid)
	if err != nil {
		return nil, err
	}
	for _, item := range entries {
		if item.FID == response.Data.FileID.String() && item.FC == fileCategoryFolder {
			if f.opt.Enc.ToStandardName(item.FN) != name {
				return nil, errors.New("server changed the requested directory name")
			}
			return &response, nil
		}
	}
	return nil, errors.New("created directory is not visible in its parent")
}

func indexedIDs(ids []string) (url.Values, error) {
	if len(ids) == 0 {
		return nil, errors.New("empty file selection")
	}
	form := url.Values{}
	for i, id := range ids {
		if id == "" {
			return nil, errors.New("empty file identity")
		}
		form.Set(fmt.Sprintf("fid[%d]", i), id)
	}
	return form, nil
}

func (f *Fs) deleteFiles(ctx context.Context, ids []string, pid string) (*api.FileOperationResponse, error) {
	form, err := indexedIDs(ids)
	if err != nil {
		return nil, err
	}
	if pid == "" {
		return nil, errors.New("deletion requires the known parent directory")
	}
	form.Set("pid", pid)
	form.Set("ignore_warn", "0")
	var response api.FileOperationResponse
	for attempt := 0; attempt < 4; attempt++ {
		err = f.callAPIWithForm(ctx, rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/rb/delete"}, form, &response, &response.Response)
		if err == nil {
			return &response, nil
		}
		var business *apiError
		if !errors.As(err, &business) || !strings.Contains(business.response.Message, "操作尚未执行完成") {
			return nil, err
		}
		entries, readErr := f.listAll(ctx, pid)
		if readErr != nil {
			return nil, errors.Join(err, readErr)
		}
		present := make(map[string]bool)
		for _, entry := range entries {
			present[entry.FID] = true
		}
		remaining := make([]string, 0, len(ids))
		for _, id := range ids {
			if present[id] {
				remaining = append(remaining, id)
			}
		}
		if len(remaining) == 0 {
			return &response, nil
		}
		if attempt == 3 {
			return nil, err
		}
		form, err = indexedIDs(remaining)
		if err != nil {
			return nil, err
		}
		form.Set("pid", pid)
		form.Set("ignore_warn", "0")
		timer := time.NewTimer(time.Duration(attempt+1) * 3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, err
}

func (f *Fs) updateFile(ctx context.Context, id string, values map[string]string) (*api.FileUpdateResponse, error) {
	form := url.Values{"fid": {id}}
	for key, value := range values {
		form.Set(key, value)
	}
	var response api.FileUpdateResponse
	err := f.callAPIWithForm(ctx, rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/files/edit"}, form, &response, &response.Response)
	return &response, err
}

func (f *Fs) performCopy(ctx context.Context, cid string, ids []string) error {
	form, err := indexedIDs(ids)
	if err != nil {
		return err
	}
	form.Set("pid", cid)
	var response api.FileOperationResponse
	return f.callAPIWithForm(ctx, rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/files/copy"}, form, &response, &response.Response)
}

func (f *Fs) getUserInfo(ctx context.Context) (*api.UserInfoResponse, error) {
	var response api.UserInfoResponse
	err := f.callAPI(ctx, rest.Opts{Method: "GET", RootURL: baseAPI, Path: "/files/index_info"}, &response, &response.Response)
	return &response, err
}

func (f *Fs) initUpload(ctx context.Context, request *api.InitUploadRequest) (*api.InitUploadResponse, error) {
	key, err := f.client.uploadKey(ctx)
	if err != nil {
		return nil, err
	}
	codec, err := newECContext()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	fileID := strings.ToUpper(request.FileID)
	form := f.uploadForm(request, key, now)
	body, err := codec.encrypt([]byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	encoded, _, err := f.client.raw(ctx, &rest.Opts{Method: "POST", RootURL: uploadAPI, Path: "/4.0/initupload.php", Parameters: url.Values{"k_ec": {codec.queryToken(uint32(f.client.userID), now)}}, ContentType: "application/x-www-form-urlencoded", Body: bytes.NewReader(body)})
	if err != nil {
		return nil, err
	}
	decoded, err := codec.decode(encoded)
	if err != nil {
		return nil, err
	}
	var data api.InitUploadData
	if err = json.Unmarshal(decoded, &data); err != nil {
		return nil, err
	}
	if data.Status != 1 && data.Status != 2 && data.Status != 7 {
		return nil, fmt.Errorf("upload initialization failed (%d/%d): %s", data.Status, data.StatusCode, data.StatusMessage)
	}
	if data.Status == 2 {
		cid := strings.TrimPrefix(request.Target, "U_1_")
		info, err := f.confirmUploaded(ctx, cid, request.FileName, request.FileSize, fileID, data.PickCode)
		if err != nil {
			return nil, err
		}
		data.FileID = info.FID
	}
	return &api.InitUploadResponse{Data: data}, nil
}

func (f *Fs) confirmUploaded(ctx context.Context, cid, name string, size int64, sha1, pickcode string) (*api.FileInfo, error) {
	if pickcode == "" {
		return nil, errors.New("upload result has no pickcode")
	}
	for attempt := 0; attempt < 6; attempt++ {
		entries, err := f.listAll(ctx, cid)
		if err != nil {
			return nil, err
		}
		var found *api.FileInfo
		for _, item := range entries {
			if item.PC != pickcode || item.FC == fileCategoryFolder {
				continue
			}
			actualSize, err := item.FS.Int64()
			if err != nil {
				return nil, err
			}
			if item.FN != name || actualSize != size || !strings.EqualFold(item.SHA1, sha1) {
				return nil, errors.New("committed upload differs from its name, size or SHA1 contract")
			}
			if found != nil {
				return nil, errors.New("upload pickcode has multiple cloud objects")
			}
			value := item
			found = &value
		}
		if found != nil {
			return found, nil
		}
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, errors.New("upload not visible in its target directory")
}

type downloadInfo struct {
	URL     string
	Cookies map[string]string
}

func (f *Fs) downloadAddress(ctx context.Context, id, pickcode string) (*downloadInfo, error) {
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(map[string]string{"pickcode": pickcode})
	if err != nil {
		return nil, err
	}
	data, err := m115Encode(plaintext, seed)
	if err != nil {
		return nil, err
	}
	body, response, err := f.client.raw(ctx, &rest.Opts{Method: "POST", RootURL: baseAPI, Path: "/files/download", ContentType: "application/x-www-form-urlencoded; charset=utf-8", Body: strings.NewReader(url.Values{"data": {data}}.Encode())})
	if err != nil {
		return nil, err
	}
	var state api.Response
	if err = json.Unmarshal(body, &state); err != nil {
		return nil, err
	}
	if !state.Success() {
		return nil, &apiError{response: state}
	}
	var envelope struct {
		Data string `json:"data"`
	}
	if err = json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	decoded, err := m115Decode(envelope.Data, seed)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(decoded, &state); err != nil {
		return nil, err
	}
	if !state.Success() {
		return nil, &apiError{response: state}
	}
	var link struct {
		URL      string     `json:"file_url"`
		ID       api.String `json:"file_id"`
		PickCode string     `json:"pickcode"`
	}
	if err = json.Unmarshal(decoded, &link); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(link.URL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("download response has no valid URL")
	}
	if string(link.ID) != id || link.PickCode != pickcode {
		return nil, errors.New("download response has a different file identity")
	}
	cookies := make(map[string]string)
	for _, cookie := range response.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	return &downloadInfo{URL: link.URL, Cookies: cookies}, nil
}

func (f *Fs) download(ctx context.Context, id, pickcode string, size int64, options ...fs.OpenOption) (io.ReadCloser, error) {
	for attempt := 0; attempt < 3; attempt++ {
		info, err := f.downloadAddress(ctx, id, pickcode)
		if err != nil {
			return nil, err
		}
		headers := map[string]string{"User-Agent": f.client.userAgent, "Cookie": cookieHeader(f.client.cookies, info.Cookies)}
		redirect := func(request *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("download redirect limit reached")
			}
			if request.URL.Scheme != "https" {
				return errors.New("download redirect requires HTTPS")
			}
			host := request.URL.Hostname()
			if request.Response != nil {
				for _, cookie := range request.Response.Cookies() {
					info.Cookies[cookie.Name] = cookie.Value
				}
				headers["Cookie"] = cookieHeader(f.client.cookies, info.Cookies)
			}
			if host != "115.com" && !strings.HasSuffix(host, ".115.com") {
				request.Header.Del("Cookie")
			} else {
				request.Header.Set("Cookie", headers["Cookie"])
			}
			request.Header.Set("User-Agent", f.client.userAgent)
			if request.Header.Get("Range") == "" && len(via) > 0 {
				request.Header.Set("Range", via[0].Header.Get("Range"))
			}
			return nil
		}
		response, err := f.client.content.Call(ctx, &rest.Opts{Method: "GET", RootURL: info.URL, ExtraHeaders: headers, Options: options, CheckRedirect: redirect})
		if err != nil {
			if response != nil && response.StatusCode == 403 && attempt < 2 {
				continue
			}
			return nil, err
		}
		if err = rest.CheckContentRange(response, options, size); err != nil {
			return nil, errors.Join(err, response.Body.Close())
		}
		return response.Body, nil
	}
	return nil, errors.New("download address recovery exhausted")
}

// Interfaces implementation check
var (
	_ fs.Fs              = (*Fs)(nil)
	_ fs.Mover           = (*Fs)(nil)
	_ fs.DirMover        = (*Fs)(nil)
	_ fs.Copier          = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.CleanUpper      = (*Fs)(nil)
	_ fs.PutUncheckeder  = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ dircache.DirCacher = (*Fs)(nil)
)

func (f *Fs) uploadForm(request *api.InitUploadRequest, key string, now time.Time) url.Values {
	fileID := strings.ToUpper(request.FileID)
	form := url.Values{"userid": {strconv.FormatInt(f.client.userID, 10)}, "appid": {"100"}, "appversion": {f.client.version},
		"filename": {request.FileName}, "filesize": {strconv.FormatInt(request.FileSize, 10)}, "fileid": {fileID}, "quickid": {""}, "pickcode": {""},
		"target": {request.Target}, "sig": {uploadSignature(f.client.userID, fileID, request.Target, key)},
		"token": {uploadToken(f.client.userID, now.Unix(), request.FileSize, fileID, request.SignKey+request.SignVal, f.client.version)},
		"t":     {strconv.FormatInt(now.Unix(), 10)}, "isp": {"0"}, "topupload": {"0"}, "json": {"json"}}
	if request.SignKey != "" {
		form.Set("sign_key", request.SignKey)
		form.Set("sign_val", request.SignVal)
	}
	return form
}
