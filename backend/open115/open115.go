// Package open115 provides an interface to the 115 Cloud Storage
package open115

import (
	"context"
	"crypto/sha1"
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
	"time"

	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/random"

	"github.com/rclone/rclone/fs/fserrors"

	"github.com/rclone/rclone/lib/rest"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/rclone/rclone/backend/open115/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
)

const (
	defaultAppID       = "100196955"            // default app id for rclone
	minSleep           = 100 * time.Millisecond // minSleep is the minimum sleep time between retries.
	maxSleep           = 5 * time.Second        // maxSleep is the maximum sleep time between retries.
	decayConstant      = 2                      // decayConstant is the backoff factor.
	rootID             = "0"                    // rootID is the ID of the root directory.
	fileCategoryFolder = "0"
	mib                = 1024 * 1024
	gib                = 1024 * mib
	tib                = 1024 * gib
)

// calPartSize calculates the part size for multipart upload based on file size
func calPartSize(fileSize int64) int64 {
	var partSize int64 = 20 * mib
	if fileSize > partSize {
		if fileSize > 1*tib { // file Size over 1TB
			partSize = 5 * gib // file part size 5GB
		} else if fileSize > 768*gib { // over 768GB
			partSize = 109951163 // ≈ 104.8576MB, split 1TB into 10,000 part
		} else if fileSize > 512*gib { // over 512GB
			partSize = 82463373 // ≈ 78.6432MB
		} else if fileSize > 384*gib { // over 384GB
			partSize = 54975582 // ≈ 52.4288MB
		} else if fileSize > 256*gib { // over 256GB
			partSize = 41231687 // ≈ 39.3216MB
		} else if fileSize > 128*gib { // over 128GB
			partSize = 27487791 // ≈ 26.2144MB
		}
	}
	return partSize
}

// init registers the backend.
func init() {
	Register("open115")
}

// Register registers the backend.
func Register(fName string) {
	fs.Register(&fs.RegInfo{
		Name:        fName,
		Description: "Open 115 Cloud Drive",
		NewFs:       NewFs,
		Config: func(ctx context.Context, name string, m configmap.Mapper, config fs.ConfigIn) (*fs.ConfigOut, error) {
			fc := fshttp.NewClient(ctx)
			rc := rest.NewClient(fc)
			opt := new(Options)
			err := configstruct.Set(m, opt)
			if err != nil {
				return nil, err
			}
			f := &Fs{
				name:   name,
				opt:    *opt,
				client: newClient(rc, nil),
			}
			return f.Config(ctx, name, m, config)
		},
		Options: []fs.Option{
			{
				Name:     "app_id",
				Help:     "open115 appid (leave blank to use default)",
				Required: false,
			},
			{
				Name:      "refresh_token",
				Help:      "Refresh Token (use token instead of appid to authorize)",
				Required:  false,
				Advanced:  true,
				Sensitive: true,
			},
			{
				Name:      config.ConfigToken,
				Help:      "OAuth Access Token as a JSON blob.",
				Advanced:  true,
				Sensitive: true,
			},
			{
				Name:     config.ConfigEncoding,
				Help:     config.ConfigEncodingHelp,
				Advanced: true,
				// 115 Cloud Drive specific encoding rules
				// Based on testing and API limitations
				// 115 does not allow: " \ < >
				// Also encode leading spaces and control characters as they cause issues
				Default: encoder.Base |
					encoder.EncodeBackSlash |
					encoder.EncodeLeftSpace |
					encoder.EncodeLeftCrLfHtVt |
					encoder.EncodeRightSpace |
					encoder.EncodeRightCrLfHtVt |
					encoder.EncodeInvalidUtf8 |
					encoder.EncodeDel |
					encoder.EncodeDoubleQuote |
					encoder.EncodeLtGt,
			},
		},
	})
}

// Options defines the configuration for this backend.
type Options struct {
	AppID        string               `config:"app_id"`        // AppID is the 115 Open Platform Application ID.
	RefreshToken string               `config:"refresh_token"` // RefreshToken is an optional refresh token.
	Enc          encoder.MultiEncoder `config:"encoding"`      // Enc is the encoding for file names.
}

// Fs represents an 115 drive file system.
type Fs struct {
	name        string             // name is the remote name.
	root        string             // root is the root path.
	opt         Options            // opt stores the configuration options.
	features    *fs.Features       // features caches the optional features.
	pacer       *fs.Pacer          // pacer is the pacer for this Fs.
	client      *client            // client is the API client.
	tokenSource *TokenSource       // tokenSource provides API tokens.
	dirCache    *dircache.DirCache // dirCache caches directory listings.
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
	fc := fshttp.NewClient(ctx)
	rc := rest.NewClient(fc)
	tokenSource, err := NewTokenSource(ctx, name, m, rc)
	if err != nil {
		return nil, err
	}
	c := newClient(rc, tokenSource)
	f := &Fs{
		name:        name,
		root:        root,
		opt:         *opt,
		pacer:       fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		client:      c,
		tokenSource: tokenSource,
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

	var nextOffset int64
	for {
		resp, err := f.getFileList(ctx, directoryID, defaultListPageSize, nextOffset)
		if err != nil {
			return "", false, err
		}
		for _, item := range resp.Data {
			// Decode the file name from the API response and compare with the requested name
			decodedName := f.opt.Enc.ToStandardName(item.FN)
			if decodedName == leafName {
				return item.FID, item.FC == fileCategoryFolder, nil // Return ID and whether it's a directory
			}
		}
		// If the returned count is less than the requested count, we have reached the end.
		if len(resp.Data) < defaultListPageSize {
			break
		}
		nextOffset += defaultListPageSize
	}
	return "", false, nil
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
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	directoryID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}

	var nextOffset int64
	var fileList []api.FileInfo

	// Get all files page by page
	for {
		resp, err := f.getFileList(ctx, directoryID, defaultListPageSize, nextOffset)
		if err != nil {
			return nil, err
		}

		fileList = append(fileList, resp.Data...)

		// If the returned count is less than the requested count, we have reached the end.
		if len(resp.Data) < defaultListPageSize {
			break
		}

		nextOffset += defaultListPageSize
	}

	entries = make([]fs.DirEntry, 0, len(fileList))
	for _, item := range fileList {
		// Decode the file name from the API response
		decodedName := f.opt.Enc.ToStandardName(item.FN)
		remote := path.Join(dir, decodedName)
		if item.FC == fileCategoryFolder { // Folder
			// Cache directory ID
			f.dirCache.Put(remote, item.FID)
			d := fs.NewDir(remote, time.Unix(item.UPT, 0)).SetID(item.FID)
			entries = append(entries, d)
		} else {
			o, err := f.newObjectWithInfo(ctx, remote, &item)
			if err != nil {
				return nil, fmt.Errorf("failed to parse metadata for %q: %w", remote, err)
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
		return nil, errors.New("open115 requires a known file size")
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
	_, err = f.deleteFiles(ctx, []string{dirID}, "")
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
	leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, o.remote, false)
	if err != nil {
		if errors.Is(err, fs.ErrorDirNotFound) {
			return fs.ErrorObjectNotFound
		}
		return err
	}
	var nextOffset int64
	for {
		resp, err := o.fs.getFileList(ctx, directoryID, defaultListPageSize, nextOffset)
		if err != nil {
			return err
		}
		// Search for matching files in the current page
		for _, item := range resp.Data {
			// Decode the file name from the API response and compare with the requested name
			decodedName := o.fs.opt.Enc.ToStandardName(item.FN)
			if decodedName == leaf {
				return o.setMetaData(&item)
			}
		}
		// If the returned count is less than the requested limit, it means we've reached the last page
		if len(resp.Data) < defaultListPageSize {
			break
		}
		// Update the offset for the next page
		nextOffset += defaultListPageSize
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
	return o.fs.download(ctx, o.downloadURL, o.size, options...)
}

func (o *Object) downloadURL(ctx context.Context) (string, error) {
	resp, err := o.fs.getFileDownloadURL(ctx, o.pickCode)
	if err != nil {
		return "", fmt.Errorf("[Open] failed to get download URL: %w", err)
	}

	var fileInfo api.FileDownloadInfo
	for fileID, info := range resp.Data {
		if fileID == o.id {
			fileInfo = info
			break
		}
	}

	if fileInfo.URL.URL == "" {
		return "", fmt.Errorf("[Open] could not find download URL for file id %s in API response", o.id)
	}
	return fileInfo.URL.URL, nil
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
		return errors.New("open115 requires a known file size")
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
	_, err := o.fs.deleteFiles(ctx, []string{o.id}, "")
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
		_, rollbackErr := f.deleteFiles(cleanupCtx, []string{info.FID}, "")
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

// CleanUp permanently deletes every item in the recycle bin.
func (f *Fs) CleanUp(ctx context.Context) error {
	form := url.Values{}
	form.Set("tid", "")
	opts := rest.Opts{
		Method:  http.MethodPost,
		RootURL: baseAPI,
		Path:    "/open/rb/del",
	}
	var resp api.FileOperationResponse
	return f.callAPIWithForm(ctx, opts, form, &resp, &resp.Response)
}

// Config handles the configuration process.
func (f *Fs) Config(ctx context.Context, name string, m configmap.Mapper, config fs.ConfigIn) (*fs.ConfigOut, error) {
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	switch config.State {
	case "":
		// Check token exists
		if _, err := oauthutil.GetToken(name, m); err != nil {
			if opt.RefreshToken == "" {
				return fs.ConfigGoto("choose_auth_type")
			}
			fc := fshttp.NewClient(ctx)
			ts := &TokenSource{
				c: rest.NewClient(fc),
				token: &api.Token{
					RefreshToken: opt.RefreshToken,
				},
				ctx:  ctx,
				m:    m,
				name: name,
			}
			err := ts.refreshToken()
			if err != nil {
				return nil, fmt.Errorf("failed to validate/refresh token: %w", err)
			}
			return &fs.ConfigOut{State: ""}, nil
		}
		return fs.ConfigConfirm("choose_reauthorize", false, "consent_to_authorize", "Re-authorize for new token?")
	case "choose_reauthorize":
		if config.Result == "false" {
			// User doesn't want to re-authorize, so return empty state
			return nil, nil
		}
		// User wants to re-authorize, so proceed to choose auth type
		return fs.ConfigGoto("choose_auth_type")
	case "choose_auth_type":
		return fs.ConfigChooseExclusiveFixed("choose_auth_type_done", "auth_type", "Select authorization type", []fs.OptionExample{
			{Value: "token", Help: "Authenticate using an existing refresh token"},
			{Value: "auth", Help: "Authenticate with 115 Open Platform QRCode"},
		})
	case "choose_auth_type_done":
		if config.Result == "auth" {
			return fs.ConfigGoto("authorize")
		} else if config.Result == "token" {
			return fs.ConfigPassword("authorize_token", "refresh_token", "Enter your refresh token")
		}
	case "authorize_token":
		// Use TokenSource to save token
		fc := fshttp.NewClient(ctx)
		ts := &TokenSource{
			c: rest.NewClient(fc),
			token: &api.Token{
				RefreshToken: config.Result,
			},
			ctx:  ctx,
			m:    m,
			name: name,
		}
		err := ts.refreshToken() // Immediately refresh to validate and get other token parts
		if err != nil {
			return nil, fmt.Errorf("failed to validate/refresh token: %w", err)
		}
		return &fs.ConfigOut{State: ""}, nil
	case "authorize":
		appID := func() string {
			if opt.AppID != "" {
				return opt.AppID
			}
			return defaultAppID
		}()
		// Use TokenSource to save token
		fc := fshttp.NewClient(ctx)
		ts := &TokenSource{
			c:    rest.NewClient(fc),
			ctx:  ctx,
			name: name,
			m:    m,
		}
		err = ts.Auth(appID)
		if err != nil {
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
		return &fs.ConfigOut{State: ""}, nil
	}
	return nil, fmt.Errorf("unknown config state %q", config.State)
}

// parseSignCheckRange parses and validates an inclusive secondary authentication range.
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

func newOSSBucket(token api.UploadTokenData, bucketName string) (*oss.Bucket, error) {
	ossClient, err := oss.New(token.Endpoint, token.AccessKeyID, token.AccessKeySecret, oss.SecurityToken(token.SecurityToken))
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
	return errors.As(err, &serviceErr) && serviceErr.StatusCode == http.StatusForbidden
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
	token, err := f.getValidUploadToken(ctx)
	if err != nil {
		return nil, err
	}
	return newOSSBucket(*token, bucketName)
}

// uploadToOSS uploads a file to Alibaba Cloud OSS.
func (f *Fs) uploadToOSS(ctx context.Context, in io.Reader, initData api.InitUploadData, token api.UploadTokenData, fileSize int64, sha1Hash string) (*api.UploadResult, error) {
	callback, err := initData.GetCallback()
	if err != nil {
		return nil, err
	}
	reader, cleanup, err := retryReadSeeker(in, fileSize)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	bucket, err := newOSSBucket(token, initData.Bucket)
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
		uploadReader := &countingReader{r: io.LimitReader(reader, fileSize)}
		putErr := bucket.PutObject(initData.Object, uploadReader,
			oss.Callback(callbackStr),
			oss.CallbackVar(callbackVarStr),
			oss.CallbackResult(&callbackBody),
			oss.WithContext(ctx),
		)
		if putErr == nil && uploadReader.n != fileSize {
			putErr = fmt.Errorf("failed to read upload data: read %d bytes, expected %d", uploadReader.n, fileSize)
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

func retryReadSeeker(in io.Reader, size int64) (io.ReadSeeker, func(), error) {
	if rs, ok := in.(io.ReadSeeker); ok && isActuallySeekable(rs) {
		return rs, func() {}, nil
	}
	return copyReaderToTempFile(in, size)
}

func stageUploadPart(in io.Reader, size int64) (io.ReadSeeker, int64, func(), error) {
	if rs, ok := in.(io.ReadSeeker); ok && isActuallySeekable(rs) {
		start, err := rs.Seek(0, io.SeekCurrent)
		return rs, start, func() {}, err
	}
	file, err := os.CreateTemp("", "rclone-open115-part-*")
	if err != nil {
		return nil, 0, func() {}, fmt.Errorf("failed to create multipart temporary file: %w", err)
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}
	written, err := io.CopyN(file, in, size)
	if err != nil {
		cleanup()
		return nil, 0, func() {}, fmt.Errorf("failed to stage upload part: read %d bytes, expected %d: %w", written, size, err)
	}
	return file, 0, cleanup, nil
}

// uploadMultipartToOSS uploads a file sequentially using OSS multipart upload.
func (f *Fs) uploadMultipartToOSS(ctx context.Context, in io.Reader, initData api.InitUploadData, token api.UploadTokenData, fileSize, chunkSize int64, sha1Hash string) (result *api.UploadResult, err error) {
	callback, err := initData.GetCallback()
	if err != nil {
		return nil, err
	}
	bucket, err := newOSSBucket(token, initData.Bucket)
	if err != nil {
		return nil, err
	}
	ossPacer := fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))
	authRetried := false
	var imur oss.InitiateMultipartUploadResult
	err = ossPacer.Call(func() (bool, error) {
		imur, err = bucket.InitiateMultipartUpload(initData.Object, oss.Sequential(), oss.WithContext(ctx))
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

	partCount := (fileSize + chunkSize - 1) / chunkSize
	parts := make([]oss.UploadPart, 0, partCount)
	for partNumber := int64(1); partNumber <= partCount; partNumber++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		curSize := chunkSize
		if partNumber == partCount {
			curSize = fileSize - (partNumber-1)*chunkSize
		}
		partReader, start, cleanup, stageErr := stageUploadPart(in, curSize)
		if stageErr != nil {
			return nil, stageErr
		}
		var part oss.UploadPart
		authRetried := false
		err = ossPacer.Call(func() (bool, error) {
			if _, seekErr := partReader.Seek(start, io.SeekStart); seekErr != nil {
				return false, fmt.Errorf("failed to rewind upload part %d: %w", partNumber, seekErr)
			}
			counted := &countingReader{r: io.LimitReader(partReader, curSize)}
			part, err = bucket.UploadPart(imur, counted, curSize, int(partNumber), oss.WithContext(ctx))
			if err == nil && counted.n != curSize {
				err = fmt.Errorf("failed to read part %d data: read %d bytes, expected %d", partNumber, counted.n, curSize)
			}
			if isOSSAuthError(err) && !authRetried {
				bucket, err = f.refreshOSSBucket(ctx, initData.Bucket)
				authRetried = err == nil
				return authRetried, err
			}
			return shouldRetryOSS(ctx, err)
		})
		cleanup()
		if err != nil {
			return nil, fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}
		parts = append(parts, part)
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
			bucket, err = f.refreshOSSBucket(ctx, initData.Bucket)
			authRetried = err == nil
			return authRetried, err
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

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

// isActuallySeekable tests if a ReadSeeker is actually usable by attempting a Seek operation
func isActuallySeekable(rs io.ReadSeeker) bool {
	_, err := rs.Seek(0, io.SeekCurrent)
	return err == nil
}

// copyReaderToTempFile copies an upload stream to a temporary file and returns it as an io.ReadSeeker.
func copyReaderToTempFile(in io.Reader, size int64) (rs io.ReadSeeker, cleanup func(), err error) {
	// Create temporary file
	tempFile, err := os.CreateTemp("", "rclone-open115-upload-*")
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Setup cleanup function
	cleanup = func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}

	// Read at most one byte beyond the declared size so a bad source can't fill the disk.
	written, err := io.Copy(tempFile, io.LimitReader(in, size+1))
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

func (p *preparedUpload) ensureReadSeeker() (io.ReadSeeker, error) {
	if p.readSeeker != nil {
		return p.readSeeker, nil
	}
	rs, cleanup, err := copyReaderToTempFile(p.reader, p.size)
	if err != nil {
		return nil, err
	}
	oldCleanup := p.cleanup
	p.cleanup = func() {
		cleanup()
		oldCleanup()
	}
	p.reader = rs
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
	p.reader = p.readSeeker
	return nil
}

// calculateSHA1 calculates the SHA1 hash of data
func calculateSHA1(r io.Reader) (string, error) {
	h := sha1.New()
	_, err := io.Copy(h, r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// calculateSHA1FromReadSeeker calculates the SHA1 hash of a ReadSeeker
func calculateSHA1FromReadSeeker(rs io.ReadSeeker) (string, error) {
	// Save current position
	currentPos, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("failed to get current position: %w", err)
	}

	// Ensure position is restored when function returns
	defer func() {
		_, _ = rs.Seek(currentPos, io.SeekStart)
	}()

	// Calculate SHA1 from beginning
	_, err = rs.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("failed to seek to start: %w", err)
	}

	return calculateSHA1(rs)
}

func calculateSHA1FromObject(ctx context.Context, obj fs.Object) (sha1Hash string, err error) {
	rc, err := obj.Open(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to open source object: %w", err)
	}
	defer fs.CheckClose(rc, &err)
	return calculateSHA1(rc)
}

func calculateSHA1RangeFromReadSeeker(rs io.ReadSeeker, start, size int64) (string, error) {
	currentPos, err := rs.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", fmt.Errorf("failed to get current position: %w", err)
	}
	defer func() {
		_, _ = rs.Seek(currentPos, io.SeekStart)
	}()

	_, err = rs.Seek(start, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("failed to seek to range start: %w", err)
	}
	return calculateSHA1Range(rs, size)
}

func calculateSHA1RangeFromObject(ctx context.Context, obj fs.Object, start, end int64) (sha1Hash string, err error) {
	rc, err := obj.Open(ctx, &fs.RangeOption{Start: start, End: end})
	if err != nil {
		return "", fmt.Errorf("failed to open source range: %w", err)
	}
	defer fs.CheckClose(rc, &err)
	return calculateSHA1Range(rc, end-start+1)
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

	rs, err := p.ensureReadSeeker()
	if err != nil {
		return "", err
	}
	return calculateSHA1RangeFromReadSeeker(rs, start, end-start+1)
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
		FileID:   fileSHA1,
	}

	// Execute upload initialization request
	initResp, err := f.initUpload(ctx, initReq)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize upload: %w", err)
	}

	initData := initResp.Data
	if initData.Status == 6 || initData.Status == 7 || initData.Status == 8 {
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
	h := sha1.New()
	n, err := io.CopyN(h, r, size)
	if err != nil {
		return "", fmt.Errorf("failed to read %d bytes, got %d: %w", size, n, err)
	}
	if n != size {
		return "", fmt.Errorf("failed to read %d bytes, only got %d", size, n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// prepareFileForUpload prepares a file for upload, calculating SHA1 and returning necessary info.
func prepareFileForUpload(ctx context.Context, in io.Reader, src fs.ObjectInfo, size int64) (upload *preparedUpload, err error) {
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
			sha1Hash, err := calculateSHA1FromReadSeeker(rs)
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

	rs, cleanup, err := copyReaderToTempFile(in, size)
	if err != nil {
		return nil, err
	}

	sha1Hash, err := calculateSHA1FromReadSeeker(rs)
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
		fs.Debugf(f, "Fast upload successful for %s, file ID: %s", remote, initData.FileID)
		// Create and return new object
		return f.newObjectWithInfo(ctx, remote, &api.FileInfo{
			FID:  initData.FileID,
			FN:   path.Base(remote),
			PC:   initData.PickCode,
			FS:   json.Number(fmt.Sprintf("%d", size)),
			UPT:  time.Now().Unix(),
			SHA1: prepared.sha1Hash,
		})
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
	chunkSize := calPartSize(size)

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

	// Create and return new object
	return f.newObjectWithInfo(ctx, remote, &api.FileInfo{
		FID:  result.FileID,
		FN:   path.Base(remote),
		PC:   result.PickCode,
		FS:   json.Number(fmt.Sprintf("%d", size)),
		UPT:  time.Now().Unix(),
		SHA1: prepared.sha1Hash,
	})
}

func resetAPIResponse(response any) {
	if responseWithState, ok := response.(interface{ GetResponse() *api.Response }); ok {
		*responseWithState.GetResponse() = api.Response{}
	}
}

func (f *Fs) callAPI(ctx context.Context, opts rest.Opts, response any, apiResp *api.Response) error {
	return f.pacer.Call(func() (bool, error) {
		callOpts := opts
		resetAPIResponse(response)
		httpResp, err := f.client.CallJSON(ctx, &callOpts, nil, response)
		return shouldRetry(ctx, httpResp, apiResp, err)
	})
}

func (f *Fs) callAPIWithForm(ctx context.Context, opts rest.Opts, form url.Values, response any, apiResp *api.Response) error {
	encoded := form.Encode()
	opts.ContentType = "application/x-www-form-urlencoded"
	return f.pacer.Call(func() (bool, error) {
		callOpts := opts
		callOpts.Body = strings.NewReader(encoded)
		resetAPIResponse(response)
		httpResp, err := f.client.CallJSON(ctx, &callOpts, nil, response)
		return shouldRetry(ctx, httpResp, apiResp, err)
	})
}

func shouldRetry(ctx context.Context, res *http.Response, resp *api.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}

	if resp != nil && !resp.Success() {
		err = &apiError{response: *resp}
		if resp.Code == open115InternalErrorCode || resp.Code == open115OperationPendingCode {
			return true, err
		}
		if resp.Code == open115AccessLimitCode {
			return false, fserrors.NoRetryError(err)
		}
		return false, fserrors.NoRetryError(err)
	}

	retry := false
	if res != nil {
		switch res.StatusCode {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			if retryAfterValue := res.Header.Get("Retry-After"); retryAfterValue != "" {
				retryAfter, parseErr := strconv.Atoi(retryAfterValue)
				if parseErr != nil {
					fs.Debugf(nil, "Failed to parse Retry-After: %q: %v", retryAfterValue, parseErr)
				} else {
					retry = true
					err = pacer.RetryAfterError(err, time.Second*time.Duration(retryAfter))
				}
			}
		}
	}

	return retry || fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(res, retryHTTPStatusCodes), err
}

type apiError struct {
	response api.Response
}

func (e *apiError) Error() string {
	return "API error: " + e.response.ErrorDetails()
}

// download starts a download from a generated URL and returns the response body reader.
func (f *Fs) download(ctx context.Context, urlFn func(context.Context) (string, error), size int64, options ...fs.OpenOption) (io.ReadCloser, error) {
	opts := rest.Opts{
		Method: "GET",
	}
	opts.Options = options
	var resp *http.Response
	var downloadURL string
	err := f.pacer.Call(func() (bool, error) {
		var err error
		if downloadURL == "" {
			downloadURL, err = urlFn(ctx)
			if err != nil {
				return false, err
			}
			opts.RootURL = downloadURL
		}
		resp, err = f.client.Call(ctx, &opts)
		retry, err := shouldRetry(ctx, resp, nil, err)
		if retry || fserrors.ContextError(ctx, &err) {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return retry, err
		}
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			downloadURL = ""
			return true, err
		}
		return false, err
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, errors.New("download failed: empty response")
	}
	if err := rest.CheckContentRange(resp, options, size); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	return resp.Body, nil
}

// createFolder creates a new folder.
func (f *Fs) createFolder(ctx context.Context, pid string, fileName string) (*api.FolderCreateResponse, error) {
	// Encode the file name for the API
	encodedFileName := f.opt.Enc.FromStandardName(fileName)
	values := url.Values{}
	values.Set("pid", pid)
	values.Set("file_name", encodedFileName)
	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/folder/add",
	}
	var resp api.FolderCreateResponse
	err := f.callAPIWithForm(ctx, opts, values, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// getFileList gets the list of files and folders.
func (f *Fs) getFileList(ctx context.Context, parentID string, pageSize, offset int64) (*api.FileListResponse, error) {

	// Build query parameters
	params := url.Values{}
	params.Set("cid", parentID)
	params.Set("limit", fmt.Sprintf("%d", pageSize))
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("cur", "1")
	params.Set("stdir", "1")
	params.Set("show_dir", "1")
	opts := rest.Opts{
		Method:     "GET",
		RootURL:    baseAPI,
		Path:       "/open/ufile/files",
		Parameters: params,
	}
	var resp api.FileListResponse
	err := f.callAPI(ctx, opts, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// getFileDownloadURL gets the download URL for a file.
func (f *Fs) getFileDownloadURL(ctx context.Context, pickCode string) (*api.FileDownloadResponse, error) {
	formData := url.Values{}
	formData.Set("pick_code", pickCode)
	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/ufile/downurl",
	}

	var resp api.FileDownloadResponse
	err := f.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// deleteFiles deletes files or folders.
func (f *Fs) deleteFiles(ctx context.Context, fileIDs []string, parentID string) (*api.FileOperationResponse, error) {
	formData := url.Values{}
	formData.Set("file_ids", strings.Join(fileIDs, ","))
	if parentID != "" {
		formData.Set("parent_id", parentID)
	}

	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/ufile/delete",
	}

	var resp api.FileOperationResponse
	err := f.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// updateFile updates file information (rename or star).
func (f *Fs) updateFile(ctx context.Context, fileID string, options map[string]string) (*api.FileUpdateResponse, error) {
	formData := url.Values{}
	formData.Set("file_id", fileID)
	for key, value := range options {
		formData.Set(key, value)
	}

	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/ufile/update",
	}

	var resp api.FileUpdateResponse
	err := f.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}

	return &resp, nil
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

func (f *Fs) hasOtherLeaf(ctx context.Context, directoryID, leaf, excludedID string) (bool, error) {
	var offset int64
	for {
		resp, err := f.getFileList(ctx, directoryID, defaultListPageSize, offset)
		if err != nil {
			return false, err
		}
		for _, item := range resp.Data {
			if item.FID != excludedID && f.opt.Enc.ToStandardName(item.FN) == leaf {
				return true, nil
			}
		}
		if len(resp.Data) < defaultListPageSize {
			return false, nil
		}
		offset += defaultListPageSize
	}
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
func (f *Fs) moveFiles(ctx context.Context, fileIDs []string, toCID string) (*api.FileOperationResponse, error) {
	formData := url.Values{}
	formData.Set("file_ids", strings.Join(fileIDs, ","))
	formData.Set("to_cid", toCID)

	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/ufile/move",
	}

	var resp api.FileOperationResponse
	err := f.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// getUploadToken gets the upload token
func (f *Fs) getUploadToken(ctx context.Context) (*api.UploadTokenResponse, error) {
	opts := rest.Opts{
		Method:  "GET",
		RootURL: baseAPI,
		Path:    "/open/upload/get_token",
	}

	var resp api.UploadTokenResponse
	err := f.callAPI(ctx, opts, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

var errUploadTokenExpired = errors.New("OSS upload token is expired")

func validateUploadToken(token *api.UploadTokenData, now time.Time) error {
	if token.Endpoint == "" || token.AccessKeyID == "" || token.AccessKeySecret == "" || token.SecurityToken == "" {
		return errors.New("upload token response is incomplete")
	}
	expires, err := time.Parse(time.RFC3339Nano, token.Expiration)
	if err != nil {
		return fmt.Errorf("invalid upload token expiration %q: %w", token.Expiration, err)
	}
	if !expires.After(now.Add(tokenExpiryGrace)) {
		return errUploadTokenExpired
	}
	return nil
}

func (f *Fs) getValidUploadToken(ctx context.Context) (*api.UploadTokenData, error) {
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := f.getUploadToken(ctx)
		if err != nil {
			return nil, err
		}
		err = validateUploadToken(&resp.Data, time.Now())
		if err == nil {
			return &resp.Data, nil
		}
		if !errors.Is(err, errUploadTokenExpired) {
			return nil, err
		}
	}
	return nil, errUploadTokenExpired
}

// initUpload initializes file upload
func (f *Fs) initUpload(ctx context.Context, req *api.InitUploadRequest) (*api.InitUploadResponse, error) {
	// Build form data
	formData := url.Values{}
	formData.Set("file_name", req.FileName)
	formData.Set("file_size", fmt.Sprintf("%d", req.FileSize))
	formData.Set("target", req.Target)
	formData.Set("fileid", req.FileID)

	if req.PreID != "" {
		formData.Set("preid", req.PreID)
	}
	if req.PickCode != "" {
		formData.Set("pick_code", req.PickCode)
	}
	if req.TopUpload != 0 {
		formData.Set("topupload", fmt.Sprintf("%d", req.TopUpload))
	}
	if req.SignKey != "" {
		formData.Set("sign_key", req.SignKey)
	}
	if req.SignVal != "" {
		formData.Set("sign_val", req.SignVal)
	}

	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/upload/init",
	}

	var resp api.InitUploadResponse
	err := f.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// getUserInfo gets the user information including space usage and VIP status.
func (f *Fs) getUserInfo(ctx context.Context) (*api.UserInfoResponse, error) {
	opts := rest.Opts{
		Method:  "GET",
		RootURL: baseAPI,
		Path:    "/open/user/info",
	}

	var resp api.UserInfoResponse
	err := f.callAPI(ctx, opts, &resp, &resp.Response)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

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
		if cleanupErr := f.cleanupTempDir(cleanupCtx, tempDirID); cleanupErr != nil {
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
func (f *Fs) cleanupTempDir(ctx context.Context, tempDirID string) error {
	// Delete the temporary directory (this should also delete any remaining files)
	_, err := f.deleteFiles(ctx, []string{tempDirID}, "")
	return err
}

// performCopy executes the actual copy operation via API
func (f *Fs) performCopy(ctx context.Context, pid string, fileIDs []string) error {
	// Use proper form data encoding
	values := url.Values{}
	values.Set("pid", pid)
	values.Set("file_id", strings.Join(fileIDs, ","))
	values.Set("no_dupli", "0")
	opts := rest.Opts{
		Method:  "POST",
		RootURL: baseAPI,
		Path:    "/open/ufile/copy",
	}

	var resp api.FileOperationResponse
	err := f.callAPIWithForm(ctx, opts, values, &resp, &resp.Response)
	if err != nil {
		return err
	}

	return nil
}

// findCopiedFile returns the only file in a fresh temporary directory.
func (f *Fs) findCopiedFile(ctx context.Context, dstDirID string) (*api.FileInfo, error) {
	resp, err := f.getFileList(ctx, dstDirID, defaultListPageSize, 0)
	if err != nil {
		return nil, err
	}
	var copied *api.FileInfo
	for i := range resp.Data {
		if resp.Data[i].FC != fileCategoryFolder {
			if copied != nil {
				return nil, errors.New("temporary copy directory contains multiple files")
			}
			copied = &resp.Data[i]
		}
	}
	if copied == nil {
		return nil, errors.New("copied file not found in temporary directory")
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
