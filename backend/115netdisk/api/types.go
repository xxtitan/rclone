// Package api defines the macOS 115 client response formats.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// String preserves string and integer identifiers without float conversion.
type String string

// UnmarshalJSON accepts a string or an exact integer.
func (s *String) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*s = String(value)
		return nil
	}
	if _, err := strconv.ParseInt(string(data), 10, 64); err != nil {
		return fmt.Errorf("invalid integer identifier: %w", err)
	}
	*s = String(data)
	return nil
}

// Int accepts integers and decimal strings used by the file API.
type Int int64

// UnmarshalJSON rejects fractional and out-of-range numbers.
func (n *Int) UnmarshalJSON(data []byte) error {
	var value String
	if err := value.UnmarshalJSON(data); err != nil {
		return err
	}
	if value == "" {
		*n = 0
		return nil
	}
	parsed, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return err
	}
	*n = Int(parsed)
	return nil
}

// ResponseState accepts the observed boolean and integer state variants.
type ResponseState bool

// UnmarshalJSON decodes explicit success and failure states.
func (s *ResponseState) UnmarshalJSON(data []byte) error {
	switch strings.TrimSpace(string(data)) {
	case "true", "1", `"true"`, `"1"`:
		*s = true
	case "false", "0", `"false"`, `"0"`:
		*s = false
	default:
		return errors.New("invalid API state")
	}
	return nil
}

// Bool returns the decoded state.
func (s ResponseState) Bool() bool { return bool(s) }

// Response contains the normalized API business state.
type Response struct {
	State   *ResponseState
	Code    int
	Errno   int
	Message string
	Error   string
}

// UnmarshalJSON reads service-specific code and message aliases.
func (r *Response) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = Response{}
	if value, ok := raw["state"]; ok {
		var state ResponseState
		if err := json.Unmarshal(value, &state); err != nil {
			return err
		}
		r.State = &state
	}
	for _, key := range []string{"code", "errno", "errNo", "errcode", "errCode", "err_code", "msg_code"} {
		value, ok := raw[key]
		if !ok || bytes.Equal(value, []byte("null")) {
			continue
		}
		var code Int
		if err := json.Unmarshal(value, &code); err != nil {
			return fmt.Errorf("invalid API code: %w", err)
		}
		r.Code = int(code)
		break
	}
	for _, key := range []string{"message", "error", "error_msg", "msg", "statusmsg"} {
		value, ok := raw[key]
		if !ok || bytes.Equal(value, []byte("null")) {
			continue
		}
		if err := json.Unmarshal(value, &r.Message); err != nil {
			return err
		}
		break
	}
	return nil
}

// GetResponse returns the business response.
func (r *Response) GetResponse() *Response { return r }

// Success requires an explicit successful business state and zero code.
func (r *Response) Success() bool {
	return r != nil && r.State != nil && r.State.Bool() && r.Code == 0 && r.Errno == 0
}

// ErrorDetails returns business diagnostics without request credentials.
func (r *Response) ErrorDetails() string { return fmt.Sprintf("code=%d: %s", r.Code, r.Message) }

// FileInfo is the normalized file or directory metadata used by the backend.
type FileInfo struct {
	FID  string
	PID  string
	FC   json.Number
	FN   string
	PC   string
	UPT  int64
	SHA1 string
	FS   json.Number
}

// RawEntry is a Web API directory member.
type RawEntry struct {
	// FID identifies a file; absence distinguishes directories in raw entries.
	FID *String `json:"fid"`
	// CID identifies a directory or a file parent.
	CID String `json:"cid"`
	// PID identifies a parent directory.
	PID String `json:"pid"`
	// Name contains the API leaf name.
	Name string `json:"n"`
	// Size contains the exact byte count.
	Size *Int `json:"s"`
	// SHA1 contains the whole-file SHA1.
	SHA1 string `json:"sha"`
	// PickCode identifies the download and upload result.
	PickCode string `json:"pc"`
	// Time contains the server epoch timestamp in seconds.
	Time Int `json:"te"`
}

// FileInfo validates member identity and exact file size.
func (r RawEntry) FileInfo() (FileInfo, error) {
	info := FileInfo{FN: r.Name, UPT: int64(r.Time), PC: r.PickCode, SHA1: r.SHA1}
	if r.FID == nil {
		info.FID, info.PID, info.FC = string(r.CID), string(r.PID), "0"
	} else {
		info.FID, info.PID, info.FC = string(*r.FID), string(r.CID), "1"
		if r.Size == nil || *r.Size < 0 {
			return info, errors.New("file response has no exact nonnegative size")
		}
		info.FS = json.Number(strconv.FormatInt(int64(*r.Size), 10))
	}
	if info.FID == "" || info.FN == "" {
		return info, errors.New("directory member has no identity or name")
	}
	return info, nil
}

// FileListResponse carries normalized entries and raw pagination metadata.
type FileListResponse struct {
	Response
	Data         []FileInfo
	Count        int64
	Offset       int64
	Limit        json.Number
	CID          String
	UseCache     bool
	CountPresent bool
}

// UnmarshalJSON preserves cached-page and missing-count distinctions.
func (r *FileListResponse) UnmarshalJSON(data []byte) error {
	var raw struct {
		Data     []RawEntry `json:"data"`
		Count    *Int       `json:"count"`
		Offset   Int        `json:"offset"`
		Limit    Int        `json:"limit"`
		CID      String     `json:"cid"`
		UseCache Int        `json:"use_cache"`
	}
	if err := json.Unmarshal(data, &r.Response); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Data = nil
	for _, entry := range raw.Data {
		info, err := entry.FileInfo()
		if err != nil {
			return err
		}
		r.Data = append(r.Data, info)
	}
	r.Offset, r.Limit, r.CID = int64(raw.Offset), json.Number(strconv.FormatInt(int64(raw.Limit), 10)), raw.CID
	r.UseCache, r.CountPresent = raw.UseCache == 1, raw.Count != nil
	if raw.Count != nil {
		r.Count = int64(*raw.Count)
	}
	return nil
}

// FileOperationResponse is the business result of a mutation.
type FileOperationResponse struct{ Response }

// FolderCreateData identifies a created directory.
type FolderCreateData struct {
	FileName string
	FileID   json.Number
}

// FolderCreateResponse normalizes the top-level directory identity.
type FolderCreateResponse struct {
	Response
	Data *FolderCreateData
}

// UnmarshalJSON reads the client's three directory-ID aliases.
func (r *FolderCreateResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.Response); err != nil {
		return err
	}
	var raw struct {
		CID        String `json:"cid"`
		FileID     String `json:"file_id"`
		CategoryID String `json:"category_id"`
		Name       string `json:"cname"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Data = nil
	for _, id := range []String{raw.CID, raw.FileID, raw.CategoryID} {
		if id != "" {
			r.Data = &FolderCreateData{FileName: raw.Name, FileID: json.Number(id)}
			break
		}
	}
	return nil
}

// FileUpdateData contains the actual name returned by a rename.
type FileUpdateData struct{ FileName string }

// FileUpdateResponse normalizes the top-level rename result.
type FileUpdateResponse struct {
	Response
	Data FileUpdateData
}

// UnmarshalJSON reads the returned actual name.
func (r *FileUpdateResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.Response); err != nil {
		return err
	}
	var raw struct {
		Name string `json:"file_name"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Data.FileName = raw.Name
	return nil
}

// UploadTokenData contains temporary OSS credentials.
type UploadTokenData struct {
	// Endpoint selects the OSS regional endpoint.
	Endpoint string `json:"endpoint"`
	// AccessKeySecret contains the temporary OSS signing secret.
	AccessKeySecret string `json:"AccessKeySecret"`
	// SecurityToken contains the temporary OSS session token.
	SecurityToken string `json:"SecurityToken"`
	// Expiration contains the credential expiry in RFC3339 format.
	Expiration string `json:"Expiration"`
	// AccessKeyID identifies the temporary OSS signing key.
	AccessKeyID string `json:"AccessKeyId"`
}

// InitUploadRequest defines the file content contract for initialization.
type InitUploadRequest struct {
	FileName string
	FileSize int64
	Target   string
	FileID   string
	SignKey  string
	SignVal  string
}

// InitUploadResponse carries the client's top-level initialization data.
type InitUploadResponse struct{ Data InitUploadData }

// InitUploadData is the decoded initialization outcome.
type InitUploadData struct {
	// PickCode identifies the download and upload result.
	PickCode string `json:"pickcode"`
	// Status selects the upload initialization outcome.
	Status int `json:"status"`
	// StatusCode contains the initialization business code.
	StatusCode int `json:"statuscode"`
	// StatusMessage contains the initialization diagnostic.
	StatusMessage string `json:"statusmsg"`
	// SignKey identifies the requested secondary content check.
	SignKey string `json:"sign_key"`
	// SignCheck contains the inclusive start-end byte range.
	SignCheck string `json:"sign_check"`
	// FileID identifies the committed object.
	FileID string `json:"-"`
	// Bucket names the assigned OSS bucket.
	Bucket string `json:"bucket"`
	// Object names the assigned OSS key.
	Object string `json:"object"`
	// Callback contains the server-provided callback JSON.
	Callback CallbackValue `json:"callback"`
}

// Callback holds the server-provided callback strings.
type Callback struct {
	// Callback contains the server-provided callback JSON.
	Callback string `json:"callback"`
	// CallbackVar contains the server-provided callback variables.
	CallbackVar string `json:"callback_var"`
}

// CallbackValue accepts a callback object or an empty rapid-upload value.
type CallbackValue struct{ Value *Callback }

// UnmarshalJSON accepts the observed empty callback forms.
func (v *CallbackValue) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) || bytes.Equal(data, []byte("[]")) || bytes.Equal(data, []byte(`""`)) {
		v.Value = nil
		return nil
	}
	var callback Callback
	if err := json.Unmarshal(data, &callback); err != nil {
		return err
	}
	v.Value = &callback
	return nil
}

// GetCallback validates the ordinary-upload callback.
func (d *InitUploadData) GetCallback() (Callback, error) {
	if d.Callback.Value == nil {
		return Callback{}, nil
	}
	if d.Callback.Value.Callback == "" || d.Callback.Value.CallbackVar == "" {
		return Callback{}, errors.New("incomplete upload callback")
	}
	return *d.Callback.Value, nil
}

// UploadResult identifies the committed cloud file.
type UploadResult struct {
	// PickCode identifies the download and upload result.
	PickCode string `json:"pick_code"`
	// FileSize contains the exact uploaded byte count.
	FileSize json.Number `json:"file_size"`
	// FileID identifies the committed object.
	FileID string `json:"file_id"`
	// SHA1 contains the whole-file SHA1.
	SHA1 string `json:"sha1"`
	// FileName contains the actual API leaf name.
	FileName string `json:"file_name"`
	// CID identifies a directory or a file parent.
	CID string `json:"cid"`
}

// UploadResultResponse contains the OSS callback result.
type UploadResultResponse struct {
	Response
	Data UploadResult
}

// UnmarshalJSON decodes the callback without losing the business envelope.
func (r *UploadResultResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.Response); err != nil {
		return err
	}
	var raw struct {
		Data UploadResult `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Data = raw.Data
	return nil
}

// SpaceSize contains an exact byte count and display value.
type SpaceSize struct {
	// Size contains the exact byte count.
	Size json.Number `json:"size"`
	// SizeFormat contains the server display value.
	SizeFormat string `json:"size_format"`
}

// SpaceInfo contains the three server-reported quota counters.
type SpaceInfo struct {
	// AllTotal contains total storage bytes.
	AllTotal SpaceSize `json:"all_total"`
	// AllRemain contains remaining storage bytes.
	AllRemain SpaceSize `json:"all_remain"`
	// AllUse contains used storage bytes.
	AllUse SpaceSize `json:"all_use"`
}

// UserInfoResponse contains the authenticated quota response.
type UserInfoResponse struct {
	Response
	Data struct {
		// RTSpaceInfo contains the decoded protocol value.
		RTSpaceInfo SpaceInfo `json:"space_info"`
	}
}

// UnmarshalJSON decodes the quota's data envelope.
func (r *UserInfoResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &r.Response); err != nil {
		return err
	}
	var raw struct {
		Data struct {
			SpaceInfo SpaceInfo `json:"space_info"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Data.RTSpaceInfo = raw.Data.SpaceInfo
	return nil
}
