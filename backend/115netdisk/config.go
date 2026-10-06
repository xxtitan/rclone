package netdisk115

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/115netdisk/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/rest"
	"github.com/skip2/go-qrcode"
)

// Register registers the cookie-authenticated 115 backend.
func Register(name string) {
	fs.Register(&fs.RegInfo{Name: name, Description: "115 Netdisk", NewFs: NewFs, Config: configure,
		Options: []fs.Option{
			{Name: "cookie", Help: "115 Cookie header or cookie dictionary JSON.", Sensitive: true, Hide: fs.OptionHideConfigurator},
			{Name: "client_version", Help: "macOS client protocol version.", Default: defaultClientVersion, Advanced: true},
			{Name: "user_agent", Help: "Override the macOS client User-Agent for API and content requests.", Advanced: true},
			{Name: "security_key", Help: "Account security key for permanently emptying the recycle bin.", Sensitive: true, Advanced: true},
			{Name: "encoding", Help: "Filename encoding for 115 netdisk.", Advanced: true, Default: encoder.Base | encoder.EncodeBackSlash | encoder.EncodeLeftSpace | encoder.EncodeLeftCrLfHtVt | encoder.EncodeRightSpace | encoder.EncodeRightCrLfHtVt | encoder.EncodeInvalidUtf8 | encoder.EncodeDel | encoder.EncodeDoubleQuote | encoder.EncodeLtGt},
		}})
}

// Config runs QR authorization or accepts a pasted Cookie.
func (f *Fs) Config(ctx context.Context, name string, m configmap.Mapper, in fs.ConfigIn) (*fs.ConfigOut, error) {
	return configure(ctx, name, m, in)
}

func configure(ctx context.Context, name string, m configmap.Mapper, in fs.ConfigIn) (*fs.ConfigOut, error) {
	switch in.State {
	case "":
		cookie, _ := m.Get("cookie")
		if cookie != "" {
			_, err := loadCookies(&Options{Cookie: cookie})
			return nil, err
		}
		return fs.ConfigChooseExclusiveFixed("auth_choice", "auth_type", "Select authorization type", []fs.OptionExample{{Value: "qr", Help: "Scan with the 115 mobile app"}, {Value: "cookie", Help: "Paste an existing Cookie"}})
	case "auth_choice":
		if in.Result == "cookie" {
			out, err := fs.ConfigInput("cookie", "cookie", "Paste your 115 Cookie header or cookie dictionary JSON")
			if err != nil {
				return nil, err
			}
			out.Option.Sensitive = true
			return out, nil
		}
		if in.Result == "qr" {
			opt := new(Options)
			if err := configstruct.Set(m, opt); err != nil {
				return nil, err
			}
			cookie, err := qrAuthorize(ctx, opt)
			if err != nil {
				return nil, err
			}
			m.Set("cookie", cookie)
			return nil, nil
		}
		return nil, errors.New("unknown session configuration choice")
	case "cookie":
		cookie := strings.TrimSpace(in.Result)
		if _, err := loadCookies(&Options{Cookie: cookie}); err != nil {
			return nil, err
		}
		m.Set("cookie", cookie)
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown configuration state %q", in.State)
	}
}

func qrAuthorize(ctx context.Context, opt *Options) (string, error) {
	version := opt.ClientVersion
	if version == "" {
		version = defaultClientVersion
	}
	ua := opt.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0; Mac OS X/13.0; 115Life/" + version
	}
	ctx, clientConfig := fs.AddConfig(ctx)
	clientConfig.UserAgent = ua
	client := rest.NewClient(fshttp.NewClient(ctx)).SetHeader("User-Agent", ua).SetHeader("Accept", "application/json, text/plain, */*")
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	device := hex.EncodeToString(random[:])
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	call := func(method, root, path string, query, form url.Values, target any) error {
		opts := rest.Opts{Method: method, RootURL: root, Path: path, Parameters: query}
		if form != nil {
			opts.ContentType = "application/x-www-form-urlencoded; charset=utf-8"
			opts.Body = strings.NewReader(form.Encode())
		}
		_, err := client.CallJSON(ctx, &opts, nil, target)
		return err
	}
	var token struct {
		State api.ResponseState `json:"state"`
		Data  struct {
			UID    string  `json:"uid"`
			Time   api.Int `json:"time"`
			Sign   string  `json:"sign"`
			QRCode string  `json:"qrcode"`
		} `json:"data"`
	}
	if err = call("GET", "https://qrcodeapi.115.com", "/api/1.0/os_mac/"+version+"/token", url.Values{"device_id": {device}, "device_name": {hostname}}, nil, &token); err != nil {
		return "", err
	}
	if !token.State.Bool() || token.Data.UID == "" || token.Data.Sign == "" || token.Data.QRCode == "" {
		return "", errors.New("QR token response is incomplete")
	}
	qr, err := qrcode.New(token.Data.QRCode, qrcode.Medium)
	if err != nil {
		return "", err
	}
	fmt.Print(qr.ToSmallString(false))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		var status struct {
			State api.ResponseState `json:"state"`
			Data  struct {
				Status *api.Int `json:"status"`
			} `json:"data"`
		}
		query := url.Values{"uid": {token.Data.UID}, "time": {fmt.Sprint(token.Data.Time)}, "sign": {token.Data.Sign}}
		if err = call("GET", "https://qrcodeapi.115.com", "/get/status/", query, nil, &status); err != nil {
			return "", err
		}
		if !status.State.Bool() {
			return "", errors.New("QR status request failed")
		}
		if status.Data.Status != nil {
			switch *status.Data.Status {
			case -2:
				return "", errors.New("QR authorization canceled")
			case -1:
				return "", errors.New("QR token expired; configure again")
			case 2:
				var login struct {
					State api.ResponseState `json:"state"`
					Data  struct {
						Cookie map[string]string `json:"cookie"`
						UserID api.String        `json:"user_id"`
					} `json:"data"`
				}
				form := url.Values{"account": {token.Data.UID}, "device": {hostname}, "device_id": {device}, "network": {"5"}, "os": {"macOS 13.0"}}
				if err = call("POST", passportAPI, "/app/1.0/os_mac/"+version+"/login/qrcode", nil, form, &login); err != nil {
					return "", err
				}
				if !login.State.Bool() || login.Data.Cookie["UID"] == "" || login.Data.UserID == "" {
					return "", errors.New("QR login requires a valid session; complete any mobile binding in the official client")
				}
				encoded, err := json.Marshal(login.Data.Cookie)
				if err != nil {
					return "", err
				}
				return string(encoded), nil
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
}
