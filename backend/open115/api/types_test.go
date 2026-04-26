package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResponseStateNumber(t *testing.T) {
	var resp TokenResponse
	err := json.Unmarshal([]byte(`{"state":0,"code":40140120,"errno":40140120,"data":{},"message":"refresh token error","error":"refresh token error"}`), &resp)
	if err != nil {
		t.Fatal(err)
	}
	if resp.State == nil {
		t.Fatal("expected state to be set")
	}
	if resp.State.Bool() {
		t.Fatal("expected numeric state 0 to be false")
	}
	if resp.Success() {
		t.Fatal("expected response to be unsuccessful")
	}
	for _, want := range []string{"state=false", "code=40140120", "errno=40140120", "message=refresh token error", "error=refresh token error"} {
		if !strings.Contains(resp.ErrorDetails(), want) {
			t.Fatalf("expected error details to contain %q, got %q", want, resp.ErrorDetails())
		}
	}
}

func TestResponseStateBoolAndString(t *testing.T) {
	for _, input := range []string{
		`{"state":true}`,
		`{"state":1}`,
		`{"state":"true"}`,
		`{"state":"1"}`,
	} {
		var resp Response
		err := json.Unmarshal([]byte(input), &resp)
		if err != nil {
			t.Fatal(err)
		}
		if resp.State == nil || !resp.State.Bool() {
			t.Fatalf("expected state to be true for %s", input)
		}
	}
}
