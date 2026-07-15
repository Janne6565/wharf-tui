package sync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/vault"
)

// TestLiveE2E exercises the real pairing + sync loop against a running
// wharf-backend (dev profile, H2). Opt-in:
//
//	WHARF_E2E_BASE=http://localhost:8931 go test ./internal/sync -run TestLiveE2E -v
//
// It registers a throwaway account, issues a device code through the API
// (standing in for the web app), pairs via the api client, and drives a
// conflict → take-remote → push cycle through the engine.
func TestLiveE2E(t *testing.T) {
	base := os.Getenv("WHARF_E2E_BASE")
	if base == "" {
		t.Skip("set WHARF_E2E_BASE to run the live end-to-end test")
	}
	ctx := context.Background()
	tiny := vault.Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}
	password := []byte("hunter2-e2e")

	// The "web-side" vault registered with the account: 2 hosts.
	webPath := filepath.Join(t.TempDir(), "web.enc")
	wv, _, err := vault.CreateWithParams(webPath, password, tiny)
	if err != nil {
		t.Fatal(err)
	}
	webPayload := []byte(`{"schema":1,"hosts":[{"id":"1111111111111111","name":"web-a","addr":"a.example.com","port":22,"source":"manual"},{"id":"2222222222222222","name":"web-b","addr":"b.example.com","port":22,"source":"manual"}],"settings":{"theme":"abyss","agent":true,"keepalive":true,"telemetry":false}}`)
	if err := wv.Save(webPayload); err != nil {
		t.Fatal(err)
	}
	wv.Close()
	webBlob, err := os.ReadFile(webPath)
	if err != nil {
		t.Fatal(err)
	}

	// Register a throwaway account (the server never checks how authKey was
	// derived — it bcrypt-hashes whatever the client sends).
	var suffix [6]byte
	rand.Read(suffix[:])
	email := fmt.Sprintf("e2e-%x@example.com", suffix)
	authKey := randB64(t)
	regBody, _ := json.Marshal(map[string]string{
		"email":           email,
		"authKey":         authKey,
		"recoveryAuthKey": randB64(t),
		"vault":           base64.StdEncoding.EncodeToString(webBlob),
		"tokenMode":       "DIRECT",
	})
	var reg struct {
		Tokens struct {
			AccessToken string `json:"accessToken"`
		} `json:"tokens"`
	}
	postJSON(t, base+"/api/v1/auth/register", "", regBody, 201, &reg)

	// The "web app" issues a device code for the signed-in account.
	var dc struct {
		Code string `json:"code"`
	}
	postJSON(t, base+"/api/v1/device-codes", reg.Tokens.AccessToken, nil, 200, &dc)
	if len(dc.Code) != 8 {
		t.Fatalf("expected an 8-char device code, got %q", dc.Code)
	}

	// The TUI side: local vault (same password, own salts/DEK), 1 own host.
	localPath := filepath.Join(t.TempDir(), "vault.enc")
	lv, _, err := vault.CreateWithParams(localPath, password, tiny)
	if err != nil {
		t.Fatal(err)
	}
	defer lv.Close()
	localPayload := []byte(`{"schema":1,"hosts":[{"id":"3333333333333333","name":"tui-a","addr":"c.example.com","port":22,"source":"manual"}],"settings":{"theme":"abyss","agent":true,"keepalive":true,"telemetry":false}}`)
	if err := lv.Save(localPayload); err != nil {
		t.Fatal(err)
	}
	key, err := lv.DeriveKey(SessionKeyInfo)
	if err != nil {
		t.Fatal(err)
	}

	eng := New(Config{
		API:         api.New(base),
		SessionPath: SessionPath(localPath),
		Key:         key,
		Password:    append([]byte(nil), password...),
		DeviceName:  "e2e-test",
		ReadBlob:    func() ([]byte, error) { return os.ReadFile(localPath) },
		OpenBlob:    vault.OpenPayload,
	})
	defer eng.Close()

	// Pair with the dash display form; the code is one-time.
	gotEmail, err := eng.Pair(ctx, dc.Code[:4]+"-"+dc.Code[4:])
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if gotEmail != email {
		t.Fatalf("paired as %q, want %q", gotEmail, email)
	}
	if _, err := eng.Pair(ctx, dc.Code); err == nil {
		t.Fatal("a device code must be one-time")
	}
	// Re-pairing must not have clobbered the good session.
	if email2, ok := New(Config{
		API: api.New(base), SessionPath: SessionPath(localPath), Key: key,
		Password: password, ReadBlob: func() ([]byte, error) { return os.ReadFile(localPath) },
		OpenBlob: vault.OpenPayload,
	}).Resume(); !ok || email2 != email {
		t.Fatalf("session resume failed: %q %v", email2, ok)
	}

	// First sync: both sides have hosts → a real conflict.
	res := eng.Sync(ctx, lv.Payload())
	if res.Conflict == nil {
		t.Fatalf("expected a conflict on first sync, got %+v", res)
	}
	if res.Conflict.LocalHosts != 1 || res.Conflict.RemoteHosts != 2 {
		t.Fatalf("conflict counts wrong: %+v", res.Conflict)
	}

	// Take remote → adopt the web payload (password-unlock of a real blob).
	res = eng.Resolve(ctx, false, lv.Payload())
	if !bytes.Equal(res.Adopt, webPayload) {
		t.Fatalf("adopt mismatch: %+v", res)
	}
	if err := lv.Save(res.Adopt); err != nil {
		t.Fatal(err)
	}
	if err := eng.CommitAdopt(res.AdoptVersion, res.Adopt); err != nil {
		t.Fatal(err)
	}
	if res := eng.Sync(ctx, lv.Payload()); res.Err != nil || res.Pushed || res.Adopt != nil || res.Conflict != nil {
		t.Fatalf("should be converged after adopt, got %+v", res)
	}

	// Local edit → push; the remote version must advance.
	edited := bytes.Replace(lv.Payload(), []byte("web-a"), []byte("web-a-renamed"), 1)
	if err := lv.Save(edited); err != nil {
		t.Fatal(err)
	}
	res = eng.Sync(ctx, lv.Payload())
	if res.Err != nil || !res.Pushed {
		t.Fatalf("edit should push, got %+v", res)
	}

	// A second client (another device with the same password) can pull and
	// unlock what we pushed.
	c2 := api.New(base)
	c2.SetTokens(reg.Tokens.AccessToken, "")
	remote, err := c2.GetVault(ctx)
	if err != nil {
		t.Fatalf("second-device get: %v", err)
	}
	if remote.Version != res.Version {
		t.Fatalf("remote version %d, want %d", remote.Version, res.Version)
	}
	pulled, err := vault.OpenPayload(remote.Blob, password)
	if err != nil {
		t.Fatalf("second-device unlock: %v", err)
	}
	if !bytes.Contains(pulled, []byte("web-a-renamed")) {
		t.Fatal("pushed edit did not round-trip")
	}
}

func randB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func postJSON(t *testing.T, url, bearer string, body []byte, wantStatus int, out any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		var raw bytes.Buffer
		raw.ReadFrom(resp.Body)
		t.Fatalf("POST %s: status %d (want %d): %s", url, resp.StatusCode, wantStatus, raw.String())
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}
