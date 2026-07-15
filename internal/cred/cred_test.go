package cred

import (
	"encoding/base64"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	if got := NormalizeEmail("  Deniz@ACME.io "); got != "deniz@acme.io" {
		t.Fatalf("NormalizeEmail = %q, want %q", got, "deniz@acme.io")
	}
}

// TestKnownAnswerVectors pins the exact base64 outputs shared with wharf-web
// (src/crypto/keys.test.ts) and wharf-backend. These prove the Go argon2id +
// HKDF pipeline is byte-compatible with the web client that created the
// account's authKey hash — if any cost parameter, salt or info string drifts,
// a changed password would no longer authenticate against the server.
func TestKnownAnswerVectors(t *testing.T) {
	const (
		password      = "hunter2"
		email         = "  Deniz@ACME.io "
		wantMasterKey = "4whxiRmv/Go698JZxXM4WFdFVT68bs3LHUVkmL0+A8M="
		wantAuthKey   = "nnzMcXPLofscNtfrXSFz0S7zt0yd1mkTzy0Gw7JWXH8="
	)

	mk := MasterKey(password, email)
	if got := base64.StdEncoding.EncodeToString(mk); got != wantMasterKey {
		t.Errorf("MasterKey = %s, want %s", got, wantMasterKey)
	}

	authKey, err := AuthKey(password, email)
	if err != nil {
		t.Fatalf("AuthKey: %v", err)
	}
	if authKey != wantAuthKey {
		t.Errorf("AuthKey = %s, want %s", authKey, wantAuthKey)
	}
}

func TestAuthKeyCasingInsensitive(t *testing.T) {
	a, err := AuthKey("hunter2", "deniz@acme.io")
	if err != nil {
		t.Fatal(err)
	}
	b, err := AuthKey("hunter2", "  Deniz@ACME.io ")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("authKey differs by email casing: %s vs %s", a, b)
	}
}

func TestAuthKeyDiffersByPassword(t *testing.T) {
	a, _ := AuthKey("hunter2", "deniz@acme.io")
	b, _ := AuthKey("hunter3", "deniz@acme.io")
	if a == b {
		t.Fatal("authKey should differ for a different password")
	}
}
