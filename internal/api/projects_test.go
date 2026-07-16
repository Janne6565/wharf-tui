package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// authedClient builds a client against srv with tokens already installed, so
// project calls skip straight past the auth gate (mirrors the client_test setup).
func authedClient(url string) *Client {
	c := New(url)
	c.SetTokens("acc", "ref")
	return c
}

func TestCreateProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Vault       string `json:"vault"`
			WrappedDek  string `json:"wrappedDek"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Name != "secrets" || body.Description != "team creds" {
			t.Fatalf("unexpected name/desc %+v", body)
		}
		if got, _ := base64.StdEncoding.DecodeString(body.Vault); string(got) != "blob" {
			t.Fatalf("unexpected vault %q", got)
		}
		if got, _ := base64.StdEncoding.DecodeString(body.WrappedDek); string(got) != "wdek" {
			t.Fatalf("unexpected wrappedDek %q", got)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":           "p1",
			"name":         "secrets",
			"description":  "team creds",
			"role":         "OWNER",
			"createdAt":    "2026-07-16T10:00:00Z",
			"vaultVersion": 1,
			"members": []map[string]any{
				{"userId": "u1", "email": "me@example.com", "role": "OWNER", "keyed": true, "publicKey": base64.StdEncoding.EncodeToString([]byte("pubkey"))},
			},
			"invites": []map[string]any{},
		})
	}))
	defer srv.Close()

	d, err := authedClient(srv.URL).CreateProject(context.Background(), "secrets", "team creds", []byte("blob"), []byte("wdek"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.ID != "p1" || d.Role != "OWNER" || d.VaultVersion != 1 {
		t.Fatalf("unexpected detail %+v", d)
	}
	if len(d.Members) != 1 || d.Members[0].UserID != "u1" || string(d.Members[0].PublicKey) != "pubkey" {
		t.Fatalf("unexpected members %+v", d.Members)
	}
	if d.CreatedAt.IsZero() {
		t.Fatal("createdAt should be parsed")
	}
}

func TestCreateProjectNoPublicKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusPreconditionFailed, "no published public key")
	}))
	defer srv.Close()

	_, err := authedClient(srv.URL).CreateProject(context.Background(), "x", "", []byte("b"), []byte("d"))
	if !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("want ErrNoPublicKey, got %v", err)
	}
}

func TestGetProjectVaultWithWrappedDek(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/p1/vault" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"vault":      base64.StdEncoding.EncodeToString([]byte("cipher")),
			"version":    5,
			"updatedAt":  "2026-07-16T10:00:00Z",
			"wrappedDek": base64.StdEncoding.EncodeToString([]byte("mydek")),
		})
	}))
	defer srv.Close()

	v, err := authedClient(srv.URL).GetProjectVault(context.Background(), "p1")
	if err != nil {
		t.Fatalf("get vault: %v", err)
	}
	if string(v.Blob) != "cipher" || v.Version != 5 || string(v.WrappedDek) != "mydek" {
		t.Fatalf("unexpected vault resp %+v", v)
	}
}

func TestGetProjectVaultNullWrappedDek(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vault":      base64.StdEncoding.EncodeToString([]byte("cipher")),
			"version":    5,
			"updatedAt":  "2026-07-16T10:00:00Z",
			"wrappedDek": nil,
		})
	}))
	defer srv.Close()

	v, err := authedClient(srv.URL).GetProjectVault(context.Background(), "p1")
	if err != nil {
		t.Fatalf("get vault: %v", err)
	}
	if v.WrappedDek != nil {
		t.Fatalf("null wrappedDek should decode to nil, got %v", v.WrappedDek)
	}
}

func TestPutProjectVaultConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Vault           string `json:"vault"`
			ExpectedVersion int64  `json:"expectedVersion"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.ExpectedVersion != 3 {
			problem(w, http.StatusConflict, "Vault version conflict")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"version": 4, "updatedAt": "2026-07-16T10:00:00Z"})
	}))
	defer srv.Close()

	c := authedClient(srv.URL)
	ver, ts, err := c.PutProjectVault(context.Background(), "p1", []byte("blob"), 3)
	if err != nil || ver != 4 || ts.IsZero() {
		t.Fatalf("put: ver=%d ts=%v err=%v", ver, ts, err)
	}
	if _, _, err := c.PutProjectVault(context.Background(), "p1", []byte("blob"), 2); !errors.Is(err, ErrVaultConflict) {
		t.Fatalf("stale version should be ErrVaultConflict, got %v", err)
	}
}

func TestPublishPublicKey(t *testing.T) {
	var rotate bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/me/public-key" || r.Method != http.MethodPut {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			PublicKey string `json:"publicKey"`
			Rotate    bool   `json:"rotate"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if got, _ := base64.StdEncoding.DecodeString(body.PublicKey); string(got) != "pub" {
			t.Fatalf("unexpected publicKey %q", got)
		}
		if !body.Rotate && !rotate {
			problem(w, http.StatusConflict, "public key already set")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := authedClient(srv.URL)
	rotate = true
	if err := c.PublishPublicKey(context.Background(), []byte("pub"), true); err != nil {
		t.Fatalf("publish (rotate): %v", err)
	}
	rotate = false
	if err := c.PublishPublicKey(context.Background(), []byte("pub"), false); !errors.Is(err, ErrPublicKeyExists) {
		t.Fatalf("want ErrPublicKeyExists, got %v", err)
	}
}

func TestListMyInvites(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/me/invites" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":             "i1",
				"projectId":      "p1",
				"projectName":    "secrets",
				"invitedByEmail": "boss@example.com",
				"createdAt":      "2026-07-16T09:00:00Z",
				"expiresAt":      "2026-07-23T09:00:00Z",
			},
		})
	}))
	defer srv.Close()

	got, err := authedClient(srv.URL).ListMyInvites(context.Background())
	if err != nil {
		t.Fatalf("list invites: %v", err)
	}
	if len(got) != 1 || got[0].ID != "i1" || got[0].ProjectName != "secrets" || got[0].InvitedByEmail != "boss@example.com" {
		t.Fatalf("unexpected invites %+v", got)
	}
	if got[0].CreatedAt.IsZero() || got[0].ExpiresAt.IsZero() {
		t.Fatal("invite timestamps should be parsed")
	}
}

func TestSubmitMemberKeyConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/p1/members/u2/key" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			WrappedDek   string `json:"wrappedDek"`
			VaultVersion int64  `json:"vaultVersion"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if got, _ := base64.StdEncoding.DecodeString(body.WrappedDek); string(got) != "wk" {
			t.Fatalf("unexpected wrappedDek %q", got)
		}
		if body.VaultVersion != 5 {
			problem(w, http.StatusConflict, "stale vault version")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := authedClient(srv.URL)
	if err := c.SubmitMemberKey(context.Background(), "p1", "u2", []byte("wk"), 5); err != nil {
		t.Fatalf("submit key: %v", err)
	}
	if err := c.SubmitMemberKey(context.Background(), "p1", "u2", []byte("wk"), 4); !errors.Is(err, ErrVaultConflict) {
		t.Fatalf("stale version should be ErrVaultConflict, got %v", err)
	}
}
