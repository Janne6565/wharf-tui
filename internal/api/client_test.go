package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func problem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "detail": detail})
}

// problemCoded is problem() plus the stable machine-readable code the backend
// attaches to the errors clients must branch on.
func problemCoded(w http.ResponseWriter, status int, detail, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "detail": detail, "code": code})
}

func TestExchangeDeviceCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/device-codes/exchange" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct{ Code, DeviceName string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Code != "K7PQM2XR" {
			// The client must strip the display dash and upper-case.
			problem(w, 404, "unknown code "+body.Code)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"user":         map[string]string{"id": "u1", "email": "d@example.com"},
			"accessToken":  "acc1",
			"refreshToken": "ref1",
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	s, err := c.ExchangeDeviceCode(context.Background(), "k7pq-m2xr", "laptop")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if s.Email != "d@example.com" || s.UserID != "u1" || s.RefreshToken != "ref1" {
		t.Fatalf("unexpected session %+v", s)
	}
	if c.RefreshToken() != "ref1" {
		t.Fatal("client should adopt the refresh token")
	}
}

func TestExchangeInvalidCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem(w, 410, "Device code expired")
	}))
	defer srv.Close()

	_, err := New(srv.URL).ExchangeDeviceCode(context.Background(), "AAAAAAAA", "")
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 410 || ae.Detail != "Device code expired" {
		t.Fatalf("want *Error{410, detail}, got %v", err)
	}
}

func TestExchangeEmailNotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problemCoded(w, 403, "Verify your email address first", CodeEmailNotVerified)
	}))
	defer srv.Close()

	_, err := New(srv.URL).ExchangeDeviceCode(context.Background(), "K7PQM2XR", "")
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
	// Status and detail must survive alongside the code — the caller may still
	// want to render the backend's prose.
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != CodeEmailNotVerified {
		t.Fatalf("want *Error{403, code}, got %#v", ae)
	}
}

// A 403 that carries no code is just a 403: the sentinel must not swallow
// every forbidden response.
func TestPlainForbiddenIsNotEmailNotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem(w, 403, "Forbidden")
	}))
	defer srv.Close()

	_, err := New(srv.URL).ExchangeDeviceCode(context.Background(), "K7PQM2XR", "")
	if errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("a codeless 403 must not match the sentinel: %v", err)
	}
	var ae *Error
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "" {
		t.Fatalf("want *Error{403, no code}, got %#v", ae)
	}
}

// An unverified account is not an expired session: the refresh path must keep
// the distinction so the UI can tell the user what to actually do.
func TestRefreshEmailNotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/refresh":
			problemCoded(w, 403, "Verify your email address first", CodeEmailNotVerified)
		default:
			problem(w, 401, "expired token")
		}
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetTokens("acc", "ref")
	_, err := c.GetVault(context.Background())
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("want ErrEmailNotVerified, got %v", err)
	}
	if errors.Is(err, ErrSessionExpired) {
		t.Fatal("an unverified account must not be reported as an expired session")
	}
}

func TestRefreshRetryOn401(t *testing.T) {
	var refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/refresh":
			var body struct{ RefreshToken, TokenMode string }
			json.NewDecoder(r.Body).Decode(&body)
			if body.RefreshToken != "ref-old" || body.TokenMode != "DIRECT" {
				problem(w, 401, "bad refresh")
				return
			}
			refreshes.Add(1)
			json.NewEncoder(w).Encode(map[string]string{
				"accessToken": "acc-new", "refreshToken": "ref-new",
			})
		case "/api/v1/vault":
			if r.Header.Get("Authorization") != "Bearer acc-new" {
				problem(w, 401, "expired token")
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"vault":   base64.StdEncoding.EncodeToString([]byte("blob")),
				"version": 7,
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetTokens("acc-old", "ref-old")
	v, err := c.GetVault(context.Background())
	if err != nil {
		t.Fatalf("get vault after refresh-retry: %v", err)
	}
	if string(v.Blob) != "blob" || v.Version != 7 {
		t.Fatalf("unexpected vault %+v", v)
	}
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("want exactly one refresh, got %d", got)
	}
	if c.RefreshToken() != "ref-new" {
		t.Fatal("rotated refresh token should be adopted")
	}
}

func TestRefreshFailureIsSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem(w, 401, "nope")
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetTokens("acc", "ref")
	_, err := c.GetVault(context.Background())
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("want ErrSessionExpired, got %v", err)
	}
}

func TestGetVaultNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem(w, 404, "no vault")
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetTokens("acc", "ref")
	if _, err := c.GetVault(context.Background()); !errors.Is(err, ErrNoVault) {
		t.Fatalf("want ErrNoVault, got %v", err)
	}
}

func TestPutVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Vault           string `json:"vault"`
			ExpectedVersion int64  `json:"expectedVersion"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.ExpectedVersion != 3 {
			problem(w, 409, "Vault version conflict")
			return
		}
		if got, _ := base64.StdEncoding.DecodeString(body.Vault); string(got) != "blob" {
			t.Fatalf("unexpected blob %q", got)
		}
		json.NewEncoder(w).Encode(map[string]any{"version": 4})
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.SetTokens("acc", "ref")
	v, err := c.PutVault(context.Background(), []byte("blob"), 3)
	if err != nil || v != 4 {
		t.Fatalf("put: v=%d err=%v", v, err)
	}
	if _, err := c.PutVault(context.Background(), []byte("blob"), 2); !errors.Is(err, ErrVaultConflict) {
		t.Fatalf("stale version should be ErrVaultConflict, got %v", err)
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{
		"k7pq-m2xr": "K7PQM2XR",
		" K7PQM2XR": "K7PQM2XR",
		"K7PQ M2XR": "K7PQM2XR",
	} {
		if got := NormalizeCode(in); got != want {
			t.Fatalf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}
