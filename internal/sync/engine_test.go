package sync

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	stdsync "sync"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/vault"
)

// fakeAPI is an in-memory backend: one vault slot with optimistic versioning.
type fakeAPI struct {
	mu      stdsync.Mutex
	refresh string

	vault   []byte
	version int64
	noVault bool

	getErr error // forced error on GetVault
	puts   int
}

func (f *fakeAPI) ExchangeDeviceCode(_ context.Context, code, _ string) (api.Session, error) {
	if api.NormalizeCode(code) != "K7PQM2XR" {
		return api.Session{}, &api.Error{Status: 404, Detail: "unknown code"}
	}
	return api.Session{UserID: "u1", Email: "d@example.com", AccessToken: "acc", RefreshToken: "ref1"}, nil
}

func (f *fakeAPI) GetVault(context.Context) (api.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return api.Vault{}, f.getErr
	}
	if f.noVault {
		return api.Vault{}, api.ErrNoVault
	}
	return api.Vault{Blob: append([]byte(nil), f.vault...), Version: f.version}, nil
}

func (f *fakeAPI) PutVault(_ context.Context, blob []byte, expectedVersion int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	if !f.noVault && expectedVersion != f.version {
		return 0, api.ErrVaultConflict
	}
	f.noVault = false
	f.vault = append([]byte(nil), blob...)
	f.version++
	return f.version, nil
}

func (f *fakeAPI) SetTokens(_, refresh string) {
	f.mu.Lock()
	f.refresh = refresh
	f.mu.Unlock()
}

func (f *fakeAPI) RefreshToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refresh == "" {
		return "ref1"
	}
	return f.refresh
}

// wrap/unwrap fake the WHARFV blob: a prefix plus the payload, "unlockable"
// only with the right password.
const blobPrefix = "BLOB:"

func wrap(payload []byte) []byte { return append([]byte(blobPrefix), payload...) }

func fakeOpenBlob(blob, password []byte) ([]byte, error) {
	if string(password) != "pw" {
		return nil, vault.ErrWrongSecret
	}
	if !bytes.HasPrefix(blob, []byte(blobPrefix)) {
		return nil, vault.ErrCorrupt
	}
	return blob[len(blobPrefix):], nil
}

// payloadN builds a store-shaped payload with n hosts.
func payloadN(n int, marker string) []byte {
	var hosts []byte
	for i := 0; i < n; i++ {
		if i > 0 {
			hosts = append(hosts, ',')
		}
		hosts = append(hosts, []byte(`{"id":"`+marker+string(rune('a'+i))+`"}`)...)
	}
	return []byte(`{"schema":1,"hosts":[` + string(hosts) + `],"settings":{"theme":"abyss"}}`)
}

// testEngine builds a paired engine over fakeAPI. local points at the
// mutable "current local payload" the ReadBlob hook wraps.
func testEngine(t *testing.T, f *fakeAPI, local *[]byte) *Engine {
	t.Helper()
	e := New(Config{
		API:         f,
		SessionPath: filepath.Join(t.TempDir(), "session.enc"),
		Key:         make([]byte, 32),
		Password:    []byte("pw"),
		DeviceName:  "test",
		ReadBlob:    func() ([]byte, error) { return wrap(*local), nil },
		OpenBlob:    fakeOpenBlob,
	})
	if _, err := e.Pair(context.Background(), "K7PQ-M2XR"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	return e
}

func TestPairPersistsAndResumes(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(0, "l")
	e := testEngine(t, f, &local)
	if !e.SignedIn() || e.Email() != "d@example.com" {
		t.Fatal("pair should sign the engine in")
	}
	// Fresh engine over the same session file resumes.
	e2 := New(Config{
		API: f, SessionPath: e.cfg.SessionPath, Key: make([]byte, 32),
		Password: []byte("pw"),
		ReadBlob: func() ([]byte, error) { return wrap(local), nil },
		OpenBlob: fakeOpenBlob,
	})
	if email, ok := e2.Resume(); !ok || email != "d@example.com" {
		t.Fatalf("resume failed: %v %v", email, ok)
	}
	// A wrong key (vault re-created) means signed out, file gone.
	e3 := New(Config{
		API: f, SessionPath: e.cfg.SessionPath, Key: bytes.Repeat([]byte{1}, 32),
		Password: []byte("pw"),
		ReadBlob: func() ([]byte, error) { return wrap(local), nil },
		OpenBlob: fakeOpenBlob,
	})
	if _, ok := e3.Resume(); ok {
		t.Fatal("resume with the wrong key must fail")
	}
	if _, err := os.Stat(e.cfg.SessionPath); !os.IsNotExist(err) {
		t.Fatal("an unreadable session file should be deleted")
	}
}

func TestPairInvalidCode(t *testing.T) {
	f := &fakeAPI{noVault: true}
	e := New(Config{
		API: f, SessionPath: filepath.Join(t.TempDir(), "session.enc"),
		Key: make([]byte, 32), Password: []byte("pw"),
		ReadBlob: func() ([]byte, error) { return nil, nil }, OpenBlob: fakeOpenBlob,
	})
	if _, err := e.Pair(context.Background(), "WRONG123"); err == nil {
		t.Fatal("bad code should fail")
	}
	if e.SignedIn() {
		t.Fatal("failed pair must not sign in")
	}
}

func TestFirstSyncPushesLocal(t *testing.T) {
	// Remote has no vault; local has hosts → push.
	f := &fakeAPI{noVault: true}
	local := payloadN(2, "l")
	e := testEngine(t, f, &local)

	res := e.Sync(context.Background(), local)
	if res.Err != nil || !res.Pushed || res.Version != 1 {
		t.Fatalf("want push to v1, got %+v", res)
	}
	if !bytes.Equal(f.vault, wrap(local)) {
		t.Fatal("remote should hold the local blob")
	}
	// Second pass: nothing to do.
	res = e.Sync(context.Background(), local)
	if res.Err != nil || res.Pushed || res.Adopt != nil || res.Conflict != nil {
		t.Fatalf("second pass should be a no-op, got %+v", res)
	}
}

func TestFirstSyncEmptyLocalAdoptsRemote(t *testing.T) {
	remote := payloadN(3, "r")
	f := &fakeAPI{vault: wrap(remote), version: 5}
	local := payloadN(0, "l")
	e := testEngine(t, f, &local)

	res := e.Sync(context.Background(), local)
	if res.Conflict != nil {
		t.Fatal("empty local side must auto-pick remote, not prompt")
	}
	if !bytes.Equal(res.Adopt, remote) || res.AdoptVersion != 5 {
		t.Fatalf("want adopt of remote v5, got %+v", res)
	}
	// The UI writes the payload, then confirms.
	local = res.Adopt
	if err := e.CommitAdopt(res.AdoptVersion, res.Adopt); err != nil {
		t.Fatalf("commit adopt: %v", err)
	}
	res = e.Sync(context.Background(), local)
	if res.Err != nil || res.Pushed || res.Adopt != nil {
		t.Fatalf("after adopt everything is in sync, got %+v", res)
	}
}

func TestPullFastForward(t *testing.T) {
	// In-sync baseline, then the remote moves and local stays put.
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	if res := e.Sync(context.Background(), local); !res.Pushed {
		t.Fatalf("baseline push failed: %+v", res)
	}

	remote := payloadN(4, "r")
	f.mu.Lock()
	f.vault, f.version = wrap(remote), f.version+1
	want := f.version
	f.mu.Unlock()

	res := e.Sync(context.Background(), local)
	if res.Conflict != nil || !bytes.Equal(res.Adopt, remote) || res.AdoptVersion != want {
		t.Fatalf("unchanged local + newer remote must fast-forward, got %+v", res)
	}
}

func TestPushLocalChanges(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	e.Sync(context.Background(), local)

	local = payloadN(2, "l")
	res := e.Sync(context.Background(), local)
	if !res.Pushed || res.Version != 2 {
		t.Fatalf("changed local + unmoved remote must push, got %+v", res)
	}
	if !bytes.Equal(f.vault, wrap(local)) {
		t.Fatal("remote should hold the new blob")
	}
}

func TestPush409ThenPullConvergesWhenEqual(t *testing.T) {
	// Local changed AND the remote moved to the very same content (another
	// device pushed the same edit): the 409 path re-evaluates and converges
	// with no conflict and no second put.
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	e.Sync(context.Background(), local)

	local = payloadN(2, "x")
	f.mu.Lock()
	f.vault, f.version = wrap(local), f.version+1 // remote already has it
	f.mu.Unlock()

	res := e.Sync(context.Background(), local)
	if res.Err != nil || res.Conflict != nil || res.Adopt != nil {
		t.Fatalf("identical content must converge silently, got %+v", res)
	}
	// And we are recorded at the remote version.
	res = e.Sync(context.Background(), local)
	if res.Pushed || res.Conflict != nil {
		t.Fatalf("bookkeeping should now match, got %+v", res)
	}
}

func TestConflictBothChanged(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	e.Sync(context.Background(), local)

	local = payloadN(2, "l")
	remote := payloadN(3, "r")
	f.mu.Lock()
	f.vault, f.version = wrap(remote), f.version+1
	rv := f.version
	f.mu.Unlock()

	res := e.Sync(context.Background(), local)
	if res.Conflict == nil {
		t.Fatalf("both changed with hosts on both sides must conflict, got %+v", res)
	}
	if res.Conflict.LocalHosts != 2 || res.Conflict.RemoteHosts != 3 || res.Conflict.RemoteVersion != rv {
		t.Fatalf("conflict info wrong: %+v", res.Conflict)
	}

	// keep local → push wins.
	res = e.Resolve(context.Background(), true, local)
	if !res.Pushed {
		t.Fatalf("keep-local should push, got %+v", res)
	}
	if !bytes.Equal(f.vault, wrap(local)) {
		t.Fatal("remote should now hold the local blob")
	}
}

func TestConflictTakeRemote(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	e.Sync(context.Background(), local)

	local = payloadN(2, "l")
	remote := payloadN(3, "r")
	f.mu.Lock()
	f.vault, f.version = wrap(remote), f.version+1
	rv := f.version
	f.mu.Unlock()

	if res := e.Sync(context.Background(), local); res.Conflict == nil {
		t.Fatalf("expected conflict, got %+v", res)
	}
	res := e.Resolve(context.Background(), false, local)
	if !bytes.Equal(res.Adopt, remote) || res.AdoptVersion != rv {
		t.Fatalf("take-remote should adopt the stashed remote, got %+v", res)
	}
	local = res.Adopt
	if err := e.CommitAdopt(res.AdoptVersion, res.Adopt); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if res := e.Sync(context.Background(), local); res.Pushed || res.Conflict != nil || res.Adopt != nil {
		t.Fatalf("converged after take-remote, got %+v", res)
	}
}

func TestEmptyRemoteAutoPushes(t *testing.T) {
	// Both changed but the remote has zero hosts → local wins silently.
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	e.Sync(context.Background(), local)

	local = payloadN(2, "l")
	f.mu.Lock()
	f.vault, f.version = wrap(payloadN(0, "r")), f.version+1
	f.mu.Unlock()

	res := e.Sync(context.Background(), local)
	if res.Conflict != nil || !res.Pushed {
		t.Fatalf("empty remote side must auto-push, got %+v", res)
	}
}

func TestOfflineError(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	f.mu.Lock()
	f.getErr = errors.New("connection refused")
	f.mu.Unlock()

	res := e.Sync(context.Background(), local)
	if res.Err == nil || res.SessionDead {
		t.Fatalf("network failure should be a transient error, got %+v", res)
	}
	if !e.SignedIn() {
		t.Fatal("a transient failure must not sign out")
	}
}

func TestSessionDeadSignsOut(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	f.mu.Lock()
	f.getErr = api.ErrSessionExpired
	f.mu.Unlock()

	res := e.Sync(context.Background(), local)
	if !res.SessionDead {
		t.Fatalf("expired refresh must report SessionDead, got %+v", res)
	}
	if e.SignedIn() {
		t.Fatal("dead session should sign the engine out")
	}
	if _, err := os.Stat(e.cfg.SessionPath); !os.IsNotExist(err) {
		t.Fatal("dead session file should be deleted")
	}
}

func TestWrongRemotePasswordSurfaces(t *testing.T) {
	f := &fakeAPI{vault: wrap(payloadN(2, "r")), version: 3}
	local := payloadN(0, "l")
	e := New(Config{
		API: f, SessionPath: filepath.Join(t.TempDir(), "session.enc"),
		Key: make([]byte, 32), Password: []byte("other"),
		ReadBlob: func() ([]byte, error) { return wrap(local), nil },
		OpenBlob: fakeOpenBlob,
	})
	if _, err := e.Pair(context.Background(), "K7PQM2XR"); err != nil {
		t.Fatalf("pair: %v", err)
	}
	res := e.Sync(context.Background(), local)
	if !errors.Is(res.Err, vault.ErrWrongSecret) {
		t.Fatalf("mismatched master password must surface ErrWrongSecret, got %+v", res)
	}
}

func TestSignOutDeletesSessionKeepsWorking(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(1, "l")
	e := testEngine(t, f, &local)
	e.SignOut()
	if e.SignedIn() {
		t.Fatal("sign-out should clear the session")
	}
	if _, err := os.Stat(e.cfg.SessionPath); !os.IsNotExist(err) {
		t.Fatal("sign-out should delete the session file")
	}
	if res := e.Sync(context.Background(), local); !res.SignedOut {
		t.Fatalf("sync while signed out is a no-op, got %+v", res)
	}
}

// TestVaultInterop proves a pull against a REAL remote WHARFV blob: a vault
// created independently (its own random salts, its own DEK) is unlocked with
// the master password via vault.OpenPayload and adopted.
func TestVaultInterop(t *testing.T) {
	tiny := vault.Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}
	password := []byte("hunter2")

	// The "web-created" remote vault, holding 2 hosts.
	remotePath := filepath.Join(t.TempDir(), "remote.enc")
	rv, _, err := vault.CreateWithParams(remotePath, password, tiny)
	if err != nil {
		t.Fatalf("create remote vault: %v", err)
	}
	remotePayload := payloadN(2, "r")
	if err := rv.Save(remotePayload); err != nil {
		t.Fatalf("save remote payload: %v", err)
	}
	rv.Close()
	remoteBlob, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatal(err)
	}

	// The local vault: same password, different salts and DEK, empty payload.
	localPath := filepath.Join(t.TempDir(), "vault.enc")
	lv, _, err := vault.CreateWithParams(localPath, password, tiny)
	if err != nil {
		t.Fatalf("create local vault: %v", err)
	}
	defer lv.Close()
	key, err := lv.DeriveKey(SessionKeyInfo)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeAPI{vault: remoteBlob, version: 9}
	e := New(Config{
		API:         f,
		SessionPath: SessionPath(localPath),
		Key:         key,
		Password:    append([]byte(nil), password...),
		ReadBlob:    func() ([]byte, error) { return os.ReadFile(localPath) },
		OpenBlob:    vault.OpenPayload,
	})
	if _, err := e.Pair(context.Background(), "K7PQM2XR"); err != nil {
		t.Fatalf("pair: %v", err)
	}

	res := e.Sync(context.Background(), lv.Payload())
	if res.Err != nil || res.Conflict != nil {
		t.Fatalf("interop sync failed: %+v", res)
	}
	if !bytes.Equal(res.Adopt, remotePayload) || res.AdoptVersion != 9 {
		t.Fatalf("remote payload not adopted: %+v", res)
	}
	// Complete the pull through the real local vault (re-encrypt under the
	// local DEK) and verify convergence.
	if err := lv.Save(res.Adopt); err != nil {
		t.Fatalf("adopt save: %v", err)
	}
	if err := e.CommitAdopt(res.AdoptVersion, res.Adopt); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if res := e.Sync(context.Background(), lv.Payload()); res.Pushed || res.Adopt != nil || res.Conflict != nil || res.Err != nil {
		t.Fatalf("interop should converge, got %+v", res)
	}
}

func TestSessionFileMode(t *testing.T) {
	f := &fakeAPI{noVault: true}
	local := payloadN(0, "l")
	e := testEngine(t, f, &local)
	fi, err := os.Stat(e.cfg.SessionPath)
	if err != nil {
		t.Fatalf("session file missing: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("session file mode = %v, want 0600", fi.Mode().Perm())
	}
	// And it is not plaintext: the refresh token must not appear.
	raw, _ := os.ReadFile(e.cfg.SessionPath)
	if bytes.Contains(raw, []byte("ref1")) || bytes.Contains(raw, []byte("d@example.com")) {
		t.Fatal("session file must be encrypted")
	}
}
