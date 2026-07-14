package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testParams keep the argon2 cost tiny so the suite (which unlocks hundreds of
// times in the corruption sweep) stays fast.
var testParams = Params{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1}

func newVault(t *testing.T) (path string, code string, v *Vault) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "vault.enc")
	v, code, err := createWithParams(path, []byte("hunter2"), testParams)
	if err != nil {
		t.Fatalf("createWithParams: %v", err)
	}
	return path, code, v
}

func TestCreateSaveOpenRoundtrip(t *testing.T) {
	path, _, v := newVault(t)

	if len(v.Payload()) != 0 {
		t.Fatalf("fresh vault payload = %q, want empty", v.Payload())
	}

	want := []byte(`{"hosts":["a","b"]}`)
	if err := v.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v2, err := Open(path, []byte("hunter2"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()
	if !bytes.Equal(v2.Payload(), want) {
		t.Fatalf("reopened payload = %q, want %q", v2.Payload(), want)
	}
}

func TestWrongPassword(t *testing.T) {
	path, _, v := newVault(t)
	v.Close()

	_, err := Open(path, []byte("wrong"))
	if !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("Open with wrong password: err = %v, want ErrWrongSecret", err)
	}
}

func TestRecoveryFlow(t *testing.T) {
	path, code, v := newVault(t)
	if len(code) != recoveryCodeLen {
		t.Fatalf("recovery code length = %d, want %d", len(code), recoveryCodeLen)
	}
	if err := v.Save([]byte("payload")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	v.Close()

	// User-typed form: lower case, grouped with dashes and a stray space.
	messy := strings.ToLower(code[:5] + "-" + code[5:10] + " " + code[10:])
	rv, err := OpenWithRecovery(path, messy)
	if err != nil {
		t.Fatalf("OpenWithRecovery(messy): %v", err)
	}
	if !bytes.Equal(rv.Payload(), []byte("payload")) {
		t.Fatalf("recovery payload mismatch: %q", rv.Payload())
	}

	// Complete the reset: set a new password; recovery slot must survive.
	if err := rv.ChangePassword([]byte("newpass")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	rv.Close()

	nv, err := Open(path, []byte("newpass"))
	if err != nil {
		t.Fatalf("Open with new password: %v", err)
	}
	nv.Close()

	if _, err := Open(path, []byte("hunter2")); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("old password still works: err = %v", err)
	}

	rv2, err := OpenWithRecovery(path, code)
	if err != nil {
		t.Fatalf("recovery code invalid after ChangePassword: %v", err)
	}
	rv2.Close()
}

func TestRegenerateRecovery(t *testing.T) {
	path, oldCode, v := newVault(t)

	newCode, err := v.RegenerateRecovery()
	if err != nil {
		t.Fatalf("RegenerateRecovery: %v", err)
	}
	if newCode == oldCode {
		t.Fatal("regenerated code equals old code")
	}
	v.Close()

	nv, err := OpenWithRecovery(path, newCode)
	if err != nil {
		t.Fatalf("OpenWithRecovery(new): %v", err)
	}
	nv.Close()

	if _, err := OpenWithRecovery(path, oldCode); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("old recovery code still works: err = %v", err)
	}
}

func TestCorruptionSweep(t *testing.T) {
	path, _, v := newVault(t)
	if err := v.Save([]byte(`{"k":"v"}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	v.Close()

	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	for i := range orig {
		mutated := append([]byte(nil), orig...)
		mutated[i] ^= 0xFF
		if err := os.WriteFile(path, mutated, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		vv, err := Open(path, []byte("hunter2"))
		if err == nil {
			vv.Close()
			t.Fatalf("flipping byte %d let Open succeed", i)
		}
		if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("flipping byte %d: err = %v, want ErrCorrupt or ErrWrongSecret", i, err)
		}
	}

	// Truncation and bad magic are corruption.
	if err := os.WriteFile(path, orig[:headerLen-1], 0600); err != nil {
		t.Fatalf("WriteFile truncated: %v", err)
	}
	if _, err := Open(path, []byte("hunter2")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated file: err = %v, want ErrCorrupt", err)
	}

	badMagic := append([]byte(nil), orig...)
	copy(badMagic[0:6], []byte("XXXXXX"))
	if err := os.WriteFile(path, badMagic, 0600); err != nil {
		t.Fatalf("WriteFile bad magic: %v", err)
	}
	if _, err := Open(path, []byte("hunter2")); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad magic: err = %v, want ErrCorrupt", err)
	}

	// Missing file is not-found, not corruption.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Open(path, []byte("hunter2")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file: err = %v, want ErrNotFound", err)
	}
}

func TestSaveAtomicityNoTmpLeft(t *testing.T) {
	path, _, v := newVault(t)
	defer v.Close()

	for i := 0; i < 20; i++ {
		if err := v.Save([]byte{byte(i)}); err != nil {
			t.Fatalf("Save %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

func TestLockExclusive(t *testing.T) {
	path, _, v := newVault(t)

	if _, err := Open(path, []byte("hunter2")); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open while held: err = %v, want ErrLocked", err)
	}

	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	v2, err := Open(path, []byte("hunter2"))
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	v2.Close()
}

func TestGoldenHeader(t *testing.T) {
	path, _, v := newVault(t)
	v.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(raw) < headerLen {
		t.Fatalf("file too short: %d bytes", len(raw))
	}
	if got := string(raw[0:6]); got != "WHARFV" {
		t.Fatalf("magic = %q, want WHARFV", got)
	}
	if got := binary.LittleEndian.Uint16(raw[6:8]); got != 1 {
		t.Fatalf("version = %d, want 1", got)
	}
	if raw[8] != 1 {
		t.Fatalf("kdf id = %d, want 1", raw[8])
	}
	if got := binary.LittleEndian.Uint32(raw[9:13]); got != testParams.Time {
		t.Fatalf("argon2 time = %d, want %d", got, testParams.Time)
	}
	if got := binary.LittleEndian.Uint32(raw[13:17]); got != testParams.MemoryKiB {
		t.Fatalf("argon2 memory = %d, want %d", got, testParams.MemoryKiB)
	}
	if got := raw[17]; got != testParams.Parallelism {
		t.Fatalf("argon2 parallelism = %d, want %d", got, testParams.Parallelism)
	}
	if headerLen != 218 {
		t.Fatalf("headerLen = %d, want 218", headerLen)
	}
}
