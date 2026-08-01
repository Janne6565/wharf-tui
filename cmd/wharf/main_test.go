package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfirmsReset(t *testing.T) {
	for _, in := range []string{
		"I am sure\n", "i am sure", "  I AM   sure  \n", "I'm sure\n", "im sure", "I’m sure\n",
	} {
		if !confirmsReset(in) {
			t.Errorf("confirmsReset(%q) = false, want true", in)
		}
	}
	for _, in := range []string{
		"", "\n", "y\n", "yes", "sure", "I am not sure", "I am sure not", "iamsure", "reset",
	} {
		if confirmsReset(in) {
			t.Errorf("confirmsReset(%q) = true, want false", in)
		}
	}
}

// seedInstance writes a full set of reset targets into a temp dir and returns
// the vault path.
func seedInstance(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.enc")
	for _, p := range []string{vaultPath, filepath.Join(dir, "session.enc"), filepath.Join(dir, "vault.lock")} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blobs := filepath.Join(dir, "projects")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blobs, "p1.blob"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return vaultPath
}

func TestResetInstanceDeletesEverythingOnConfirm(t *testing.T) {
	vaultPath := seedInstance(t)
	var out strings.Builder

	if err := resetInstance(vaultPath, strings.NewReader("I am sure\n"), &out); err != nil {
		t.Fatalf("resetInstance: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(vaultPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("reset should empty the vault directory, still present: %v", entries)
	}
	for _, want := range []string{"Are you sure you want to reset your wharf instance?", "reset complete"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output should contain %q, got:\n%s", want, out.String())
		}
	}
}

func TestResetInstanceAbortsWithoutPhrase(t *testing.T) {
	vaultPath := seedInstance(t)
	var out strings.Builder

	if err := resetInstance(vaultPath, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatalf("an abort is not an error: %v", err)
	}

	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("aborting must leave the vault in place: %v", err)
	}
	if !strings.Contains(out.String(), "aborted") {
		t.Errorf("an abort should say so, got:\n%s", out.String())
	}
	if strings.Contains(out.String(), "removed") {
		t.Errorf("an abort must not report deletions, got:\n%s", out.String())
	}
}

func TestResetInstanceNothingToReset(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.enc")
	var out strings.Builder

	// No prompt at all: an empty reader would fail the read if one were shown.
	if err := resetInstance(vaultPath, strings.NewReader(""), &out); err != nil {
		t.Fatalf("resetInstance: %v", err)
	}
	if !strings.Contains(out.String(), "nothing to reset") {
		t.Errorf("expected a nothing-to-reset notice, got:\n%s", out.String())
	}
}

func TestResetTargetsCoverKnownArtifacts(t *testing.T) {
	// Built with filepath.Join rather than written as literals: resetTargets
	// joins too, so on Windows a literal "/data/wharf/projects" would differ
	// from the identical path only by separator.
	dir := filepath.Join("testdata", "wharf")
	got := resetTargets(filepath.Join(dir, "vault.enc"))
	want := []string{
		filepath.Join(dir, "projects"),
		filepath.Join(dir, "session.enc"),
		filepath.Join(dir, "vault.enc"),
		filepath.Join(dir, "vault.lock"),
	}
	if len(got) != len(want) {
		t.Fatalf("resetTargets() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("resetTargets()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestResolveVaultPathPrecedence(t *testing.T) {
	t.Setenv("WHARF_VAULT", "/from/env/vault.enc")

	got, err := resolveVaultPath("/from/flag/vault.enc")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/from/flag/vault.enc" {
		t.Errorf("--vault should win over $WHARF_VAULT, got %q", got)
	}

	got, err = resolveVaultPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/from/env/vault.enc" {
		t.Errorf("$WHARF_VAULT should apply with no flag, got %q", got)
	}

	t.Setenv("WHARF_VAULT", "  ")
	got, err = resolveVaultPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || strings.TrimSpace(got) != got {
		t.Errorf("a blank $WHARF_VAULT should fall through to the default, got %q", got)
	}
}

// The reset confirmation has to mention the background sessions it will close:
// they are separate processes holding live connections and the host spec —
// stored password included — that the reset promises to erase.
func TestResetWarnsAboutRunningSessions(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.enc")
	if err := os.WriteFile(vaultPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No sessions running: the line must not appear at all rather than saying
	// "0 background sessions".
	var out bytes.Buffer
	if err := resetInstance(vaultPath, strings.NewReader("no\n"), &out); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if strings.Contains(out.String(), "background session") {
		t.Fatalf("with nothing running the warning should be absent:\n%s", out.String())
	}
}

func TestPluralReadsNaturally(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{
		{1, "1 session"},
		{2, "2 sessions"},
		{0, "0 sessions"},
	} {
		if got := plural(tc.n, "session"); got != tc.want {
			t.Fatalf("plural(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
