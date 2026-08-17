package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/termius"
	tea "github.com/charmbracelet/bubbletea"
)

// 'm' used to import ~/.ssh/config straight off the keypress. It now opens a
// chooser, because picking Termius by accident is expensive: it prompts the OS
// credential store.
func TestImportKeyOpensSourceChooser(t *testing.T) {
	tm, _ := openedModel(t)
	tm = typeStr(tm, "m")

	view := tm.View()
	if !strings.Contains(view, "import hosts") {
		t.Fatalf("expected the import chooser, got:\n%s", view)
	}
	for _, want := range []string{"ssh config", "Termius"} {
		if !strings.Contains(view, want) {
			t.Errorf("chooser is missing %q:\n%s", want, view)
		}
	}
}

func TestImportChooserCancels(t *testing.T) {
	tm, _ := openedModel(t)
	tm = typeStr(tm, "m")
	tm, _ = step(tm, special(tea.KeyEsc))

	// Asserted on chooser-only body text: the footer hint for 'm' also reads
	// "import hosts", so the title alone cannot tell open from closed.
	if strings.Contains(tm.View(), "local profile, read-only") {
		t.Error("esc should close the import chooser")
	}
}

// A Termius summary must say that passwords came along: they land in the
// encrypted vault either way, but importing credentials silently would be the
// wrong default.
func TestTermiusSummaryReportsPasswords(t *testing.T) {
	tm, _ := openedModel(t)
	tm, _ = step(tm, importDoneMsg{
		hosts: []store.Host{
			{Name: "web", User: "deploy", Addr: "10.0.0.5", Port: 22, Source: termius.Source},
		},
		source: termius.Source,
		note:   "1 with a saved password",
	})

	view := tm.View()
	if !strings.Contains(view, "Termius profile") {
		t.Errorf("summary should name the source:\n%s", view)
	}
	if !strings.Contains(view, "saved password") {
		t.Errorf("summary should mention imported passwords:\n%s", view)
	}
}

// A Termius failure carries multi-line guidance (profiles searched, keyring
// entries tried), so it goes to the error modal instead of a truncating toast.
func TestTermiusImportErrorUsesErrorModal(t *testing.T) {
	tm, _ := openedModel(t)
	tm, _ = step(tm, importDoneMsg{
		source: termius.Source,
		err:    termius.ErrNoLocalKey{Detail: "no Termius localKey in the darwin credential store"},
	})

	view := tm.View()
	if !strings.Contains(view, "termius import failed") {
		t.Errorf("expected the error modal:\n%s", view)
	}
	if !strings.Contains(view, "localKey") {
		t.Errorf("error detail should survive to the modal:\n%s", view)
	}
}

// Imported Termius passwords must actually reach the store; the ssh_config
// path deliberately drops secrets, so the apply step has to pick the right one.
func TestTermiusApplyKeepsPasswords(t *testing.T) {
	tm, _ := openedModel(t)
	tm, _ = step(tm, importDoneMsg{
		hosts: []store.Host{{
			Name: "db", User: "root", Addr: "10.0.0.9", Port: 22,
			AuthMethod: "password", Password: "s3cret", Source: termius.Source,
		}},
		source: termius.Source,
	})
	tm = drainCmd(t, tm, applyImport(t, tm))

	hosts := tm.(Model).st.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].Password != "s3cret" {
		t.Errorf("imported password was dropped: %+v", hosts[0])
	}
	if hosts[0].Source != termius.Source {
		t.Errorf("source = %q, want %q", hosts[0].Source, termius.Source)
	}
}

// applyImport confirms the summary modal and returns the resulting command.
func applyImport(t *testing.T, tm tea.Model) tea.Cmd {
	t.Helper()
	next, cmd := step(tm, special(tea.KeyEnter))
	if _, ok := next.(Model); !ok {
		t.Fatal("apply did not return a Model")
	}
	return cmd
}

// Keys imported from Termius must reach the vault, and a re-import must not
// keep adding renamed copies of keys that are already there.
func TestTermiusApplyImportsKeys(t *testing.T) {
	tm, _ := openedModel(t)
	msg := importDoneMsg{
		hosts:  []store.Host{{Name: "h", User: "u", Addr: "a", Port: 22, Source: termius.Source}},
		keys:   []store.VaultKey{{Name: "work", Type: "RSA", Material: "bWF0ZXJpYWw="}},
		source: termius.Source,
	}

	tm, _ = step(tm, msg)
	tm = drainCmd(t, tm, applyImport(t, tm))
	if got := len(tm.(Model).st.Keys()); got != 1 {
		t.Fatalf("after first import: %d keys, want 1", got)
	}

	tm, _ = step(tm, msg)
	tm = drainCmd(t, tm, applyImport(t, tm))
	if got := len(tm.(Model).st.Keys()); got != 1 {
		t.Errorf("re-import added a duplicate: %d keys, want 1", got)
	}
}
