package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/proxydial"
	tea "github.com/charmbracelet/bubbletea"
)

// proxyModel returns an unlocked real-mode model with the proxy hooks wired to
// a recorder, parked on the settings tab with the proxy row selected. The
// returned pointer receives whatever the UI asks to persist.
func proxyModel(t *testing.T, start string, applyErr error) (tea.Model, *[]string) {
	t.Helper()
	saved := &[]string{}

	tm, _ := openedModel(t)
	mm := tm.(Model)
	mm.proxySetting = start
	mm.proxyDialer = proxydial.Direct()
	mm.applyProxy = func(setting string) (*proxydial.Dialer, error) {
		*saved = append(*saved, setting)
		if applyErr != nil {
			return nil, applyErr
		}
		// The real hook resolves against the flag and environment; here the
		// stored value is the only input, which is the case under test.
		return proxydial.New(setting)
	}
	tm = mm

	tm = send(tm, runes("4")) // settings tab
	tm = selectSettingRow(t, tm, "proxy")
	return tm, saved
}

// selectSettingRow moves the settings cursor onto the named row.
func selectSettingRow(t *testing.T, tm tea.Model, key string) tea.Model {
	t.Helper()
	for i := 0; i < 12; i++ {
		mm := tm.(Model)
		if mm.settingRows()[mm.settingIdx()].key == key {
			return tm
		}
		tm = send(tm, runes("j"))
	}
	t.Fatalf("never reached the %q settings row", key)
	return tm
}

func TestProxyRowOpensEditor(t *testing.T) {
	tm, _ := proxyModel(t, "", nil)
	if v := tm.View(); !strings.Contains(v, "Egress proxy") {
		t.Fatalf("settings should list the proxy row:\n%s", v)
	}
	tm = send(tm, special(tea.KeyEnter))
	v := tm.View()
	if !strings.Contains(v, "egress proxy") {
		t.Fatalf("enter should open the proxy editor:\n%s", v)
	}
	// The two facts people get wrong have to be on screen, not in a man page.
	if !strings.Contains(v, "never synced") {
		t.Fatalf("editor should say the setting is machine-local:\n%s", v)
	}
	if !strings.Contains(v, "not stored") {
		t.Fatalf("editor should say a password in the URL is not stored:\n%s", v)
	}
}

func TestProxySaveApplies(t *testing.T) {
	tm, saved := proxyModel(t, "", nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = typeStr(tm, "socks5://proxy.corp:1080")
	tm, _ = step(tm, special(tea.KeyEnter))

	if len(*saved) != 1 || (*saved)[0] != "socks5://proxy.corp:1080" {
		t.Fatalf("persisted %v, want the typed proxy once", *saved)
	}
	mm := tm.(Model)
	if mm.modal != modalNone {
		t.Fatalf("a successful save should close the editor, modal = %v", mm.modal)
	}
	v := tm.View()
	if !strings.Contains(v, "socks5://proxy.corp:1080") {
		t.Fatalf("settings row should show the new proxy:\n%s", v)
	}
}

func TestProxyInvalidValueStaysInEditor(t *testing.T) {
	tm, saved := proxyModel(t, "", nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = typeStr(tm, "ftp://nope:21")
	tm, _ = step(tm, special(tea.KeyEnter))

	if len(*saved) != 0 {
		t.Fatalf("an invalid proxy must not be persisted, got %v", *saved)
	}
	mm := tm.(Model)
	if mm.modal != modalProxy {
		t.Fatalf("editor should stay open on a bad value, modal = %v", mm.modal)
	}
	if !strings.Contains(tm.View(), "unsupported proxy scheme") {
		t.Fatalf("the error should be shown in the editor:\n%s", tm.View())
	}
}

// Writing the file can fail (read-only home, full disk). The edit must not be
// reported as applied when it was not.
func TestProxySaveErrorStaysInEditor(t *testing.T) {
	tm, _ := proxyModel(t, "", errors.New("permission denied"))
	tm = send(tm, special(tea.KeyEnter))
	tm = typeStr(tm, "socks5://proxy.corp:1080")
	tm, _ = step(tm, special(tea.KeyEnter))

	mm := tm.(Model)
	if mm.modal != modalProxy {
		t.Fatalf("editor should stay open when persisting fails, modal = %v", mm.modal)
	}
	if !strings.Contains(tm.View(), "permission denied") {
		t.Fatalf("the failure should be shown:\n%s", tm.View())
	}
}

// "off" is how someone with an ambient $ALL_PROXY tells wharf to ignore it, so
// it has to survive validation rather than being rejected as a malformed URL.
func TestProxyOffIsAccepted(t *testing.T) {
	tm, saved := proxyModel(t, "socks5://proxy.corp:1080", nil)
	tm = send(tm, special(tea.KeyEnter))
	// Clear the seeded value first.
	for i := 0; i < len("socks5://proxy.corp:1080"); i++ {
		tm = send(tm, special(tea.KeyBackspace))
	}
	tm = typeStr(tm, "off")
	tm, _ = step(tm, special(tea.KeyEnter))

	if len(*saved) != 1 || (*saved)[0] != "off" {
		t.Fatalf("persisted %v, want [off]", *saved)
	}
	if v := tm.View(); !strings.Contains(v, "direct") {
		t.Fatalf("the row should read direct after switching the proxy off:\n%s", v)
	}
}

// The editor edits the stored value, not the effective one: seeding it with an
// inherited $ALL_PROXY would let someone accidentally persist an ambient value
// they never chose for wharf.
func TestProxyEditorSeedsStoredValue(t *testing.T) {
	tm, _ := proxyModel(t, "socks5://stored:1080", nil)
	mm := tm.(Model)
	amb, err := proxydial.New("socks5://ambient:1080")
	if err != nil {
		t.Fatal(err)
	}
	mm.proxyDialer = amb
	tm = mm

	tm = send(tm, special(tea.KeyEnter))
	v := tm.View()
	if !strings.Contains(v, "socks5://stored:1080") {
		t.Fatalf("editor should be seeded with the stored value:\n%s", v)
	}
}

// A demo model has no hook; enter must say so instead of opening an editor
// whose save would silently do nothing.
func TestProxyRowInDemoIsRefused(t *testing.T) {
	var tm tea.Model = New(Config{Demo: true})
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = send(tm, runes("l")) // skip the demo login → dashboard
	tm = send(tm, runes("4"))
	tm = selectSettingRow(t, tm, "proxy")
	tm, _ = step(tm, special(tea.KeyEnter))

	if mm := tm.(Model); mm.modal == modalProxy {
		t.Fatal("demo mode should not open the proxy editor")
	}
	if !strings.Contains(tm.View(), "needs a real vault") {
		t.Fatalf("demo mode should explain why the row is inert:\n%s", tm.View())
	}
}
