package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/localcfg"
	"github.com/Janne6565/wharf-tui/internal/proxydial"
	tea "github.com/charmbracelet/bubbletea"
)

// openProxyForm prepares the egress-proxy editor, seeded with the stored
// setting rather than the effective one: editing is what this machine saves,
// and a value inherited from $ALL_PROXY is not something the user typed here.
func (m Model) openProxyForm() Model {
	m.modal = modalProxy
	m.pxVal = m.proxySetting
	m.pxErr = ""
	return m
}

// proxyKey drives the proxy editor. Enter validates, persists and applies;
// the value takes effect for connections opened from now on.
func (m Model) proxyKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.modal = modalNone
		m.pxErr = ""
		return m, nil
	case "enter":
		return m.saveProxy()
	case "backspace":
		if len(m.pxVal) > 0 {
			m.pxVal = m.pxVal[:len(m.pxVal)-1]
		}
		m.pxErr = ""
		return m, nil
	default:
		if isPrintable(key) {
			m.pxVal += key
			m.pxErr = ""
		}
		return m, nil
	}
}

// saveProxy validates the typed value, hands it to the ApplyProxy hook (which
// owns persistence and precedence) and reports what is now in effect.
func (m Model) saveProxy() (tea.Model, tea.Cmd) {
	if m.applyProxy == nil {
		m.modal = modalNone
		return m.setToast("the proxy setting needs a real vault", "err"), nil
	}
	val := strings.TrimSpace(m.pxVal)

	// Validate here as well as in the hook so a typo is corrected in place,
	// with the cursor still in the field, rather than as a toast over a closed
	// modal. Empty and "off" are both legal and neither parses as a URL.
	if val != "" && !strings.EqualFold(val, proxydial.Off) {
		if _, err := proxydial.Parse(val); err != nil {
			m.pxErr = err.Error()
			return m, nil
		}
	}

	d, err := m.applyProxy(val)
	if err != nil {
		m.pxErr = err.Error()
		return m, nil
	}

	// What gets stored is what the file will hold: the password is stripped on
	// the way to disk, so keeping the typed value in memory would leave the
	// screen disagreeing with the file after the next restart.
	m.proxySetting = localcfg.StripPassword(val)
	m.proxyDialer = d
	m.modal = modalNone
	m.pxErr = ""

	switch {
	case !d.Enabled():
		return m.setToast("proxy off — connecting directly", "ok"), nil
	case d.Source() != proxydial.SourceConfig:
		// Saved, but something with higher precedence is still in charge; say so
		// rather than let the row imply the edit did nothing.
		return m.setToast("saved — "+d.String()+" still applies from "+d.Source().String(), "warn"), nil
	default:
		return m.setToast("proxy set to "+d.String(), "ok"), nil
	}
}

// proxyLabel renders the effective proxy for the settings row.
func (m Model) proxyLabel() string {
	if m.demo {
		return "—"
	}
	return m.proxyDialer.String()
}

// proxyOverridden reports whether something outranks the stored setting, which
// the editor calls out so a saved value that does not apply is not a mystery.
func (m Model) proxyOverridden() bool {
	src := m.proxyDialer.Source()
	return src == proxydial.SourceFlag || src == proxydial.SourceEnv
}
