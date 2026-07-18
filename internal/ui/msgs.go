package ui

import (
	"context"

	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/sshcfg"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// --- vault gate messages ----------------------------------------------------

// The gate messages carry the master password onward: the sync engine
// retains it in memory to unlock remote vault blobs (which have their own
// salts and DEK). It never touches disk.
type vaultCreatedMsg struct {
	v    vaultHandle
	code string
	pw   string
	err  error
}

type vaultOpenedMsg struct {
	v   vaultHandle
	pw  string
	err error
}

type vaultRecoveredMsg struct {
	v   vaultHandle
	err error
}

type vaultResetMsg struct {
	code string
	pw   string
	err  error
}

func (m Model) createCmd(pw string) tea.Cmd {
	path, fn := m.vaultPath, m.createVault
	return func() tea.Msg {
		v, code, err := fn(path, []byte(pw))
		return vaultCreatedMsg{v: v, code: code, pw: pw, err: err}
	}
}

func (m Model) openCmd(pw string) tea.Cmd {
	path, fn := m.vaultPath, m.openVault
	return func() tea.Msg {
		v, err := fn(path, []byte(pw))
		return vaultOpenedMsg{v: v, pw: pw, err: err}
	}
}

func (m Model) recoverCmd(code string) tea.Cmd {
	path, fn := m.vaultPath, m.openRecovery
	return func() tea.Msg {
		v, err := fn(path, code)
		return vaultRecoveredMsg{v: v, err: err}
	}
}

// resetCmd changes the password and regenerates the recovery code on an
// already-open (recovery-unlocked) vault.
func resetCmd(v vaultHandle, pw string) tea.Cmd {
	return func() tea.Msg {
		if err := v.ChangePassword([]byte(pw)); err != nil {
			return vaultResetMsg{err: err}
		}
		code, err := v.RegenerateRecovery()
		return vaultResetMsg{code: code, pw: pw, err: err}
	}
}

// --- probes -----------------------------------------------------------------

type probeResultMsg struct {
	HostID string
	Result probe.Result
}

// probeCmds fans out one probe per host as a batch.
func (m Model) probeCmds() tea.Cmd {
	if m.st == nil {
		return nil
	}
	hosts := m.st.Hosts()
	cmds := make([]tea.Cmd, 0, len(hosts))
	for _, h := range hosts {
		h := h
		cmds = append(cmds, func() tea.Msg {
			res := probe.Dial(h.Addr, h.Port, probe.DefaultTimeout)
			return probeResultMsg{HostID: h.ID, Result: res}
		})
	}
	return tea.Batch(cmds...)
}

// --- key scan ---------------------------------------------------------------

type keysScannedMsg struct {
	keys []keys.KeyInfo
	err  error
}

func (m Model) scanKeysCmd() tea.Cmd {
	dir := m.sshDir()
	return func() tea.Msg {
		infos, err := keys.Scan(dir)
		return keysScannedMsg{keys: infos, err: err}
	}
}

type keyGeneratedMsg struct {
	info keys.KeyInfo
	err  error
}

func (m Model) generateKeyCmd(name, comment, passphrase string) tea.Cmd {
	dir := m.sshDir()
	return func() tea.Msg {
		info, err := keys.Generate(dir, name, comment, []byte(passphrase))
		return keyGeneratedMsg{info: info, err: err}
	}
}

// keySyncedMsg carries a VaultKey built from a scanned key (or a read error).
// The file read runs off the reducer, mirroring generateKeyCmd; AddKey and the
// vault save happen back in the handler.
type keySyncedMsg struct {
	key store.VaultKey
	err error
}

func (m Model) syncKeyCmd(info keys.KeyInfo) tea.Cmd {
	return func() tea.Msg {
		vk, err := buildVaultKey(info)
		return keySyncedMsg{key: vk, err: err}
	}
}

// --- ssh_config import ------------------------------------------------------

type importDoneMsg struct {
	hosts   []store.Host
	skipped []string
	err     error
}

func (m Model) importCmd() tea.Cmd {
	path := m.sshDir() + "/config"
	return func() tea.Msg {
		hs, skipped, err := sshcfg.Import(path)
		return importDoneMsg{hosts: hs, skipped: skipped, err: err}
	}
}

// --- dial / session ---------------------------------------------------------

type dialDoneMsg struct {
	hostID string
	sess   *sshx.Session
	err    error
}

// detachedMsg is returned by the tea.Exec attach callback: the takeover ended,
// either by an explicit detach (ctrl+\) or the remote session dying.
type detachedMsg struct {
	hostID string
}

func dialCmd(mgr *sshx.Manager, ctx context.Context, spec sshx.HostSpec, cols, rows int) tea.Cmd {
	return func() tea.Msg {
		sess, err := mgr.Dial(ctx, spec, cols, rows)
		return dialDoneMsg{hostID: spec.ID, sess: sess, err: err}
	}
}

// --- port forward -----------------------------------------------------------

// forwardDoneMsg reports the result of an async StartForward. fwd is nil on
// error (and on a degenerate start in tests). It mirrors dialDoneMsg so the
// same dial machinery (esc-cancel, prompt restore) drives the forward handshake.
type forwardDoneMsg struct {
	hostID string
	fwd    *sshx.Forward
	err    error
}

func startForwardCmd(mgr *sshx.Manager, ctx context.Context, hs sshx.HostSpec, spec sshx.ForwardSpec) tea.Cmd {
	return func() tea.Msg {
		fwd, err := mgr.StartForward(ctx, hs, spec)
		return forwardDoneMsg{hostID: hs.ID, fwd: fwd, err: err}
	}
}
