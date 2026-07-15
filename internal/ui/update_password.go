package ui

import (
	"context"
	"errors"
	"os"

	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// change-master-password modal field indices.
const (
	cpCurrent = iota
	cpNew
	cpConfirm
	cpFields
)

// changePasswordDoneMsg reports the outcome of the async re-key. wrongCurrent
// distinguishes a bad current password (a retryable user error) from a real
// failure; online marks a failure that came from the backend rotation.
type changePasswordDoneMsg struct {
	err          error
	wrongCurrent bool
	online       bool
}

// openChangePassword resets and shows the change-master-password modal.
func (m Model) openChangePassword() Model {
	m.modal = modalChangePassword
	m.cpVals = [3]string{}
	m.cpFocus = 0
	m.cpErr = ""
	m.cpBusy = false
	return m
}

// changePasswordKey drives the modal: three masked fields (current / new /
// confirm), submitted with enter. Input is ignored while the re-key runs.
func (m Model) changePasswordKey(key string) (tea.Model, tea.Cmd) {
	if m.cpBusy {
		return m, nil
	}
	switch key {
	case "esc":
		m.modal = modalNone
		m.cpVals = [3]string{}
		m.cpFocus = 0
		m.cpErr = ""
		return m, nil
	case "tab", "down":
		m.cpFocus = (m.cpFocus + 1) % cpFields
		return m, nil
	case "shift+tab", "up":
		m.cpFocus = (m.cpFocus + cpFields - 1) % cpFields
		return m, nil
	case "enter":
		return m.submitChangePassword()
	case "backspace":
		if v := m.cpVals[m.cpFocus]; len(v) > 0 {
			m.cpVals[m.cpFocus] = v[:len(v)-1]
		}
		return m, nil
	default:
		if isPrintable(key) {
			m.cpVals[m.cpFocus] += key
		}
		return m, nil
	}
}

// submitChangePassword validates the fields and kicks off the async re-key.
func (m Model) submitChangePassword() (tea.Model, tea.Cmd) {
	current, newPw, confirm := m.cpVals[cpCurrent], m.cpVals[cpNew], m.cpVals[cpConfirm]
	switch {
	case current == "":
		m.cpErr = "enter your current password"
		return m, nil
	case newPw == "":
		m.cpErr = "new password cannot be empty"
		return m, nil
	case newPw != confirm:
		m.cpErr = "new passwords do not match"
		return m, nil
	case newPw == current:
		m.cpErr = "new password must be different"
		return m, nil
	}
	m.cpErr = ""
	m.cpBusy = true
	return m, m.changePasswordCmd(current, newPw)
}

// changePasswordCmd verifies the current password, re-keys the local vault and
// — when signed in — rotates the server auth key and uploads the re-encrypted
// blob. Every step runs off the UI goroutine (argon2 is slow). On an online
// failure the local vault is rolled back to the old password so the local and
// remote states never diverge.
func (m Model) changePasswordCmd(current, newPw string) tea.Cmd {
	v := m.vault
	eng := m.eng
	signedIn := m.signedIn
	payload := append([]byte(nil), m.vault.Payload()...)
	readBlob := m.blobReader()
	openBlob := m.blobOpener()
	return func() tea.Msg {
		// 1. Confirm the current password by decrypting the on-disk blob. This
		//    is lock-free (OpenPayload just decrypts bytes) and works offline.
		blob, err := readBlob()
		if err != nil {
			return changePasswordDoneMsg{err: err}
		}
		if _, err := openBlob(blob, []byte(current)); err != nil {
			if errors.Is(err, vault.ErrWrongSecret) {
				return changePasswordDoneMsg{wrongCurrent: true}
			}
			return changePasswordDoneMsg{err: err}
		}

		// 2. Re-key the local vault (rewrites the password slot; the recovery
		//    slot stays valid). Always safe and all the offline path needs.
		if err := v.ChangePassword([]byte(newPw)); err != nil {
			return changePasswordDoneMsg{err: err}
		}

		// 3. Online: rotate the server auth key and push the re-encrypted blob.
		if signedIn && eng != nil {
			ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
			defer cancel()
			if err := eng.ChangePassword(ctx, []byte(current), []byte(newPw), payload); err != nil {
				// The backend change is transactional and left the server
				// untouched, so roll the local vault back to keep them in step.
				_ = v.ChangePassword([]byte(current))
				return changePasswordDoneMsg{err: err, online: true}
			}
			return changePasswordDoneMsg{}
		}

		// Offline: keep the engine's retained password current so a later
		// sign-in and sync can still unlock remote blobs.
		if eng != nil {
			eng.SetPassword([]byte(newPw))
		}
		return changePasswordDoneMsg{}
	}
}

// handleChangePasswordDone applies the async outcome to the modal.
func (m Model) handleChangePasswordDone(msg changePasswordDoneMsg) (tea.Model, tea.Cmd) {
	m.cpBusy = false
	switch {
	case msg.wrongCurrent:
		m.cpErr = "current password is incorrect"
		m.cpVals[cpCurrent] = ""
		m.cpFocus = cpCurrent
		return m, nil
	case msg.err != nil:
		if msg.online {
			m.cpErr = "server rejected the change: " + msg.err.Error()
		} else {
			m.cpErr = "could not change password: " + msg.err.Error()
		}
		return m, nil
	}
	m.modal = modalNone
	m.cpVals = [3]string{}
	m.cpFocus = 0
	m.cpErr = ""
	if m.signedIn {
		return m.setToast("master password changed — re-unlock other devices with it", "ok"), nil
	}
	return m.setToast("master password changed", "ok"), nil
}

// blobReader returns the local vault-file reader (injectable in tests; defaults
// to reading the vault file directly).
func (m Model) blobReader() func() ([]byte, error) {
	if m.syncReadBlob != nil {
		return m.syncReadBlob
	}
	path := m.vaultPath
	return func() ([]byte, error) { return os.ReadFile(path) }
}

// blobOpener returns the WHARFV-blob decryptor (injectable in tests; defaults to
// vault.OpenPayload).
func (m Model) blobOpener() func(blob, password []byte) ([]byte, error) {
	if m.syncOpenBlob != nil {
		return m.syncOpenBlob
	}
	return vault.OpenPayload
}
