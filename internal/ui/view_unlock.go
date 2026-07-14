package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/theme"
)

// unlockView renders the real-mode vault gate, styled like the auth screen
// (centered panel, ⚓ wharf branding).
func (m Model) unlockView(t theme.Theme) []string {
	logo := bold(t.Hi, t.Bg).Render("⚓ wharf") + m.cur(t.Hi, t.Bg)
	subtitle := stl(t.Dim, t.Bg).Render("local encrypted vault")

	pw := 66
	if pw > m.w-6 {
		pw = m.w - 6
	}

	title, border, body := m.unlockBody(t)

	box := boxPanelAuto(t, title, colorFor(t, border), pw, body)
	block := []string{logo, subtitle, ""}
	block = append(block, box...)
	return centerInArea(block, m.w, m.h, t.Bg)
}

// unlockBody produces the panel title/border/body for the current gate step.
func (m Model) unlockBody(t theme.Theme) (string, string, []string) {
	errLine := func(body []string) []string {
		if m.unlockErr != "" {
			body = append(body, "", stl(t.Err, t.Panel).Render(" "+m.unlockErr))
		}
		return body
	}

	switch m.unlockStep {
	case ulUnlock:
		body := []string{
			stl(t.Dim, t.Panel).Render("Enter your master password to unlock this vault."),
			"",
			m.pwLine(t, "password  ", m.pwInput, true),
			"",
			stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" unlock · ") +
				stl(t.Hi, t.Panel).Render("r") + stl(t.Dim, t.Panel).Render(" recovery code (empty field)"),
		}
		return "unlock vault", "hi", errLine(body)

	case ulUnlocking:
		return "unlock vault", "hi", []string{
			stl(t.Warn, t.Panel).Render(m.spinner() + " unlocking…"),
			stl(t.Dim, t.Panel).Render("deriving key (argon2id)"),
		}

	case ulCreate:
		body := []string{
			stl(t.Dim, t.Panel).Render("No vault yet. Choose a master password for this machine."),
			"",
			m.pwLine(t, "password  ", m.pwInput, m.pwField == 0),
			m.pwLine(t, "confirm   ", m.pwConfirm, m.pwField == 1),
			"",
			stl(t.Hi, t.Panel).Render("tab") + stl(t.Dim, t.Panel).Render(" switch field · ") +
				stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" create vault"),
		}
		return "create vault", "hi", errLine(body)

	case ulCreating:
		return "create vault", "hi", []string{
			stl(t.Warn, t.Panel).Render(m.spinner() + " creating vault…"),
			stl(t.Dim, t.Panel).Render("deriving key (argon2id)"),
		}

	case ulRecovery:
		body := []string{
			stl(t.Dim, t.Panel).Render("Enter your 40-character recovery code."),
			stl(t.Dim, t.Panel).Render("Dashes, spaces and case don't matter."),
			"",
			m.echoLine(t, "code  ", recoveryDisplay(m.recoveryInput)),
			"",
			stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" unlock · ") +
				stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" back to password"),
		}
		return "recovery code", "warn", errLine(body)

	case ulRecoveryOpening:
		return "recovery code", "warn", []string{
			stl(t.Warn, t.Panel).Render(m.spinner() + " verifying recovery code…"),
		}

	case ulReset:
		body := []string{
			stl(t.Ok, t.Panel).Render("Recovery accepted. Set a NEW master password."),
			"",
			m.pwLine(t, "new password  ", m.pwInput, m.pwField == 0),
			m.pwLine(t, "confirm       ", m.pwConfirm, m.pwField == 1),
			"",
			stl(t.Hi, t.Panel).Render("tab") + stl(t.Dim, t.Panel).Render(" switch field · ") +
				stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" continue"),
		}
		return "set a new password", "hi", errLine(body)

	case ulResetting:
		return "set a new password", "hi", []string{
			stl(t.Warn, t.Panel).Render(m.spinner() + " updating vault…"),
		}

	case ulShowCode:
		code := bold(t.Hi, t.Panel).Render(formatRecoveryCode(m.recoveryCode))
		body := []string{
			stl(t.Warn, t.Panel).Render("Write this down NOW. It is shown exactly once."),
			stl(t.Warn, t.Panel).Render("It is the ONLY way to recover your vault if you"),
			stl(t.Warn, t.Panel).Render("forget your password. Wharf cannot show it again."),
			"",
			hcenter([]string{code}, panelInner(m.w), t.Panel)[0],
			"",
			stl(t.Hi, t.Panel).Render(" y") + stl(t.Dim, t.Panel).Render(" / ") +
				stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render("  I saved it — continue"),
		}
		return "recovery code — save it now", "warn", body

	case ulLocked:
		return "vault locked", "err", []string{
			stl(t.Err, t.Panel).Render("Another wharf instance is running."),
			"",
			stl(t.Dim, t.Panel).Render("This vault is locked by another process. Close it,"),
			stl(t.Dim, t.Panel).Render("then press enter to retry."),
		}
	}
	return "wharf", "hi", nil
}

// pwLine renders a masked password field with a cursor when focused.
func (m Model) pwLine(t theme.Theme, label, value string, focused bool) string {
	dots := stl(t.Hi, t.Panel).Render(strings.Repeat("•", len([]rune(value))))
	line := stl(t.Fg, t.Panel).Render(label) + dots
	if focused {
		line += m.cur(t.Hi, t.Panel)
	}
	return line
}

// echoLine renders a plain (echoed) input field with a cursor.
func (m Model) echoLine(t theme.Theme, label, value string) string {
	return stl(t.Fg, t.Panel).Render(label) + stl(t.Hi, t.Panel).Render(value) + m.cur(t.Hi, t.Panel)
}

// recoveryDisplay keeps the recovery input readable while typing without
// exceeding the panel width.
func recoveryDisplay(s string) string {
	if len(s) > 46 {
		return "…" + s[len(s)-45:]
	}
	return s
}

// formatRecoveryCode groups a 40-char code into 8×5 blocks (XXXXX-XXXXX-…).
func formatRecoveryCode(code string) string {
	var parts []string
	for i := 0; i+5 <= len(code); i += 5 {
		parts = append(parts, code[i:i+5])
	}
	if len(parts) == 0 {
		return code
	}
	return strings.Join(parts, "-")
}

// panelInner is the usable content width of a centered gate / modal panel
// (interior minus the horizontal padding on both sides).
func panelInner(w int) int {
	pw := 66
	if pw > w-6 {
		pw = w - 6
	}
	return boxContentW(pw)
}
