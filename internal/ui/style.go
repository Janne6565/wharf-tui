package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/theme"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Layout tokens. These translate the design's px spacing into terminal cells
// (≈8-10px ≙ 1ch horizontally, ≈1 line vertically) and are the single source of
// truth for the view layer's breathing room.
const (
	padX    = 2 // horizontal inner padding inside every bordered box
	marginX = 1 // outer left/right screen margin for dashboard panes
	paneGap = 2 // gap between the two dashboard panes
	hintGap = 3 // gap between footer hint items
)

// stl builds a lipgloss style from a foreground and background color. Either may
// be empty ("") to leave it unset.
func stl(fg, bg lipgloss.Color) lipgloss.Style {
	s := lipgloss.NewStyle()
	if fg != "" {
		s = s.Foreground(fg)
	}
	if bg != "" {
		s = s.Background(bg)
	}
	return s
}

// bold is stl with bold applied.
func bold(fg, bg lipgloss.Color) lipgloss.Style { return stl(fg, bg).Bold(true) }

// bgpad renders n spaces painted with bg (used to extend a line's background).
func bgpad(n int, bg lipgloss.Color) string {
	if n <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", n))
}

// padTo right-pads a (possibly styled) string to width w with bg-colored space.
func padTo(s string, w int, bg lipgloss.Color) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + bgpad(d, bg)
	}
	return s
}

// trunc shortens a plain string to width w, adding an ellipsis when it overflows.
func trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	return string(r[:w-1]) + "…"
}

// hcenter horizontally centers each line within width w over a bg fill.
func hcenter(lines []string, w int, bg lipgloss.Color) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		left := (w - lipgloss.Width(l)) / 2
		if left < 0 {
			left = 0
		}
		out[i] = padTo(bgpad(left, bg)+l, w, bg)
	}
	return out
}

// vpad grows (or clips) lines to exactly h rows of width w. When center is true
// the block is vertically centered, otherwise it is top-aligned.
func vpad(lines []string, w, h int, bg lipgloss.Color, center bool) []string {
	if len(lines) >= h {
		return lines[:h]
	}
	blank := bgpad(w, bg)
	top := 0
	if center {
		top = (h - len(lines)) / 2
	}
	out := make([]string, 0, h)
	for i := 0; i < top; i++ {
		out = append(out, blank)
	}
	out = append(out, lines...)
	for len(out) < h {
		out = append(out, blank)
	}
	return out
}

// hjoin concatenates equal-height columns of lines side by side.
func hjoin(cols ...[]string) []string {
	h := 0
	for _, c := range cols {
		if len(c) > h {
			h = len(c)
		}
	}
	out := make([]string, h)
	for i := 0; i < h; i++ {
		for _, c := range cols {
			if i < len(c) {
				out[i] += c[i]
			}
		}
	}
	return out
}

// col builds a column of h identical bg-painted spacer lines of width w.
func col(w, h int, bg lipgloss.Color) []string {
	out := make([]string, h)
	line := bgpad(w, bg)
	for i := range out {
		out[i] = line
	}
	return out
}

// panel draws a bordered box exactly w wide and h tall, with the title floating
// on the top border (matching the design's label-on-border look). border sets
// the border/title color; the interior is painted with the theme's panel bg.
func panel(t theme.Theme, title string, border lipgloss.Color, w, h int, body []string) []string {
	if w < 2 || h < 2 {
		return col(w, h, t.Bg)
	}
	inner := w - 2
	bs := stl(border, t.Bg)

	// Top border with embedded "─ title ─────┐".
	head := "─ " + title + " "
	dashes := inner - lipgloss.Width(head)
	if dashes < 0 {
		head = trunc(head, inner)
		dashes = 0
	}
	top := bs.Render("┌" + head + strings.Repeat("─", dashes) + "┐")

	out := make([]string, 0, h)
	out = append(out, top)
	for i := 0; i < h-2; i++ {
		var content string
		if i < len(body) {
			content = body[i]
			if lipgloss.Width(content) > inner {
				content = ansi.Truncate(content, inner, "")
			}
			content = padTo(content, inner, t.Panel)
		} else {
			content = bgpad(inner, t.Panel)
		}
		out = append(out, bs.Render("│")+content+bs.Render("│"))
	}
	out = append(out, bs.Render("└"+strings.Repeat("─", inner)+"┘"))
	return out
}

// boxContentW is the usable content width inside a padded box of outer width w:
// the interior (w-2 borders) minus padX cells of padding on each side. Content
// lines for boxPanel should be built to at most this width.
func boxContentW(w int) int {
	if cw := w - 2 - 2*padX; cw > 0 {
		return cw
	}
	return 1
}

// insetBody wraps body for a padded box: one blank row of vertical padding top
// and bottom, and padX cells of horizontal padding prefixed to every content
// line. The matching right-hand inset is supplied by panel's own right-fill.
func insetBody(t theme.Theme, body []string) []string {
	pad := bgpad(padX, t.Panel)
	out := make([]string, 0, len(body)+2)
	out = append(out, "")
	for _, l := range body {
		out = append(out, pad+l)
	}
	out = append(out, "")
	return out
}

// boxPanel draws a bordered box like panel but insets its body (see insetBody).
// h is the full box height including borders; the two padding rows are drawn
// from the interior.
func boxPanel(t theme.Theme, title string, border lipgloss.Color, w, h int, body []string) []string {
	return panel(t, title, border, w, h, insetBody(t, body))
}

// boxPanelAuto is boxPanel sized to exactly fit body (2 borders + 2 padding).
func boxPanelAuto(t theme.Theme, title string, border lipgloss.Color, w int, body []string) []string {
	return boxPanel(t, title, border, w, len(body)+4, body)
}

// listPanel draws a bordered box with only vertical padding (one blank row top
// and bottom). List rows manage their own full-width selection background and
// horizontal text inset via selRow, so no horizontal padding is applied here.
func listPanel(t theme.Theme, title string, border lipgloss.Color, w, h int, rows []string) []string {
	out := make([]string, 0, len(rows)+2)
	out = append(out, "")
	out = append(out, rows...)
	out = append(out, "")
	return panel(t, title, border, w, h, out)
}

// selRow paints a full-inner-width list row: padX cells of inset on each side
// over bg, with mid (already sized to inner-2*padX) between them, so a selected
// row's highlight spans the whole pane while its text starts padX cells in.
func selRow(inner int, bg lipgloss.Color, mid string) string {
	avail := inner - 2*padX
	if avail < 0 {
		avail = 0
	}
	return bgpad(padX, bg) + padTo(mid, avail, bg) + bgpad(padX, bg)
}

// rule renders a full-width horizontal border line.
func rule(t theme.Theme, w int) string {
	return stl(t.Border, t.Bg).Render(strings.Repeat("─", w))
}

// ruleIn renders a horizontal rule of width w in the border color over the panel
// background, for footers/separators inside a box.
func ruleIn(t theme.Theme, w int) string {
	if w < 0 {
		w = 0
	}
	return stl(t.Border, t.Panel).Render(strings.Repeat("─", w))
}

// kv renders a "key   value" detail row, padded to width w over the panel bg.
func kv(t theme.Theme, k, v string, vc lipgloss.Color, w int) string {
	key := stl(t.Dim, t.Panel).Render(padTo2(k, 13))
	val := stl(vc, t.Panel).Render(v)
	return padTo(key+val, w, t.Panel)
}

// padTo2 right-pads a plain string to width w with spaces (no color).
func padTo2(s string, w int) string {
	if d := w - len([]rune(s)); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}
