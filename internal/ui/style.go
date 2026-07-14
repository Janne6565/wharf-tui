package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/theme"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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

// rule renders a full-width horizontal border line.
func rule(t theme.Theme, w int) string {
	return stl(t.Border, t.Bg).Render(strings.Repeat("─", w))
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
