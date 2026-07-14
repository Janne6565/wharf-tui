// Package theme holds Wharf's terminal color palettes. The three themes
// (abyss, phosphor, amber) mirror the design spec one-to-one so the TUI reads
// identically to the mockups.
package theme

import "github.com/charmbracelet/lipgloss"

// Theme is a full palette. Field names match the design's CSS custom properties
// (--hi, --dim, …) so cross-referencing the spec stays trivial.
type Theme struct {
	Name   string
	Bg     lipgloss.Color // canvas background
	Panel  lipgloss.Color // panel/card background
	Border lipgloss.Color // unfocused border
	Hi     lipgloss.Color // accent / focus / selection foreground
	Fg     lipgloss.Color // primary text
	Dim    lipgloss.Color // muted text
	Ok     lipgloss.Color // success / online
	Warn   lipgloss.Color // warning / hardware
	Err    lipgloss.Color // error / offline
	Mag    lipgloss.Color // project accent
	Blue   lipgloss.Color // tags
	Sel    lipgloss.Color // selected-row background
	// Ink is the near-black used for text painted on top of an Hi-colored badge.
	Ink lipgloss.Color
}

var (
	Abyss = Theme{
		Name: "abyss", Bg: "#0A0E13", Panel: "#0C1219", Border: "#233140",
		Hi: "#57D7C2", Fg: "#BCC8D2", Dim: "#54646F", Ok: "#69D26E",
		Warn: "#E3C078", Err: "#E0685E", Mag: "#C983E8", Blue: "#6FB3E8",
		Sel: "#12202A", Ink: "#07110E",
	}
	Phosphor = Theme{
		Name: "phosphor", Bg: "#040804", Panel: "#071007", Border: "#153815",
		Hi: "#9BFF9B", Fg: "#7FD98A", Dim: "#3E6B44", Ok: "#9BFF9B",
		Warn: "#D8E87A", Err: "#FF8A65", Mag: "#B8E8B8", Blue: "#7FD9C0",
		Sel: "#0C1F0E", Ink: "#03120A",
	}
	Amber = Theme{
		Name: "amber", Bg: "#0B0700", Panel: "#120C02", Border: "#3C2C0C",
		Hi: "#FFC86B", Fg: "#E0B064", Dim: "#7A5C24", Ok: "#C8E87A",
		Warn: "#FFC86B", Err: "#FF7A5C", Mag: "#E8C89B", Blue: "#D8B87A",
		Sel: "#241804", Ink: "#160E00",
	}
)

// Order is the theme cycle used by the settings screen.
var Order = []string{"abyss", "phosphor", "amber"}

var byName = map[string]Theme{
	"abyss": Abyss, "phosphor": Phosphor, "amber": Amber,
}

// Get returns the named theme, falling back to abyss.
func Get(name string) Theme {
	if t, ok := byName[name]; ok {
		return t
	}
	return Abyss
}

// Next returns the theme after name in the cycle.
func Next(name string) string {
	for i, n := range Order {
		if n == name {
			return Order[(i+1)%len(Order)]
		}
	}
	return Order[0]
}
