package ui

import (
	"errors"
	"sort"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/theme"
	tea "github.com/charmbracelet/bubbletea"
)

// errNoProjectDoc signals a routed host mutation whose project doc is missing.
var errNoProjectDoc = errors.New("project not ready — sync first")

// mergedHost is a hosts-tab row: a stored host plus its origin. ProjectID is ""
// for a personal-vault host; otherwise the host comes from a keyed project doc.
type mergedHost struct {
	store.Host
	ProjectID   string
	ProjectName string
}

// mergedHosts returns the personal hosts plus every keyed project's hosts (real
// mode only), stable-sorted by name. In demo/signed-out mode this is exactly the
// personal host list, so those screens are unchanged.
func (m Model) mergedHosts() []mergedHost {
	var out []mergedHost
	for _, h := range m.storeHosts() {
		out = append(out, mergedHost{Host: h})
	}
	if m.realMode() {
		for _, p := range m.realProjects {
			if p.AwaitingKey {
				continue
			}
			doc := m.projectDocs[p.ID]
			if doc == nil {
				continue
			}
			for _, h := range doc.HostList() {
				out = append(out, mergedHost{Host: h, ProjectID: p.ID, ProjectName: p.Name})
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		})
	}
	return out
}

// filteredMergedHosts applies the active project filter and search query.
func (m Model) filteredMergedHosts() []mergedHost {
	hs := m.mergedHosts()
	if m.projFilterID != "" {
		kept := hs[:0:0]
		for _, h := range hs {
			if h.ProjectID == m.projFilterID {
				kept = append(kept, h)
			}
		}
		hs = kept
	}
	if m.query == "" {
		return hs
	}
	q := strings.ToLower(m.query)
	out := make([]mergedHost, 0, len(hs))
	for _, h := range hs {
		hay := strings.ToLower(h.Name + " " + h.Addr + " " + h.User + " " + strings.Join(h.Tags, " ") + " " + h.ProjectName)
		if strings.Contains(hay, q) {
			out = append(out, h)
		}
	}
	return out
}

// selectedMergedHost returns the host under the hosts-tab cursor.
func (m Model) selectedMergedHost() (mergedHost, bool) {
	fh := m.filteredMergedHosts()
	if len(fh) == 0 {
		return mergedHost{}, false
	}
	return fh[clampIdx(m.hostIdx, len(fh))], true
}

// projectHostRow renders a merged row for a project host: identical layout to a
// personal row but with a dim project tag in place of the tags column.
func projectHostRow(t theme.Theme, mh mergedHost, res probe.Result, known, live, sel bool, innerW int) string {
	bg := t.Panel
	mark := " "
	nameFg := t.Fg
	if sel {
		bg = t.Sel
		mark = "▸"
		nameFg = t.Hi
	}
	avail := innerW - 2*padX
	if avail < 10 {
		avail = 10
	}
	liveSeg := bgpad(2, bg)
	if live {
		liveSeg = stl(t.Ok, bg).Render("● ")
	}
	tag := "⧉ " + mh.ProjectName
	statusTxt, statusRole := probeStatusText(res, known)
	tagW := len([]rune(tag))
	const (
		nameW   = 16
		statusW = 10
	)
	connW := avail - (2 + 2 + nameW + 3 + tagW + statusW)
	if connW < 6 {
		connW = 6
	}
	mid := stl(t.Hi, bg).Render(mark+" ") +
		liveSeg +
		rowSeg(mh.Name, nameW, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(mh.Conn(), connW, t.Dim, bg, false) +
		bgpad(1, bg) +
		rowSeg(tag, tagW, t.Mag, bg, false) +
		bgpad(1, bg) +
		rowSeg(statusTxt, statusW, colorFor(t, statusRole), bg, true)
	return selRow(innerW, bg, mid)
}

// --- project-aware host CRUD --------------------------------------------------

// addHostToProject validates and appends h to a project doc, then schedules a
// debounced push.
func (m Model) addHostToProject(projectID string, h store.Host) (Model, tea.Cmd, store.Host, error) {
	doc := m.projectDocs[projectID]
	if doc == nil {
		return m, nil, store.Host{}, errNoProjectDoc
	}
	stored, err := doc.AddHost(h)
	if err != nil {
		return m, nil, store.Host{}, err
	}
	mm, cmd := m.scheduleProjectPush(projectID)
	return mm, cmd, stored, nil
}

// deleteHostFromProject removes a host from a project doc and schedules a push.
func (m Model) deleteHostFromProject(projectID, hostID string) (Model, tea.Cmd, error) {
	doc := m.projectDocs[projectID]
	if doc == nil {
		return m, nil, errNoProjectDoc
	}
	if err := doc.DeleteHost(hostID); err != nil {
		return m, nil, err
	}
	mm, cmd := m.scheduleProjectPush(projectID)
	return mm, cmd, nil
}

// projectFormOptions are the selectable targets in the host form's project
// selector: personal first, then each writable project (by ID).
func (m Model) projectFormOptions() []mergedHost {
	opts := []mergedHost{{ProjectID: "", ProjectName: "personal"}}
	for _, p := range m.writableProjects() {
		opts = append(opts, mergedHost{ProjectID: p.ID, ProjectName: p.Name})
	}
	return opts
}

// projectOptionLabel is the display name for a project ID in the selector.
func (m Model) projectOptionLabel(id string) string {
	if id == "" {
		return "personal"
	}
	for _, p := range m.realProjects {
		if p.ID == id {
			return p.Name
		}
	}
	return "personal"
}

// cycleProject advances the project selector by dir among the form options.
func (m Model) cycleProject(cur string, dir int) string {
	opts := m.projectFormOptions()
	idx := 0
	for i, o := range opts {
		if o.ProjectID == cur {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(opts)) % len(opts)
	return opts[idx].ProjectID
}
