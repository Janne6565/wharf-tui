package ui

import (
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// Moving a host between the personal vault and a project has always been
// possible — buried in the host form's project selector, three keystrokes deep
// and invisible unless you already knew it was there. This is the same
// operation as a first-class action on the hosts tab (`p`): pick a
// destination, enter.

// openMoveProject opens the destination picker for the selected host.
func (m Model) openMoveProject() (tea.Model, tea.Cmd) {
	mh, ok := m.selectedMergedHost()
	if !ok {
		return m, nil
	}
	if !m.realMode() {
		return m.setToast("sign in to use projects", "err"), nil
	}
	opts := m.projectFormOptions()
	if len(opts) < 2 {
		return m.setToast(m.noDestinationsText(), "err"), nil
	}
	m.mvHostID = mh.ID
	m.mvSourceID = mh.ProjectID
	m.mvName = mh.Name
	// Start on the current location so the highlighted row says where the host
	// is now, and moving the cursor is what changes it.
	m.mvIdx = 0
	for i, o := range opts {
		if o.ProjectID == mh.ProjectID {
			m.mvIdx = i
		}
	}
	m.modal = modalMoveProject
	return m, nil
}

// noDestinationsText explains why there is nowhere to move to. "No projects
// yet" is a claim about the account, so it must not be said while the list is
// still on its way — that was exactly the confusing case when projects only
// loaded on entering their tab.
func (m Model) noDestinationsText() string {
	if m.identityReady && !m.projectsLoaded {
		return "projects are still loading — try again in a moment"
	}
	if len(m.realProjects) > 0 {
		return "no project you can write to — the ones you have are awaiting access"
	}
	return "no projects yet — create one on the projects tab"
}

// moveProjectKey drives the destination picker.
func (m Model) moveProjectKey(key string) (tea.Model, tea.Cmd) {
	opts := m.projectFormOptions()
	switch key {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "j", "down":
		m.mvIdx = clampIdx(m.mvIdx+1, len(opts))
		return m, nil
	case "k", "up":
		m.mvIdx = clampIdx(m.mvIdx-1, len(opts))
		return m, nil
	case "enter", " ":
		target := opts[clampIdx(m.mvIdx, len(opts))].ProjectID
		if target == m.mvSourceID {
			m.modal = modalNone
			return m, nil
		}
		h, ok := m.moveSourceHost()
		if !ok {
			m.modal = modalNone
			return m.setToast("that host is gone — sync may have moved it", "err"), nil
		}
		mm, cmd, err := m.moveHostTo(m.mvSourceID, target, h)
		if err != nil {
			// The picker stays open with the reason: the usual cause is a name
			// clash at the destination, which the user can fix by renaming.
			m.mvErr = cleanErr(err)
			return m, nil
		}
		mm.mvErr = ""
		mm.hostIdx = clampIdx(mm.hostIdx, len(mm.filteredMergedHosts()))
		return mm, cmd
	}
	return m, nil
}

// moveSourceHost re-reads the host being moved from its own document, so the
// move writes the stored record (secrets included) rather than a display copy.
func (m Model) moveSourceHost() (store.Host, bool) {
	if m.mvSourceID == "" {
		if m.st == nil {
			return store.Host{}, false
		}
		return m.st.HostByID(m.mvHostID)
	}
	doc := m.projectDocs[m.mvSourceID]
	if doc == nil {
		return store.Host{}, false
	}
	return doc.HostByID(m.mvHostID)
}
