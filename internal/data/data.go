// Package data holds Wharf's in-memory sample vault. In a real build these come
// from the local encrypted vault (and, when signed in, sync from the server as
// ciphertext). The shapes here match the design mockup's fixtures exactly.
package data

// Host is a single SSH connection in the vault.
type Host struct {
	Name    string
	User    string
	Addr    string
	Port    int
	Tags    []string
	Project string // team project this host belongs to ("Personal" = local only)
	Key     string // identity used to authenticate
	Status  string // online | offline | unknown
	Last    string // human-readable "last session" time
}

// Conn renders the user@addr:port connection string.
func (h Host) Conn() string {
	return h.User + "@" + h.Addr + ":" + itoa(h.Port)
}

// Member is a person in a team project.
type Member struct {
	Name string
	Role string // owner | admin | member
}

// Project is a shared workspace. Only available while signed in.
type Project struct {
	Name    string
	Desc    string
	Hosts   int
	Members []Member
	Invites []string // pending invite emails
}

// Key is an identity in the vault. Private material never leaves the device.
type Key struct {
	Name    string
	Type    string
	Fp      string // fingerprint
	Created string
	Hosts   int    // number of hosts using it
	Badge   string // "default" | "hardware" | ""
}

// Hosts returns the sample local vault.
func Hosts() []Host {
	return []Host{
		{"prod-api-01", "deploy", "10.4.1.12", 22, []string{"prod", "api"}, "Atlas Platform", "id_ed25519", "online", "2h ago"},
		{"prod-api-02", "deploy", "10.4.1.13", 22, []string{"prod", "api"}, "Atlas Platform", "id_ed25519", "online", "1d ago"},
		{"db-primary", "postgres", "10.4.2.5", 5522, []string{"prod", "db"}, "Atlas Platform", "id_ed25519", "online", "4d ago"},
		{"staging-web", "deploy", "staging.acme.io", 22, []string{"staging"}, "Atlas Platform", "deploy_rsa", "unknown", "6h ago"},
		{"edge-lb-euw1", "root", "edge-euw1.acme.io", 22, []string{"edge", "lb"}, "Edge Infra", "yubikey-resident", "online", "3w ago"},
		{"edge-lb-use1", "root", "edge-use1.acme.io", 22, []string{"edge", "lb"}, "Edge Infra", "yubikey-resident", "unknown", "3w ago"},
		{"build-runner-1", "ci", "10.4.7.31", 22, []string{"ci"}, "Edge Infra", "deploy_rsa", "offline", "2mo ago"},
		{"homelab", "deniz", "homelab.local", 22, []string{"personal"}, "Personal", "id_ed25519", "online", "12m ago"},
	}
}

// Projects returns the sample team projects (only shown when signed in).
func Projects() []Project {
	return []Project{
		{"Atlas Platform", "Core API + data plane", 4, []Member{
			{"mara", "owner"}, {"deniz (you)", "admin"}, {"jonas", "member"}, {"priya", "member"},
		}, []string{"sam@acme.io"}},
		{"Edge Infra", "Load balancers & CDN edge", 3, []Member{
			{"deniz (you)", "owner"}, {"jonas", "member"},
		}, nil},
		{"Personal", "Private vault — only you", 1, []Member{
			{"deniz (you)", "owner"},
		}, nil},
	}
}

// Keys returns the sample identities.
func Keys() []Key {
	return []Key{
		{"id_ed25519", "ED25519", "SHA256:tQ9kR2mVxWpL0aY4nBc8dEfGhJkLmZw", "Mar 2025", 5, "default"},
		{"deploy_rsa", "RSA-4096", "SHA256:8fJqT5wYuIoP1sD6gHj3kLzXc2Nv9Bm", "Nov 2024", 2, ""},
		{"yubikey-resident", "ED25519-SK", "SHA256:pW3dF7hK9mQ1rT5vX8zBcEgJnRt7yLs", "Jan 2026", 2, "hardware"},
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
