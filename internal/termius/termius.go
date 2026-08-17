package termius

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/store"
)

// Source is the store.Host.Source value marking a Termius-imported host.
const Source = "termius"

// Options control where an import reads from. The zero value auto-detects.
type Options struct {
	// DataDir is a Termius profile, IndexedDB or leveldb directory. Empty
	// means auto-detect.
	DataDir string
	// LocalKeyFile holds the base64 localKey, for when the credential store
	// cannot be read (no keyring client, headless machine, foreign profile).
	LocalKeyFile string
}

// Result reports what an import found. Counts come from the profile itself, so
// the summary can tell the user what was skipped rather than quietly dropping it.
type Result struct {
	Hosts []store.Host
	// KeySource describes where the decryption key came from, for the summary.
	KeySource string
	// Groups is the number of Termius groups folded into tags.
	Groups int
	// WithPassword counts hosts that carried a saved password.
	WithPassword int
	// Skipped lists hosts that could not be imported, with the reason.
	Skipped []string
}

// Import reads a local Termius profile and converts it to Wharf hosts.
//
// It is read-only: nothing in the Termius profile is opened for writing, and
// Termius does not need to be running (or closed).
func Import(opts Options) (Result, error) {
	dir := opts.DataDir
	if dir == "" {
		dir = DefaultDataDir()
		if dir == "" {
			return Result{}, fmt.Errorf("no Termius profile found; looked in:\n  %s",
				strings.Join(SearchedDataDirs(), "\n  "))
		}
	}
	leveldbDir, ok := locateLevelDB(dir)
	if !ok {
		return Result{}, fmt.Errorf("no IndexedDB under %s; point the import at the Termius "+
			"data directory itself", dir)
	}

	tbl, err := readTables(leveldbDir)
	if err != nil {
		return Result{}, err
	}

	hosts := dropDeleted(dedupeLatest(tbl["hosts"]))
	if len(hosts) == 0 {
		return Result{}, fmt.Errorf("no hosts in the Termius profile at %s", dir)
	}

	// Pick the key against a field known to be encrypted, so a machine holding
	// several Termius keyring entries resolves to the one that fits.
	key, err := loadLocalKey(opts.LocalKeyFile, encryptedSample(hosts))
	if err != nil {
		return Result{}, err
	}
	dec, err := newDecryptor(key.Key)
	if err != nil {
		return Result{}, err
	}

	configs := byID(dedupeLatest(tbl["ssh_configs"]))
	identities := byID(dedupeLatest(tbl["ssh_identities"]))
	groups := groupNames(dedupeLatest(tbl["groups"]), dec)
	tags := hostTags(dedupeLatest(tbl["tags"]), dedupeLatest(tbl["tag_hosts"]), dec)

	res := Result{KeySource: key.Source, Groups: len(groups)}
	for _, h := range hosts {
		converted, err := convertHost(h, configs, identities, groups, tags, dec)
		if err != nil {
			res.Skipped = append(res.Skipped, err.Error())
			continue
		}
		if converted.Password != "" {
			res.WithPassword++
		}
		res.Hosts = append(res.Hosts, converted)
	}

	// Nothing decrypting at all means the key is wrong in a way individual
	// fields did not surface (every field empty, say). Better to fail than to
	// report a successful import of blank hosts.
	if dec.decrypted == 0 {
		return Result{}, ErrWrongKey
	}
	if len(res.Hosts) == 0 {
		return Result{}, fmt.Errorf("no importable hosts: %s", strings.Join(res.Skipped, "; "))
	}

	sort.Slice(res.Hosts, func(i, j int) bool {
		return strings.ToLower(res.Hosts[i].Name) < strings.ToLower(res.Hosts[j].Name)
	})
	return res, nil
}

// convertHost joins a Termius host with its ssh_config and identity and maps
// the result onto store.Host.
func convertHost(h map[string]any, configs, identities map[string]map[string]any,
	groups map[string]string, tags map[string][]string, dec *decryptor) (store.Host, error) {

	id := fmt.Sprint(h["id"])

	addr, err := dec.str(h, "address")
	if err != nil {
		return store.Host{}, fmt.Errorf("host %s: address: %w", id, err)
	}
	if addr == "" {
		// Termius allows a host whose address comes from a template or an
		// agent-forwarded chain; Wharf has nowhere to put that.
		return store.Host{}, fmt.Errorf("host %s has no address", id)
	}
	label, err := dec.str(h, "label")
	if err != nil {
		return store.Host{}, fmt.Errorf("host %s: label: %w", id, err)
	}
	if label == "" {
		label = addr
	}

	out := store.Host{
		Name:   label,
		Addr:   addr,
		Port:   22,
		Source: Source,
	}

	// The username, port and credentials live on the linked ssh_config, not on
	// the host row.
	if cfg := lookupRef(h["ssh_config"], configs); cfg != nil {
		if u, err := dec.str(cfg, "username"); err == nil && u != "" {
			out.User = u
		}
		if p := intOf(cfg["port"]); p > 0 {
			out.Port = p
		}
		pw, err := dec.str(cfg, "password")
		if err != nil {
			return store.Host{}, fmt.Errorf("host %s: password: %w", id, err)
		}
		out.Password = pw

		// An ssh_config may point at a stored identity instead of carrying the
		// credentials itself.
		if ident := lookupRef(cfg["identity"], identities); ident != nil {
			if out.User == "" {
				if u, err := dec.str(ident, "username"); err == nil {
					out.User = u
				}
			}
			if out.Password == "" {
				if pw, err := dec.str(ident, "password"); err == nil {
					out.Password = pw
				}
			}
		}

		// Key mode is Wharf's default; only a host that has a password and no
		// key is switched to password mode, matching how it actually connects.
		hasKey := cfg["ssh_key"] != nil
		if !hasKey && out.Password != "" {
			out.AuthMethod = "password"
		} else {
			out.AuthMethod = "key"
		}
	} else {
		out.AuthMethod = "key"
	}

	if out.User == "" {
		out.User = "root"
	}

	// Termius groups are a folder tree and Wharf has tags, so the group name
	// becomes one tag; explicit tags are added alongside.
	var t []string
	if g := groups[refID(h["group"])]; g != "" {
		t = append(t, g)
	}
	t = append(t, tags[fmt.Sprint(h["id"])]...)
	out.Tags = dedupeStrings(t)

	return out, nil
}

// --- record helpers -----------------------------------------------------------

// dedupeLatest collapses LevelDB's historical generations to one row per
// business key, keeping the greatest updated_at.
//
// This is not the same as filtering LevelDB tombstones: every generation is
// "live" at that level, so one host legitimately appears many times. Measured
// on a real profile: 69 raw host rows collapse to the hosts the app shows.
func dedupeLatest(rows []map[string]any) []map[string]any {
	latest := map[string]map[string]any{}
	var keyless []map[string]any

	for _, r := range rows {
		var key string
		switch {
		case r["id"] != nil:
			key = "id:" + fmt.Sprint(r["id"])
		case r["local_id"] != nil:
			key = "local:" + fmt.Sprint(r["local_id"])
		default:
			keyless = append(keyless, r)
			continue
		}
		prev, seen := latest[key]
		if !seen || fmt.Sprint(r["updated_at"]) >= fmt.Sprint(prev["updated_at"]) {
			latest[key] = r
		}
	}

	out := make([]map[string]any, 0, len(latest)+len(keyless))
	for _, r := range latest {
		out = append(out, r)
	}
	out = append(out, keyless...)
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["id"]) < fmt.Sprint(out[j]["id"])
	})
	return out
}

// dropDeleted removes rows Termius has marked as deleted.
//
// Every row in the profile this was developed against was SYNCHRONIZED, so the
// exact wording of a deleted row's status is unverified — hence a substring
// match rather than an equality test, and a filter that only ever removes rows
// it positively recognises as deleted. An unknown status keeps its host: a
// missing host is a worse import than a stale one, and the user reviews the
// summary before anything is written.
func dropDeleted(rows []map[string]any) []map[string]any {
	out := rows[:0:0]
	for _, r := range rows {
		if s, ok := r["status"].(string); ok && strings.Contains(strings.ToUpper(s), "DELET") {
			continue
		}
		out = append(out, r)
	}
	return out
}

// byID indexes rows by their id for reference lookups.
func byID(rows []map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(rows))
	for _, r := range rows {
		if r["id"] != nil {
			out[fmt.Sprint(r["id"])] = r
		}
	}
	return out
}

// refID extracts the id from a Termius foreign key, which is stored as a nested
// {id, local_id} object rather than a scalar.
func refID(v any) string {
	m, ok := v.(map[string]any)
	if !ok || m["id"] == nil {
		return ""
	}
	return fmt.Sprint(m["id"])
}

func lookupRef(v any, table map[string]map[string]any) map[string]any {
	id := refID(v)
	if id == "" {
		return nil
	}
	return table[id]
}

// groupNames maps group id to its (decrypted) label.
func groupNames(rows []map[string]any, dec *decryptor) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		if r["id"] == nil {
			continue
		}
		if label, err := dec.str(r, "label"); err == nil && label != "" {
			out[fmt.Sprint(r["id"])] = label
		}
	}
	return out
}

// hostTags maps host id to its tag labels via the tag_hosts join table.
func hostTags(tags, joins []map[string]any, dec *decryptor) map[string][]string {
	labels := map[string]string{}
	for _, t := range tags {
		if t["id"] == nil {
			continue
		}
		if l, err := dec.str(t, "label"); err == nil && l != "" {
			labels[fmt.Sprint(t["id"])] = l
		}
	}

	out := map[string][]string{}
	for _, j := range joins {
		host, tag := refID(j["host"]), refID(j["tag"])
		if host == "" || tag == "" {
			continue
		}
		if l := labels[tag]; l != "" {
			out[host] = append(out[host], l)
		}
	}
	return out
}

// encryptedSample returns any encrypted field value, used to test candidate
// keys against this profile before committing to one.
func encryptedSample(hosts []map[string]any) string {
	for _, h := range hosts {
		for _, f := range []string{"address", "label"} {
			if s, ok := h[f].(string); ok && s != "" {
				if raw, err := decodeBase64(s); err == nil && isEnvelope(raw) {
					return s
				}
			}
		}
	}
	return ""
}

func intOf(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
