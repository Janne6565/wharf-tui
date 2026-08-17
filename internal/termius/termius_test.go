package termius

import (
	"reflect"
	"testing"
)

// plainDecryptor passes fields through: values that are not cipher envelopes are
// returned verbatim, so the mapping can be tested without any key material.
func plainDecryptor(t *testing.T) *decryptor {
	t.Helper()
	d, err := newDecryptor(make([]byte, keySize))
	if err != nil {
		t.Fatalf("newDecryptor: %v", err)
	}
	return d
}

func ref(id int64) map[string]any { return map[string]any{"id": id} }

// LevelDB keeps every generation of a row, and all of them are "live" at that
// level — dedup has to happen on the business key or one host appears many times.
func TestDedupeLatestKeepsNewest(t *testing.T) {
	rows := []map[string]any{
		{"id": int64(1), "label": "old", "updated_at": "2024-01-01T00:00:00"},
		{"id": int64(1), "label": "new", "updated_at": "2025-06-01T00:00:00"},
		{"id": int64(1), "label": "middle", "updated_at": "2024-09-01T00:00:00"},
		{"id": int64(2), "label": "other", "updated_at": "2024-01-01T00:00:00"},
	}
	got := dedupeLatest(rows)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if got[0]["label"] != "new" {
		t.Errorf("id 1 resolved to %q, want %q", got[0]["label"], "new")
	}
}

// A row that never synced has no server id, only a local one; dropping those
// would silently lose hosts the user just created.
func TestDedupeLatestKeepsLocalOnlyRows(t *testing.T) {
	rows := []map[string]any{
		{"local_id": int64(7), "label": "unsynced", "updated_at": "2025-01-01T00:00:00"},
		{"local_id": int64(7), "label": "unsynced-newer", "updated_at": "2025-02-01T00:00:00"},
	}
	got := dedupeLatest(rows)
	if len(got) != 1 || got[0]["label"] != "unsynced-newer" {
		t.Fatalf("got %#v, want one row labelled unsynced-newer", got)
	}
}

func TestConvertHostJoinsConfig(t *testing.T) {
	dec := plainDecryptor(t)
	host := map[string]any{
		"id": int64(1), "label": "web", "address": "10.0.0.5",
		"ssh_config": ref(50), "group": ref(9),
	}
	configs := map[string]map[string]any{
		"50": {"id": int64(50), "username": "deploy", "port": int64(2222), "ssh_key": ref(3)},
	}
	groups := map[string]string{"9": "prod"}
	tags := map[string][]string{"1": {"eu", "web"}}

	got, err := convertHost(host, configs, nil, groups, tags, dec)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got.Name != "web" || got.Addr != "10.0.0.5" || got.User != "deploy" || got.Port != 2222 {
		t.Errorf("got %+v", got)
	}
	if got.Source != Source {
		t.Errorf("source = %q, want %q", got.Source, Source)
	}
	// The group is a folder in Termius and Wharf has no folders, so it joins
	// the tags rather than being dropped.
	if want := []string{"eu", "prod", "web"}; !reflect.DeepEqual(got.Tags, want) {
		t.Errorf("tags = %v, want %v", got.Tags, want)
	}
}

// A host with a key configured stays in Wharf's default key mode. Only a host
// that has a password and no key is switched, so the imported auth mode matches
// how Termius actually connects.
func TestConvertHostAuthMode(t *testing.T) {
	dec := plainDecryptor(t)
	base := func() map[string]any {
		return map[string]any{"id": int64(1), "label": "h", "address": "a", "ssh_config": ref(1)}
	}

	cases := []struct {
		name       string
		cfg        map[string]any
		wantAuth   string
		wantPasswd string
	}{
		{"key", map[string]any{"id": int64(1), "ssh_key": ref(2)}, "key", ""},
		{"password only", map[string]any{"id": int64(1), "password": "s3cret"}, "password", "s3cret"},
		{"key and password", map[string]any{"id": int64(1), "ssh_key": ref(2), "password": "s3cret"}, "key", "s3cret"},
		{"neither", map[string]any{"id": int64(1)}, "key", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convertHost(base(), map[string]map[string]any{"1": tc.cfg}, nil, nil, nil, dec)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}
			if got.AuthMethod != tc.wantAuth {
				t.Errorf("auth = %q, want %q", got.AuthMethod, tc.wantAuth)
			}
			if got.Password != tc.wantPasswd {
				t.Errorf("password stored = %v, want %v", got.Password != "", tc.wantPasswd != "")
			}
		})
	}
}

// Credentials may live on a shared identity rather than on the config.
func TestConvertHostFallsBackToIdentity(t *testing.T) {
	dec := plainDecryptor(t)
	host := map[string]any{"id": int64(1), "label": "h", "address": "a", "ssh_config": ref(1)}
	configs := map[string]map[string]any{"1": {"id": int64(1), "identity": ref(8)}}
	identities := map[string]map[string]any{"8": {"id": int64(8), "username": "ci", "password": "pw"}}

	got, err := convertHost(host, configs, identities, nil, nil, dec)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got.User != "ci" || got.Password != "pw" {
		t.Errorf("got user=%q password-set=%v, want ci/true", got.User, got.Password != "")
	}
}

func TestConvertHostDefaults(t *testing.T) {
	dec := plainDecryptor(t)
	host := map[string]any{"id": int64(1), "address": "box.example"}

	got, err := convertHost(host, nil, nil, nil, nil, dec)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	// An unlabelled host is shown by its address in Termius; mirror that
	// rather than importing a blank name.
	if got.Name != "box.example" {
		t.Errorf("name = %q, want the address", got.Name)
	}
	if got.Port != 22 || got.User != "root" {
		t.Errorf("got user=%q port=%d, want root/22", got.User, got.Port)
	}
}

// Termius allows hosts whose address comes from a template or a chain; Wharf
// has nowhere to put those, so they are reported rather than imported blank.
func TestConvertHostWithoutAddressIsSkipped(t *testing.T) {
	dec := plainDecryptor(t)
	if _, err := convertHost(map[string]any{"id": int64(1), "label": "x"}, nil, nil, nil, nil, dec); err == nil {
		t.Fatal("want an error for a host with no address, got nil")
	}
}

func TestRefID(t *testing.T) {
	if got := refID(map[string]any{"id": int64(12), "local_id": int64(3)}); got != "12" {
		t.Errorf("refID = %q, want 12", got)
	}
	if got := refID(nil); got != "" {
		t.Errorf("refID(nil) = %q, want empty", got)
	}
}

// Identification is by cipher header, never by "looks like base64": a plain
// field that happens to decode as base64 must not be treated as ciphertext.
func TestIsEnvelope(t *testing.T) {
	if isEnvelope([]byte("dGhpcyBpcyBub3QgY2lwaGVydGV4dA==")) {
		t.Error("plain base64-looking text classified as an envelope")
	}
	env := append([]byte{0x04, 0x01}, make([]byte, nonceSize+16)...)
	if !isEnvelope(env) {
		t.Error("well-formed envelope not recognised")
	}
}

// Deleted rows must not be imported, but an unrecognised status must not cost
// the user a host either.
func TestDropDeleted(t *testing.T) {
	rows := []map[string]any{
		{"id": int64(1), "status": "SYNCHRONIZED"},
		{"id": int64(2), "status": "DELETED"},
		{"id": int64(3), "status": "PENDING_DELETE"},
		{"id": int64(4), "status": "SOMETHING_NEW"},
		{"id": int64(5)},
	}
	got := dropDeleted(rows)
	if len(got) != 3 {
		t.Fatalf("kept %d rows, want 3 (1, 4 and 5)", len(got))
	}
	for _, r := range got {
		if id := r["id"].(int64); id == 2 || id == 3 {
			t.Errorf("deleted row %d survived", id)
		}
	}
}
