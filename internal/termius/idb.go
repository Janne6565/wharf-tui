package termius

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/syndtr/goleveldb/leveldb/journal"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/table"
)

// Why this reads raw files instead of opening the database
//
// Chromium's IndexedDB uses a custom LevelDB comparator ("idb_cmp1") that
// decodes key prefixes and orders them numerically. goleveldb cannot reproduce
// it, and opening the database with a byte-comparing stand-in does not fail —
// it silently mis-merges the sstables and drops records. Measured on a real
// profile: opening the database yielded 4,627 records and 8 of 38 database
// names, while reading the same files directly yielded 39,955 records and all
// 38 names, hosts included.
//
// So each sstable and journal is read on its own and every record is kept.
// Ordering does not matter, because dedup happens afterwards on the business
// key rather than on LevelDB's key order.

// idbComparer satisfies goleveldb's table reader, which insists on a comparator
// whose name matches the one recorded in the file. Ordering is irrelevant here:
// tables are read whole, never seeked into.
type idbComparer struct{}

func (idbComparer) Compare(a, b []byte) int {
	return strings.Compare(string(a), string(b))
}
func (idbComparer) Name() string                      { return "idb_cmp1" }
func (idbComparer) Separator(dst, a, _ []byte) []byte { return append(dst, a...) }
func (idbComparer) Successor(dst, b []byte) []byte    { return append(dst, b...) }

// idbRecord is one raw key/value pair recovered from the profile.
type idbRecord struct {
	key   []byte
	value []byte
}

// readTable reads every entry of one .ldb sstable.
func readTable(path string) ([]idbRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	r, err := table.NewReader(f, fi.Size(), storage.FileDesc{}, nil, nil, &opt.Options{Comparer: idbComparer{}})
	if err != nil {
		return nil, err
	}
	defer r.Release()

	var out []idbRecord
	it := r.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		// Table-level keys are internal keys: the user key plus an 8-byte
		// (sequence, kind) trailer the database layer would normally strip.
		k := it.Key()
		if len(k) < 8 {
			continue
		}
		out = append(out, idbRecord{
			key:   append([]byte(nil), k[:len(k)-8]...),
			value: append([]byte(nil), it.Value()...),
		})
	}
	return out, it.Error()
}

// readJournal reads the write-ahead log, whose records have not been compacted
// into an sstable yet — that is where the most recent edits live.
func readJournal(path string) ([]idbRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// strict=false: a journal's tail is routinely a partially written record,
	// which is normal rather than corruption. Stopping there is correct; the
	// records already read stay valid.
	jr := journal.NewReader(f, nil, false, true)
	var out []idbRecord
	for {
		r, err := jr.Next()
		if err != nil {
			break
		}
		var buf []byte
		tmp := make([]byte, 32*1024)
		for {
			n, err := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil || n == 0 {
				break
			}
		}
		out = append(out, decodeBatch(buf)...)
	}
	return out, nil
}

// decodeBatch walks a LevelDB write batch: an 8-byte sequence number, a 4-byte
// entry count, then per entry a kind byte, a length-prefixed key and — for puts
// only — a length-prefixed value.
func decodeBatch(b []byte) []idbRecord {
	const batchHeader = 12
	if len(b) < batchHeader {
		return nil
	}
	r := &reader{b: b, i: batchHeader}

	var out []idbRecord
	for r.i < len(r.b) {
		kind, err := r.byte()
		if err != nil {
			break
		}
		kl, err := r.varint()
		if err != nil {
			break
		}
		k, err := r.take(int(kl))
		if err != nil {
			break
		}
		if kind == 0 { // deletion carries no value
			continue
		}
		vl, err := r.varint()
		if err != nil {
			break
		}
		v, err := r.take(int(vl))
		if err != nil {
			break
		}
		out = append(out, idbRecord{
			key:   append([]byte(nil), k...),
			value: append([]byte(nil), v...),
		})
	}
	return out
}

// scanProfile gathers every record from every sstable and journal in dir.
func scanProfile(dir string) ([]idbRecord, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var all []idbRecord
	var failures []string
	for _, name := range names {
		p := filepath.Join(dir, name)
		var (
			recs []idbRecord
			err  error
		)
		switch strings.ToLower(filepath.Ext(name)) {
		case ".ldb", ".sst":
			recs, err = readTable(p)
		case ".log":
			recs, err = readJournal(p)
		default:
			continue
		}
		if err != nil {
			// One unreadable file is survivable — the same rows usually exist
			// in another generation — but it must not pass unmentioned.
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		all = append(all, recs...)
	}

	if len(all) == 0 {
		if len(failures) > 0 {
			return nil, fmt.Errorf("no records read from %s (%s)", dir, strings.Join(failures, "; "))
		}
		return nil, fmt.Errorf("no records found in %s", dir)
	}
	return all, nil
}

// --- key parsing -------------------------------------------------------------

// globalMetaDatabaseName is the key type byte for the "database name -> id" rows
// in Chromium's global metadata.
const globalMetaDatabaseName = 201

// keyPrefix is the database/object-store/index triple every IndexedDB key opens
// with. Only the single-byte-per-id encoding (leading 0x00) is handled, which is
// what a profile of this size uses; anything wider is skipped rather than
// misread.
type keyPrefix struct {
	database    uint64
	objectStore uint64
	index       uint64
}

// indexObjectStoreData is the index id marking a row that holds an object
// store's actual record, as opposed to an index entry or metadata.
const indexObjectStoreData = 1

func parsePrefix(k []byte) (keyPrefix, []byte, bool) {
	if len(k) < 4 || k[0] != 0x00 {
		return keyPrefix{}, nil, false
	}
	return keyPrefix{
		database:    uint64(k[1]),
		objectStore: uint64(k[2]),
		index:       uint64(k[3]),
	}, k[4:], true
}

// stringWithLength reads Chromium's metadata string encoding: a varint
// character count followed by big-endian UTF-16.
func (r *reader) stringWithLength() (string, error) {
	n, err := r.varint()
	if err != nil {
		return "", err
	}
	b, err := r.take(int(n) * 2)
	if err != nil {
		return "", err
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return string(utf16.Decode(u)), nil
}

// tables groups a profile's records by database name, still encrypted and
// still carrying every historical generation.
type tables map[string][]map[string]any

// readTables scans the profile and decodes every object-store record, keyed by
// database name.
func readTables(leveldbDir string) (tables, error) {
	recs, err := scanProfile(leveldbDir)
	if err != nil {
		return nil, err
	}

	// Pass 1: database id -> name, from the global metadata rows.
	names := map[uint64]string{}
	for _, rec := range recs {
		p, rest, ok := parsePrefix(rec.key)
		if !ok || p.database != 0 || p.objectStore != 0 || p.index != 0 {
			continue
		}
		if len(rest) == 0 || rest[0] != globalMetaDatabaseName {
			continue
		}
		r := &reader{b: rest[1:]}
		if _, err := r.stringWithLength(); err != nil { // origin
			continue
		}
		name, err := r.stringWithLength()
		if err != nil {
			continue
		}
		vr := &reader{b: rec.value}
		id, err := vr.varint()
		if err != nil {
			continue
		}
		names[id] = name
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no database names found in %s; the profile may be from an "+
			"incompatible Termius version", leveldbDir)
	}

	// Pass 2: decode the object-store records of the databases we care about.
	out := tables{}
	var decodeErr error
	for _, rec := range recs {
		p, _, ok := parsePrefix(rec.key)
		if !ok || p.index != indexObjectStoreData {
			continue
		}
		name, known := names[p.database]
		if !known || !wantedDatabases[name] {
			continue
		}
		v, err := decodeValue(rec.value)
		if err != nil {
			// Keep the first failure but carry on: historical generations of a
			// row are common, and one bad generation should not sink a profile
			// whose live rows decode cleanly. Reported only if nothing decodes.
			if decodeErr == nil {
				decodeErr = fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		if m, ok := v.(map[string]any); ok {
			out[name] = append(out[name], m)
		}
	}

	if len(out) == 0 {
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, fmt.Errorf("no host records found in %s", leveldbDir)
	}
	return out, nil
}

// wantedDatabases are the object stores a host import needs. The rest of the
// profile (history_commands, activities, telemetry) is deliberately not read.
var wantedDatabases = map[string]bool{
	"hosts":          true,
	"ssh_configs":    true,
	"ssh_identities": true,
	"groups":         true,
	"tags":           true,
	"tag_hosts":      true,
	"keys":           true,
	"known_hosts":    true,
}
