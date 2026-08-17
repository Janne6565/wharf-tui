package termius

import (
	"fmt"
	"math"
	"time"
	"unicode/utf16"
)

// V8 structured-clone tags. Only the subset Termius actually writes is
// implemented; anything else is an error rather than a skipped field, because a
// tag we cannot read means the record after it is misaligned and every value we
// would report from that point on is fiction.
const (
	tagVersion    = 0xff
	tagPadding    = 0x00 // alignment filler emitted before two-byte strings
	tagUndefined  = '_'
	tagNull       = '0'
	tagTrue       = 'T'
	tagFalse      = 'F'
	tagInt32      = 'I' // zigzag varint
	tagUint32     = 'U' // varint
	tagDouble     = 'N' // 8 bytes, little-endian
	tagDate       = 'D' // 8 bytes, little-endian double: ms since epoch
	tagOneByteStr = '"'
	tagTwoByteStr = 'c'
	tagUTF8Str    = 'S'
	tagObject     = 'o'
	tagObjectEnd  = '{'
	tagDenseArray = 'A'
	tagArrayEnd   = '$'
	tagSparseAray = 'a'
	tagSparseEnd  = '@'
	tagObjectRef  = '^'
)

// reader is a byte cursor over one serialized value.
type reader struct {
	b []byte
	i int
}

func (r *reader) byte() (byte, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("unexpected end of value at offset %d", r.i)
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}

func (r *reader) varint() (uint64, error) {
	var x uint64
	var shift uint
	for {
		c, err := r.byte()
		if err != nil {
			return 0, err
		}
		x |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return x, nil
		}
		shift += 7
		if shift > 63 {
			return 0, fmt.Errorf("varint overflow at offset %d", r.i)
		}
	}
}

// zigzag decodes the signed encoding V8 uses for int32 values.
func (r *reader) zigzag() (int64, error) {
	u, err := r.varint()
	if err != nil {
		return 0, err
	}
	return int64(u>>1) ^ -int64(u&1), nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, fmt.Errorf("value truncated: want %d bytes at offset %d of %d", n, r.i, len(r.b))
	}
	s := r.b[r.i : r.i+n]
	r.i += n
	return s, nil
}

func (r *reader) float64() (float64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	var bits uint64
	for i := 7; i >= 0; i-- {
		bits = bits<<8 | uint64(b[i])
	}
	return math.Float64frombits(bits), nil
}

// skipPadding advances past kPadding bytes, which may appear anywhere a tag is
// expected. V8 emits them so two-byte string payloads land on an even offset.
func (r *reader) skipPadding() {
	for r.i < len(r.b) && r.b[r.i] == tagPadding {
		r.i++
	}
}

// peek returns the next non-padding tag without consuming it.
func (r *reader) peek() (byte, error) {
	r.skipPadding()
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("unexpected end of value at offset %d", r.i)
	}
	return r.b[r.i], nil
}

func utf16leString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u))
}

// decoder deserializes one IndexedDB value.
type decoder struct {
	reader
	// objects is the back-reference table: '^' addresses an earlier object by
	// the order in which deserialization created it, so entries must be
	// appended before their contents are read.
	objects []any
}

// decodeValue deserializes a raw IndexedDB record body into Go values
// (map[string]any, []any, string, int64, float64, bool, nil).
func decodeValue(raw []byte) (any, error) {
	d := &decoder{reader: reader{b: raw}}
	// The record body is prefixed by a varint the IndexedDB layer writes ahead
	// of the serialized value itself.
	if _, err := d.varint(); err != nil {
		return nil, err
	}
	return d.value()
}

func (d *decoder) value() (any, error) {
	d.skipPadding()
	t, err := d.byte()
	if err != nil {
		return nil, err
	}

	switch t {
	case tagVersion:
		// Version tags nest: an outer envelope version wraps the value's own.
		if _, err := d.varint(); err != nil {
			return nil, err
		}
		return d.value()

	case tagObject:
		obj := map[string]any{}
		d.objects = append(d.objects, obj)
		for {
			c, err := d.peek()
			if err != nil {
				return nil, err
			}
			if c == tagObjectEnd {
				d.i++
				_, err := d.varint() // property count
				return obj, err
			}
			k, err := d.value()
			if err != nil {
				return nil, err
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			obj[fmt.Sprint(k)] = v
		}

	case tagDenseArray:
		n, err := d.varint()
		if err != nil {
			return nil, err
		}
		arr := make([]any, 0, min(int(n), 1024))
		d.objects = append(d.objects, arr)
		for {
			c, err := d.peek()
			if err != nil {
				return nil, err
			}
			if c == tagArrayEnd {
				d.i++
				if _, err := d.varint(); err != nil { // property count
					return nil, err
				}
				_, err := d.varint() // length
				return arr, err
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}

	case tagSparseAray:
		// Sparse arrays carry explicit indices, so they read as key/value pairs
		// and are surfaced as a map rather than a Go slice with holes.
		if _, err := d.varint(); err != nil { // declared length
			return nil, err
		}
		obj := map[string]any{}
		d.objects = append(d.objects, obj)
		for {
			c, err := d.peek()
			if err != nil {
				return nil, err
			}
			if c == tagSparseEnd {
				d.i++
				if _, err := d.varint(); err != nil {
					return nil, err
				}
				_, err := d.varint()
				return obj, err
			}
			k, err := d.value()
			if err != nil {
				return nil, err
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			obj[fmt.Sprint(k)] = v
		}

	case tagObjectRef:
		id, err := d.varint()
		if err != nil {
			return nil, err
		}
		if int(id) >= len(d.objects) {
			return nil, fmt.Errorf("object reference %d out of range (%d known)", id, len(d.objects))
		}
		return d.objects[id], nil

	case tagOneByteStr, tagUTF8Str:
		n, err := d.varint()
		if err != nil {
			return nil, err
		}
		b, err := d.take(int(n))
		return string(b), err

	case tagTwoByteStr:
		n, err := d.varint()
		if err != nil {
			return nil, err
		}
		b, err := d.take(int(n))
		if err != nil {
			return nil, err
		}
		return utf16leString(b), nil

	case tagInt32:
		return d.zigzag()

	case tagUint32:
		v, err := d.varint()
		return int64(v), err

	case tagDouble:
		return d.float64()

	case tagDate:
		ms, err := d.float64()
		if err != nil {
			return nil, err
		}
		t := time.UnixMilli(int64(ms)).UTC()
		d.objects = append(d.objects, t)
		return t.Format(time.RFC3339), nil

	case tagTrue:
		return true, nil
	case tagFalse:
		return false, nil
	case tagNull, tagUndefined:
		return nil, nil

	default:
		return nil, fmt.Errorf("unsupported structured-clone tag %q (%#x) at offset %d; "+
			"Termius may have changed its storage format", t, t, d.i-1)
	}
}
