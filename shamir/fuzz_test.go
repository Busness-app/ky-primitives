package shamir

import "testing"

// Combine must return an error for any malformed input, never a panic. The three 0x11d
// implementations panic on a duplicate index and on a short share, both reachable from a
// custodian retrying a shard.
func FuzzCombineNeverPanics(f *testing.F) {
	f.Add([]byte{1, 2}, []byte{0xaa, 0xbb}, 2)
	f.Add([]byte{0, 0}, []byte{0x00}, 1)
	f.Add([]byte{5, 5, 5}, []byte{0xff, 0xee, 0xdd}, 1)
	f.Add([]byte{}, []byte{}, 0)

	f.Fuzz(func(t *testing.T, indices, values []byte, width int) {
		if len(indices) == 0 || width < 0 || width > 64 {
			return
		}
		shares := make([]Share, 0, len(indices))
		for i, idx := range indices {
			start := (i * width) % (len(values) + 1)
			end := start + width
			if end > len(values) {
				end = len(values)
			}
			shares = append(shares, Share{Index: idx, Value: values[start:end]})
		}
		if got, err := Combine(shares); err == nil && len(got) != len(shares[0].Value) {
			t.Fatalf("nil error but got %d bytes for %d-byte shares", len(got), len(shares[0].Value))
		}
	})
}

func FuzzParseShareNeverPanics(f *testing.F) {
	for _, s := range []string{"1-ff", "", "-", "0-", "999999999999999999999-ff", "1-f-2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseShare(in)
		if err != nil {
			return
		}
		if round, err := ParseShare(got.String()); err != nil || round.Index != got.Index {
			t.Fatalf("ParseShare(%q) = %v, but its String() does not round trip: %v", in, got, err)
		}
	})
}
