package cidr

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// TestCoverText holds the conversion a registry forces. It writes an allocation as a first and last
// address, and an arbitrary range of addresses is not one prefix.
func TestCoverText(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		first       string
		last        string
		expect      []string
		expectError bool
	}{
		{name: "a range that is one prefix", first: "193.10.7.0", last: "193.10.7.255", expect: []string{"193.10.7.0/24"}},
		{name: "a large range", first: "130.237.0.0", last: "130.237.255.255", expect: []string{"130.237.0.0/16"}},
		{name: "a single address", first: "10.0.0.0", last: "10.0.0.0", expect: []string{"10.0.0.0/32"}},
		{
			// The case that makes this more than a string rewrite: an unaligned range needs several
			// prefixes to cover it exactly, and the alternative -- one prefix too large -- would
			// attribute addresses the party does not hold.
			name:   "an unaligned range needs several prefixes",
			first:  "10.0.0.1",
			last:   "10.0.0.6",
			expect: []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"},
		},
		{
			// The top of the address space is where the walk would run forever if it added the block
			// size to the start and looked for the next one without checking for the wrap.
			name:   "a range reaching the top of the address space",
			first:  "255.255.255.252",
			last:   "255.255.255.255",
			expect: []string{"255.255.255.252/30"},
		},
		{name: "the whole address space", first: "0.0.0.0", last: "255.255.255.255", expect: []string{"0.0.0.0/0"}},
		{
			// A v6 allocation is written the same way, and is worth as much: the registries hand out
			// a great deal of v6 space, and dropping it would make a party look smaller than it is.
			name:   "a v6 allocation",
			first:  "2606:4700::",
			last:   "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff",
			expect: []string{"2606:4700::/32"},
		},
		{
			name:   "an unaligned v6 range",
			first:  "2001:db8::1",
			last:   "2001:db8::4",
			expect: []string{"2001:db8::1/128", "2001:db8::2/127", "2001:db8::4/128"},
		},
		{
			name:   "the top of the v6 address space",
			first:  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
			last:   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			expect: []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"},
		},
		{
			// A v4-in-v6 address is the v4 address it wraps, so it covers as one rather than failing
			// on the family check below.
			name:   "a v4 address written as v6",
			first:  "::ffff:10.0.0.0",
			last:   "10.0.0.255",
			expect: []string{"10.0.0.0/24"},
		},
		{name: "not an address at all", first: "nonsense", last: "10.0.0.1", expectError: true},
		{name: "the end not an address", first: "10.0.0.1", last: "nonsense", expectError: true},
		{name: "the end before the start", first: "10.0.0.6", last: "10.0.0.1", expectError: true},
		// Two families are not a range at all, and treating them as one would produce prefixes in
		// neither.
		{name: "two families", first: "10.0.0.1", last: "2001:db8::1", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := CoverText(testCase.first, testCase.last)

			if testCase.expectError {
				if !errors.Is(err, ErrMalformedRange) {
					t.Fatalf("%s: expected a malformed range, got %v", testCase.name, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if !slices.Equal(got, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

// TestCoverIsExact holds the property the prefixes have to have, whatever the range: they cover
// every address between the two ends and not one address more.
func TestCoverIsExact(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		first string
		last  string
	}{
		{name: "unaligned at both ends", first: "10.0.0.3", last: "10.0.1.130"},
		{name: "unaligned at the start", first: "192.0.2.5", last: "192.0.2.255"},
		{name: "unaligned at the end", first: "198.51.100.0", last: "198.51.100.200"},
		{name: "spanning octets", first: "172.16.255.250", last: "172.17.0.10"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			first := netip.MustParseAddr(testCase.first)
			last := netip.MustParseAddr(testCase.last)

			prefixes, err := Cover(first, last)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			// Walking the range one address at a time is affordable here and is the check that
			// matters: every address in the range is covered.
			for address := first; address.Compare(last) <= 0; address = address.Next() {
				if !slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
					return prefix.Contains(address)
				}) {
					t.Fatalf("%s: %v is in the range but in none of %v", testCase.name, address, prefixes)
				}
			}

			// And nothing outside it is.
			for _, outside := range []netip.Addr{first.Prev(), last.Next()} {
				if slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
					return prefix.Contains(outside)
				}) {
					t.Errorf("%s: %v is outside the range but covered by %v", testCase.name, outside, prefixes)
				}
			}
		})
	}
}

// TestPrefixes holds the other two forms a registry writes an allocation in. A v6 allocation is a
// prefix rather than two addresses and a range of one address is written as the address, so a
// caller reading allocations meets all three and should not have to tell them apart.
func TestPrefixes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		text        string
		expect      []string
		expectError bool
	}{
		{name: "a v6 prefix", text: "2001:db8::/32", expect: []string{"2001:db8::/32"}},
		{name: "a v4 prefix", text: "192.0.2.0/24", expect: []string{"192.0.2.0/24"}},
		{name: "a single v4 address", text: "192.0.2.1", expect: []string{"192.0.2.1/32"}},
		{name: "a single v6 address", text: "2001:db8::1", expect: []string{"2001:db8::1/128"}},
		{name: "space around it", text: "  192.0.2.0/24 ", expect: []string{"192.0.2.0/24"}},
		{
			// A registry does not write one, but a caller passing one on should get the network
			// rather than an address inside it.
			name:   "a prefix with host bits set",
			text:   "192.0.2.5/24",
			expect: []string{"192.0.2.0/24"},
		},
		{
			// The v4 address it wraps, so that it covers as one rather than as a v6 /128.
			name:   "a v4 address written as v6",
			text:   "::ffff:192.0.2.1",
			expect: []string{"192.0.2.1/32"},
		},
		{name: "not an address at all", text: "nonsense", expectError: true},
		{name: "a range rather than a prefix", text: "10.0.0.1 - 10.0.0.6", expectError: true},
		{name: "nothing", text: "", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := Prefixes(testCase.text)

			if testCase.expectError {
				if !errors.Is(err, ErrMalformedRange) {
					t.Fatalf("%s: expected a malformed range, got %v", testCase.name, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if !slices.Equal(got, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

func TestStrings(t *testing.T) {
	t.Parallel()

	if got := Strings(nil); len(got) != 0 {
		t.Errorf("expected nothing, got %v", got)
	}

	got := Strings([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")})
	if !slices.Equal(got, []string{"10.0.0.0/8", "2001:db8::/32"}) {
		t.Errorf("expected both rendered, got %v", got)
	}
}

func TestCoverRejectsAnInvalidAddress(t *testing.T) {
	t.Parallel()

	if _, err := Cover(netip.Addr{}, netip.MustParseAddr("10.0.0.1")); !errors.Is(err, ErrMalformedRange) {
		t.Errorf("expected a malformed range, got %v", err)
	}
	if _, err := Cover(netip.MustParseAddr("10.0.0.1"), netip.Addr{}); !errors.Is(err, ErrMalformedRange) {
		t.Errorf("expected a malformed range, got %v", err)
	}
}
