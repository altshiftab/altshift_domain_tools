// Package cidr expresses an address range as prefixes.
//
// Registries write an allocation as a first and last address, and an arbitrary range of addresses is
// not one prefix: 10.0.0.1 - 10.0.0.6 is a /32, a /30 and a /31. So the conversion returns however
// many prefixes it takes to cover the range exactly, rather than the one prefix that would have to
// be too large -- which would attribute addresses the party does not hold.
//
// Both ends of a range are addresses like any other. A registry writing 104.16.0.0 - 104.31.255.255
// is stating the extent of what a party holds, not an addressing plan, so neither end is a network
// or a broadcast address and neither is trimmed: whether the lowest and highest address of a subnet
// can be assigned to a host is a matter of how the holder configures it -- a /31 link uses both of
// its addresses (RFC 3021), a /32 is one host, and IPv6 has no broadcast at all -- and none of that
// bears on who the addresses belong to. A /31 or a /32 in the output is a real range rather than a
// degenerate one, and dropping either end would understate what a party holds.
//
// It is its own package because more than one registry forces the same conversion, and because the
// arithmetic is the kind that is worth getting right once.
package cidr

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// ErrMalformedRange is a pair of addresses that is not a range: an address that does not parse, two
// addresses of different families, or an end before the start.
var ErrMalformedRange = errors.New("malformed range")

// Cover returns the prefixes that cover the range from the first address to the last, exactly.
func Cover(first netip.Addr, last netip.Addr) ([]netip.Prefix, error) {
	// The zone is dropped rather than rejected: a scoped address is the same address, and keeping
	// the zone would only make the comparisons below disagree with the arithmetic. Unmapping is what
	// lets a v4-in-v6 address be covered as the v4 address it is.
	first = first.Unmap().WithZone("")
	last = last.Unmap().WithZone("")

	if !first.IsValid() || !last.IsValid() {
		return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, first.String(), last.String())
	}

	if first.Is4() != last.Is4() {
		return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, first.String(), last.String())
	}

	if first.Compare(last) > 0 {
		return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, first.String(), last.String())
	}

	bits := first.BitLen()
	prefixes := make([]netip.Prefix, 0)

	for {
		// The largest block that starts here and does not run past the end: the shortest prefix the
		// address is the network address of, whose own last address is still within the range. The
		// single-address prefix always satisfies both, so the search always finds one.
		prefix := netip.PrefixFrom(first, bits)
		for length := 0; length <= bits; length++ {
			candidate := netip.PrefixFrom(first, length)
			if candidate.Masked().Addr() != first {
				continue
			}

			if lastAddress(candidate).Compare(last) <= 0 {
				prefix = candidate

				break
			}
		}

		prefixes = append(prefixes, prefix)

		next := lastAddress(prefix).Next()
		// The range reached the top of the address space, or the block covered the rest of it.
		if !next.IsValid() || next.Compare(last) > 0 {
			break
		}

		first = next
	}

	return prefixes, nil
}

// CoverText covers the range between two addresses written as text.
func CoverText(first string, last string) ([]string, error) {
	firstAddress, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: parse addr: %w", ErrMalformedRange, err), first)
	}

	lastAddress, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: parse addr: %w", ErrMalformedRange, err), last)
	}

	prefixes, err := Cover(firstAddress, lastAddress)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("cover: %w", err), first, last)
	}

	return Strings(prefixes), nil
}

// Prefixes reads a single address, or something already written as a prefix, as prefixes.
//
// It is the other form a registry writes an allocation in: a v6 allocation is a prefix rather than
// two addresses, and a range of one address is written as the address. Both are already exact, so
// there is nothing to cover -- but a caller reading allocations meets all three forms and should
// not have to tell them apart.
func Prefixes(text string) ([]string, error) {
	text = strings.TrimSpace(text)

	// Masked, so that a prefix written with host bits set -- which a registry does not do, but a
	// caller might pass on -- names the network rather than an address inside it.
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return []string{prefix.Masked().String()}, nil
	}

	if address, err := netip.ParseAddr(text); err == nil {
		address = address.Unmap().WithZone("")

		return Strings([]netip.Prefix{netip.PrefixFrom(address, address.BitLen())}), nil
	}

	return nil, altshiftErrors.NewWithTrace(ErrMalformedRange, text)
}

// Strings renders prefixes as text.
func Strings(prefixes []netip.Prefix) []string {
	rendered := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		rendered = append(rendered, prefix.String())
	}

	return rendered
}

// lastAddress is the highest address in the prefix: the network address with every host bit set.
func lastAddress(prefix netip.Prefix) netip.Addr {
	address := prefix.Masked().Addr()

	// AsSlice returns a copy, so setting the host bits here does not touch the address it came from.
	// It answers with nothing for an address that is not one, which has no highest address either.
	octets := address.AsSlice()
	if octets == nil {
		return address
	}

	host := address.BitLen() - prefix.Bits()
	for index := len(octets) - 1; index >= 0 && host > 0; index-- {
		if host >= 8 {
			octets[index] = 0xff
			host -= 8

			continue
		}

		octets[index] |= byte(1<<host - 1)
		host = 0
	}

	highest, _ := netip.AddrFromSlice(octets)

	return highest
}
