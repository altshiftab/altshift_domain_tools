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
	"strconv"
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

// The suffixes reverse DNS is served under, and the label widths each of them counts in.
const (
	Ipv4ReverseSuffix = "in-addr.arpa"
	Ipv6ReverseSuffix = "ip6.arpa"
)

// The prefix lengths a reverse zone is delegated at.
//
// A zone name has one label per octet for v4 and one per nibble for v6, so only these lengths can
// be written as a zone at all. They are listed longest first because a walk looking for the
// delegation wants the most specific zone first: the delegation sits at whatever boundary the
// holder took, which is a /24 for one party and a /16 for the next.
var (
	Ipv4ReverseLengths = []int{32, 24, 16, 8}
	// The v6 list stops short of every nibble boundary on purpose. There are thirty-two of them and
	// each is a query; these are the lengths address space is actually handed out and delegated at.
	Ipv6ReverseLengths = []int{64, 56, 48, 40, 32, 24, 16}
)

// FromReverseZone reads the prefix a reverse zone is the zone for.
//
// The name is the address written backwards under a suffix -- 8.8.8.in-addr.arpa is 8.8.8.0/24 --
// so the labels count the prefix's length as well as naming it, and a zone is exactly as specific
// as the delegation that created it.
func FromReverseZone(zone string) (string, error) {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))

	if labels, found := strings.CutSuffix(zone, "."+Ipv4ReverseSuffix); found {
		prefix, err := ipv4ReverseZone(labels)
		if err != nil {
			return "", altshiftErrors.New(fmt.Errorf("ipv4 reverse zone: %w", err), zone)
		}

		return prefix, nil
	}

	if labels, found := strings.CutSuffix(zone, "."+Ipv6ReverseSuffix); found {
		prefix, err := ipv6ReverseZone(labels)
		if err != nil {
			return "", altshiftErrors.New(fmt.Errorf("ipv6 reverse zone: %w", err), zone)
		}

		return prefix, nil
	}

	return "", altshiftErrors.NewWithTrace(ErrMalformedRange, zone)
}

// ipv4ReverseZone reads the labels of an in-addr.arpa zone, which are the octets written backwards.
func ipv4ReverseZone(labels string) (string, error) {
	parts := strings.Split(labels, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return "", altshiftErrors.NewWithTrace(ErrMalformedRange, labels)
	}

	octets := make([]string, 4)
	for index := range octets {
		octets[index] = "0"
	}

	for index, part := range parts {
		// A classless delegation writes a range of addresses as one label -- "0-25" -- which names
		// no prefix of its own, so it is not one of these.
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return "", altshiftErrors.NewWithTrace(ErrMalformedRange, labels)
		}

		octets[len(parts)-1-index] = part
	}

	prefix, err := netip.ParsePrefix(strings.Join(octets, ".") + "/" + strconv.Itoa(8*len(parts)))
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("parse prefix: %w", err), labels)
	}

	return prefix.Masked().String(), nil
}

// ipv6ReverseZone reads the labels of an ip6.arpa zone, which are the nibbles written backwards.
func ipv6ReverseZone(labels string) (string, error) {
	parts := strings.Split(labels, ".")
	if len(parts) == 0 || len(parts) > 32 {
		return "", altshiftErrors.NewWithTrace(ErrMalformedRange, labels)
	}

	nibbles := make([]byte, 32)
	for index := range nibbles {
		nibbles[index] = '0'
	}

	for index, part := range parts {
		if len(part) != 1 {
			return "", altshiftErrors.NewWithTrace(ErrMalformedRange, labels)
		}

		digit := part[0]
		isDigit := digit >= '0' && digit <= '9'
		isHex := digit >= 'a' && digit <= 'f'
		if !isDigit && !isHex {
			return "", altshiftErrors.NewWithTrace(ErrMalformedRange, labels)
		}

		nibbles[len(parts)-1-index] = digit
	}

	// Grouped into hextets, an address being written four nibbles at a time.
	hextets := make([]string, 0, 8)
	for index := 0; index < len(nibbles); index += 4 {
		hextets = append(hextets, string(nibbles[index:index+4]))
	}

	prefix, err := netip.ParsePrefix(
		strings.Join(hextets, ":") + "/" + strconv.Itoa(4*len(parts)),
	)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("parse prefix: %w", err), labels)
	}

	return prefix.Masked().String(), nil
}

// ReverseZones names the zones an address could have its reverse delegated at, most specific first.
//
// The delegation sits at whatever boundary the holder took, and nothing in the address says which,
// so finding it means asking for each in turn until one answers.
func ReverseZones(address netip.Addr) []string {
	address = address.Unmap().WithZone("")
	if !address.IsValid() {
		return nil
	}

	lengths := Ipv6ReverseLengths
	if address.Is4() {
		lengths = Ipv4ReverseLengths
	}

	zones := make([]string, 0, len(lengths))
	for _, length := range lengths {
		zone, err := ReverseZone(netip.PrefixFrom(address, length))
		if err != nil {
			continue
		}

		zones = append(zones, zone)
	}

	return zones
}

// ReverseZone names the zone a prefix's reverse is delegated at.
//
// Only a prefix falling on a label boundary has one -- an octet for v4, a nibble for v6 -- because
// a zone name is written a label at a time and can say nothing finer.
func ReverseZone(prefix netip.Prefix) (string, error) {
	address := prefix.Masked().Addr()
	if !address.IsValid() {
		return "", altshiftErrors.NewWithTrace(ErrMalformedRange, prefix.String())
	}

	if address.Is4() {
		if prefix.Bits()%8 != 0 || prefix.Bits() == 0 {
			return "", altshiftErrors.NewWithTrace(ErrMalformedRange, prefix.String())
		}

		octets := address.As4()
		labels := make([]string, 0, 4)
		for index := prefix.Bits()/8 - 1; index >= 0; index-- {
			labels = append(labels, strconv.Itoa(int(octets[index])))
		}

		return strings.Join(labels, ".") + "." + Ipv4ReverseSuffix, nil
	}

	if prefix.Bits()%4 != 0 || prefix.Bits() == 0 {
		return "", altshiftErrors.NewWithTrace(ErrMalformedRange, prefix.String())
	}

	octets := address.As16()
	labels := make([]string, 0, 32)
	for index := prefix.Bits()/4 - 1; index >= 0; index-- {
		nibble := octets[index/2] >> 4
		if index%2 == 1 {
			nibble = octets[index/2] & 0x0f
		}

		labels = append(labels, strconv.FormatUint(uint64(nibble), 16))
	}

	return strings.Join(labels, ".") + "." + Ipv6ReverseSuffix, nil
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
