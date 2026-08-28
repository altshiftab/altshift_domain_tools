// Package asn is an autonomous system number, written the one way.
//
// It is its own package because four sources produce one and they do not agree on how to write it:
// a registry object opens with "AS13335", ARIN calls the same thing a handle, RDAP answers with the
// number on its own, and the routing data writes it as a decimal string. A consumer comparing two
// of those as text would find them different and count one party's network twice.
package asn

import (
	"fmt"
	"strconv"
	"strings"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// Prefix is what a number is written with.
const Prefix = "AS"

// Normalize writes a number the one way, or answers with nothing where it is not one.
//
// It answers rather than failing because the sources it reads are registries and routing tables
// rather than a caller: an object holding something that is not a number is that registry's problem,
// and dropping it is the whole of what a reader should do about it.
func Normalize(value string) string {
	value = strings.TrimSpace(value)

	// "AS 13335" is written, and so is "as13335".
	if rest, found := cutPrefixFold(value, Prefix); found {
		value = strings.TrimSpace(rest)
	}

	if value == "" {
		return ""
	}

	// A 32-bit number, which is what the registries hand out. Anything else is not one, leading
	// zeros included -- ParseUint reads them, and writing the number back drops them, which is what
	// makes two spellings of the same number one thing.
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return ""
	}

	return Prefix + strconv.FormatUint(number, 10)
}

// FromNumber writes a number a source answered with as an integer.
func FromNumber(number uint32) string {
	return Prefix + strconv.FormatUint(uint64(number), 10)
}

// Number reads the number back out, for a source that wants it without the prefix.
func Number(value string) (uint32, error) {
	normalized := Normalize(value)
	if normalized == "" {
		return 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: not an autonomous system number", altshiftErrors.ErrParseError),
			value,
		)
	}

	number, err := strconv.ParseUint(strings.TrimPrefix(normalized, Prefix), 10, 32)
	if err != nil {
		return 0, altshiftErrors.NewWithTrace(fmt.Errorf("parse uint: %w", err), normalized)
	}

	return uint32(number), nil
}

// cutPrefixFold is strings.CutPrefix without regard to case.
func cutPrefixFold(value string, prefix string) (string, bool) {
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return value, false
	}

	return value[len(prefix):], true
}
