package asn

import (
	"errors"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// TestNormalize holds the four spellings the sources use. A consumer comparing two of them as text
// would find them different and count one party's network twice.
func TestNormalize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		value  string
		expect string
	}{
		{name: "a registry object's own form", value: "AS13335", expect: "AS13335"},
		{name: "the number on its own", value: "13335", expect: "AS13335"},
		{name: "lower case", value: "as13335", expect: "AS13335"},
		{name: "a space after the prefix", value: "AS 13335", expect: "AS13335"},
		{name: "space around it", value: "  AS13335 ", expect: "AS13335"},
		// Two spellings of one number are one number, which is the whole point of writing it the
		// one way.
		{name: "leading zeros", value: "AS0013335", expect: "AS13335"},
		{name: "a 32-bit number", value: "AS4294967295", expect: "AS4294967295"},
		{name: "zero", value: "AS0", expect: "AS0"},

		{name: "past 32 bits", value: "AS4294967296", expect: ""},
		{name: "negative", value: "AS-1", expect: ""},
		{name: "not a number", value: "ASNONSENSE", expect: ""},
		{name: "a prefix and nothing else", value: "AS", expect: ""},
		{name: "nothing", value: "", expect: ""},
		{name: "a range rather than a number", value: "AS1-AS2", expect: ""},
		// A name beginning the same way is not a number written oddly.
		{name: "a word starting with the prefix", value: "ASSIGNED", expect: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := Normalize(testCase.value); got != testCase.expect {
				t.Errorf("%s: expected %q, got %q", testCase.name, testCase.expect, got)
			}
		})
	}
}

func TestFromNumber(t *testing.T) {
	t.Parallel()

	if got := FromNumber(13335); got != "AS13335" {
		t.Errorf("expected AS13335, got %q", got)
	}
	if got := FromNumber(0); got != "AS0" {
		t.Errorf("expected AS0, got %q", got)
	}
}

func TestNumber(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"AS13335", "13335", "as13335", "AS0013335"} {
		got, err := Number(value)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", value, err)

			continue
		}
		if got != 13335 {
			t.Errorf("%q: expected 13335, got %d", value, got)
		}
	}

	if _, err := Number("nonsense"); !errors.Is(err, altshiftErrors.ErrParseError) {
		t.Errorf("expected a parse error, got %v", err)
	}
}
