package organization_test

import (
	"errors"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/organization"
)

func TestDistinctive(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		given    string
		expected string
	}{
		{name: "a company form is dropped", given: "Kivra AB", expected: "Kivra"},
		{name: "however it is punctuated", given: "Google, Inc.", expected: "Google"},
		{name: "and however it is cased", given: "Example LTD", expected: "Example"},
		{name: "a dotted form is one word rather than two", given: "Example S.A.", expected: "Example"},
		{
			name:     "the words every company shares go too, the shorter term matching more",
			given:    "Nordic Snipe Group AB",
			expected: "Nordic Snipe",
		},
		{name: "a hyphenated name is one word", given: "Alt-Shift AB", expected: "Alt-Shift"},
		{name: "nothing but form and shared words leaves nothing", given: "Data Group AB", expected: ""},
		{name: "a name that is only a company form leaves nothing", given: "AB", expected: ""},
		{name: "an empty name stays empty", given: "", expected: ""},
		{
			name:     "an airline is not a company form, whatever France thinks",
			given:    "SAS",
			expected: "SAS",
		},
		{name: "surrounding space is not a word", given: "  Kivra   AB  ", expected: "Kivra"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := organization.Distinctive(testCase.given); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

// TestCheck holds the first of the two gates: what a name could not possibly discriminate on is
// caught here, before a search is made, because the search would bill for the privilege.
func TestCheck(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		given    string
		expected error
	}{
		{name: "a real name passes", given: "Kivra AB"},
		{name: "a hyphenated one passes", given: "Alt-Shift AB"},
		{
			name:  "a three-letter name passes, real companies having them",
			given: "SEB",
		},
		{name: "two letters cannot identify anyone", given: "AI", expected: organization.ErrTooShort},
		{
			name:     "nor can a name of nothing but shared words",
			given:    "Data Group AB",
			expected: organization.ErrTooGeneric,
		},
		{
			name:     "nor can a company form on its own",
			given:    "Ltd",
			expected: organization.ErrTooGeneric,
		},
		{
			name:     "the length is counted in letters rather than in characters",
			given:    "A B",
			expected: organization.ErrTooShort,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := organization.Check(testCase.given)

			if testCase.expected == nil {
				if err != nil {
					t.Errorf("expected the name to pass, got %v", err)
				}

				return
			}

			if !errors.Is(err, testCase.expected) {
				t.Errorf("expected %v, got %v", testCase.expected, err)
			}
		})
	}
}

func TestLabel(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		given    string
		expected string
	}{
		{name: "a plain domain", given: "kivra.com", expected: "kivra"},
		{name: "a multi-part suffix", given: "example.co.uk", expected: "example"},
		{name: "a host under the domain", given: "www.kivra.se", expected: "kivra"},
		{name: "a trailing dot", given: "kivra.se.", expected: "kivra"},
		{name: "cased and spaced", given: "  KIVRA.SE ", expected: "kivra"},
		{name: "nothing is nothing", given: "", expected: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := organization.Label(testCase.given); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

// TestMinimumLengthAdmitsRealNames records why the gate is set where it is. Three-letter companies
// exist and are exactly the ones worth searching for; what a three-letter substring drags in with it
// is caught by the match count instead, which no reading of the name could have predicted.
func TestMinimumLengthAdmitsRealNames(t *testing.T) {
	t.Parallel()

	if organization.MinimumLength > 3 {
		t.Errorf("expected a minimum that admits SEB and IBM, got %d", organization.MinimumLength)
	}
	if organization.MinimumLength < 2 {
		t.Errorf("expected a minimum that rejects a single letter, got %d", organization.MinimumLength)
	}
}
