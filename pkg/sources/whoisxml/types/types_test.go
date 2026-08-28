package types_test

import (
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whoisxml/types"
)

// TestErrorResponseText holds the API's two names for the one thing. A rejected search field
// answers under "message" and a refused key under "messages", and a reader that knew only one of
// them would report half the failures as having said nothing.
func TestErrorResponseText(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		given    *types.ErrorResponse
		expected string
	}{
		{
			name:     "the singular, as a rejected field answers",
			given:    &types.ErrorResponse{Code: 422, Message: "Invalid search field: RegistrantName"},
			expected: "Invalid search field: RegistrantName",
		},
		{
			name:     "the plural, as a refused key answers",
			given:    &types.ErrorResponse{Code: 403, Messages: "Access restricted."},
			expected: "Access restricted.",
		},
		{
			name:     "the singular wins where both arrive",
			given:    &types.ErrorResponse{Message: "first", Messages: "second"},
			expected: "first",
		},
		{
			name:  "and neither is nothing, which the caller answers with the body itself",
			given: &types.ErrorResponse{Code: 500},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.given.Text(); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}
