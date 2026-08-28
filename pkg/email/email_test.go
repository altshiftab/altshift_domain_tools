package email

import "testing"

func TestAtDomain(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		address string
		domain  string
		expect  bool
	}{
		{name: "at the domain", address: "ops@example.com", domain: "example.com", expect: true},
		{
			// A party registers contacts at a subdomain freely, and they are still the party's.
			name:    "at a subdomain",
			address: "noc@ops.example.com",
			domain:  "example.com",
			expect:  true,
		},
		{
			// The case a bare suffix match would get wrong, and the reason this is a function rather
			// than a HasSuffix at each call site: it ends with the domain and belongs to somebody
			// else entirely.
			name:    "a domain that merely ends the same way",
			address: "ops@notexample.com",
			domain:  "example.com",
			expect:  false,
		},
		{name: "another domain", address: "ops@example.net", domain: "example.com", expect: false},
		{name: "the domain as a prefix", address: "ops@example.com.evil.test", domain: "example.com", expect: false},
		{name: "case and space", address: "  OPS@Example.COM ", domain: " Example.com ", expect: true},
		// A domain is written with a trailing dot as readily as without, and they are the same name.
		{name: "a rooted domain", address: "ops@example.com", domain: "example.com.", expect: true},
		{name: "a rooted address", address: "ops@example.com.", domain: "example.com", expect: true},
		{
			// The local part may itself hold an at sign when quoted, so the host is what follows the
			// last one rather than the first.
			name:    "an at sign in the local part",
			address: `"weird@local"@example.com`,
			domain:  "example.com",
			expect:  true,
		},
		{name: "not an address", address: "example.com", domain: "example.com", expect: false},
		{name: "nothing after the at", address: "ops@", domain: "example.com", expect: false},
		{name: "an empty address", address: "", domain: "example.com", expect: false},
		{name: "an empty domain", address: "ops@example.com", domain: "", expect: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := AtDomain(testCase.address, testCase.domain); got != testCase.expect {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}
