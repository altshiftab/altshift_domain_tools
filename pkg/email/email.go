// Package email answers whether a registered address belongs to a domain.
//
// It is one predicate, and it is its own package because it is the one the library's trustworthiness
// rests on. Every registry walk begins with a search that is looser than what it is looking for --
// a full-text match anywhere in an object, a name that merely begins the same way -- and this is
// what stands between such a match and attributing a stranger's address space to a customer. Three
// registry clients ask it, and they should be asking the same question.
package email

import "strings"

// AtDomain reports whether the address is at the domain or a subdomain of it.
//
// A subdomain counts because a party registers contacts at one freely -- noc@ops.example.com is
// example.com's -- while a suffix match alone would not do: notexample.com ends with example.com
// and belongs to somebody else entirely.
func AtDomain(address string, domain string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))

	if address == "" || domain == "" {
		return false
	}

	// The last one, an address being allowed to hold a quoted local part with an at sign in it.
	index := strings.LastIndex(address, "@")
	if index < 0 {
		return false
	}

	host := strings.TrimSuffix(address[index+1:], ".")
	if host == "" {
		return false
	}

	return host == domain || strings.HasSuffix(host, "."+domain)
}
