package arin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin/arin_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func serverClient(t *testing.T, handler http.HandlerFunc, options ...arin_config.Option) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewClient(
		slices.Concat(
			[]arin_config.Option{
				arin_config.WithBaseUrl(serverUrl),
				arin_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
			},
			options,
		)...,
	)
}

// database is what a test server answers from: the whole walk, so that a test can say what the
// registry holds rather than what each of four requests returns.
type database struct {
	// personHandles are the hits the domain search answers with.
	personHandles []string
	// persons are the objects behind them, by handle.
	persons map[string]string
	// organizations are the search hits, by the name searched for.
	organizations map[string][]string
	// organizationPersons are the contacts on an organisation, by handle.
	organizationPersons map[string][]string
	// organizationNets are the allocations of an organisation, by handle.
	organizationNets map[string][]string

	asked []string

	lock sync.Mutex
}

func personObject(handle string, name string, company string, email string) string {
	return fmt.Sprintf(
		`{"poc":{"handle":{"$":%q},"lastName":{"$":%q},"companyName":{"$":%q},"emails":{"email":{"$":%q}}}}`,
		handle, name, company, email,
	)
}

func netRef(handle string, name string, start string, end string) string {
	return fmt.Sprintf(
		`{"@handle":%q,"@name":%q,"@startAddress":%q,"@endAddress":%q}`,
		handle, name, start, end,
	)
}

// handler answers the four requests the walk makes, and records what it was asked.
func (data *database) handler(t *testing.T) http.HandlerFunc {
	t.Helper()

	write := func(writer http.ResponseWriter, body string) {
		writer.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}

	// ARIN answers a search that matched nothing with a 404 rather than with an empty result.
	list := func(writer http.ResponseWriter, wrapper string, field string, items []string) {
		if len(items) == 0 {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		// One of something is an object and several are an array, which is what the mapping from
		// XML costs.
		body := items[0]
		if len(items) > 1 {
			body = "[" + strings.Join(items, ",") + "]"
		}

		write(writer, fmt.Sprintf(`{%q:{%q:%s}}`, wrapper, field, body))
	}

	return func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.EscapedPath()

		data.lock.Lock()
		data.asked = append(data.asked, path)
		data.lock.Unlock()

		switch {
		case strings.HasPrefix(path, PersonSearchPath+";domain="):
			refs := make([]string, 0, len(data.personHandles))
			for _, handle := range data.personHandles {
				refs = append(refs, fmt.Sprintf(`{"@handle":%q}`, handle))
			}

			list(writer, "pocs", "pocRef", refs)
		case strings.HasPrefix(path, PersonPath+"/"):
			object, ok := data.persons[strings.TrimPrefix(path, PersonPath+"/")]
			if !ok {
				writer.WriteHeader(http.StatusNotFound)

				return
			}

			write(writer, object)
		case strings.HasPrefix(path, OrganizationSearchPath+";name="):
			name, err := url.PathUnescape(strings.TrimPrefix(path, OrganizationSearchPath+";name="))
			if err != nil {
				t.Errorf("could not unescape %q: %v", path, err)
			}

			refs := make([]string, 0)
			for _, handle := range data.organizations[name] {
				refs = append(refs, fmt.Sprintf(`{"@handle":%q,"@name":%q}`, handle, handle))
			}

			list(writer, "orgs", "orgRef", refs)
		case strings.HasSuffix(path, "/pocs"):
			handle := strings.TrimSuffix(strings.TrimPrefix(path, OrganizationPath+"/"), "/pocs")

			refs := make([]string, 0)
			for _, contact := range data.organizationPersons[handle] {
				refs = append(refs, fmt.Sprintf(`{"@handle":%q,"@function":"AD"}`, contact))
			}

			list(writer, "pocs", "pocLinkRef", refs)
		case strings.HasSuffix(path, "/nets"):
			handle := strings.TrimSuffix(strings.TrimPrefix(path, OrganizationPath+"/"), "/nets")

			list(writer, "nets", "netRef", data.organizationNets[handle])
		default:
			t.Errorf("unexpected path: %s", path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}
}

// cloudflare is a live run reduced to what the walk needs: a domain whose contacts name a company,
// an organisation registered under a longer form of that company's name, and the space it holds.
func cloudflare() *database {
	return &database{
		personHandles: []string{"ABUSE2916-ARIN", "ADMIN2521-ARIN"},
		persons: map[string]string{
			"ABUSE2916-ARIN": personObject("ABUSE2916-ARIN", "Abuse", "Cloudflare, Inc.", "abuse@cloudflare.com"),
			"ADMIN2521-ARIN": personObject("ADMIN2521-ARIN", "Admin", "Cloudflare, Inc.", "rir@cloudflare.com"),
		},
		organizations:       map[string][]string{"Cloudflare*": {"CLOUD14"}},
		organizationPersons: map[string][]string{"CLOUD14": {"ADMIN2521-ARIN", "ADMIN2521-ARIN"}},
		organizationNets: map[string][]string{
			"CLOUD14": {
				netRef("NET-104-16-0-0-1", "CLOUDFLARENET", "104.16.0.0", "104.31.255.255"),
				netRef("NET6-2606-4700-1", "CLOUDFLARENET", "2606:4700::", "2606:4700:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			},
		},
	}
}

func networksOf(ranges []*Range) []string {
	found := make([]string, 0, len(ranges))
	for _, item := range ranges {
		found = append(found, item.Networks...)
	}

	return found
}

// TestRanges holds the whole walk, which is four steps because ARIN offers no search from a contact
// to the space they administer: only an organisation holds ranges, and an organisation is reachable
// by name.
func TestRanges(t *testing.T) {
	t.Parallel()

	data := cloudflare()
	client := serverClient(t, data.handler(t))

	ranges, err := client.Ranges(t.Context(), "cloudflare.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"104.16.0.0/12", "2606:4700::/32"}) {
		t.Fatalf("expected the allocations as CIDR, got %v", networksOf(ranges))
	}

	if ranges[0].NetName != "CLOUDFLARENET" {
		t.Errorf("expected the registry name kept, got %+v", ranges[0])
	}
	// The organisation is carried so that a consumer can say which party the space was attributed
	// to, rather than only that it was.
	if ranges[0].Organization == nil || ranges[0].Organization.Handle != "CLOUD14" {
		t.Errorf("expected the organisation kept, got %+v", ranges[0].Organization)
	}
}

// TestRangesChecksTheOrganizationAgainstTheContacts holds the check the name search forces. The
// bridge from a domain to an organisation is a name, and a name is a poor thing to attribute
// address space on: a stranger sharing the beginning of one would otherwise have its space handed
// to the domain's owner.
func TestRangesChecksTheOrganizationAgainstTheContacts(t *testing.T) {
	t.Parallel()

	data := cloudflare()
	// An organisation the name search finds whose contacts are nobody the domain search did.
	data.organizations["Cloudflare*"] = []string{"CLOUDS-9", "CLOUD14"}
	data.organizationPersons["CLOUDS-9"] = []string{"STRANGER1-ARIN"}
	data.organizationNets["CLOUDS-9"] = []string{netRef("NET-198-51-100-0-1", "SOMEONE-ELSE", "198.51.100.0", "198.51.100.255")}

	ranges, err := serverClient(t, data.handler(t)).Ranges(t.Context(), "cloudflare.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slices.Contains(networksOf(ranges), "198.51.100.0/24") {
		t.Errorf("expected the stranger's space left alone, got %v", networksOf(ranges))
	}
	if !slices.Contains(networksOf(ranges), "104.16.0.0/12") {
		t.Errorf("expected the checked organisation kept, got %v", networksOf(ranges))
	}

	// It was rejected on its contacts rather than skipped, so its ranges were never asked for.
	if slices.ContainsFunc(data.asked, func(path string) bool {
		return strings.Contains(path, "CLOUDS-9/nets")
	}) {
		t.Errorf("expected the rejected organisation's ranges never asked for, got %v", data.asked)
	}
}

// TestPersonsChecksTheEmailDomain holds the confirmation. The contact search is ARIN's own search
// over e-mail addresses, so this is defence in depth rather than the only guard -- but it is the
// one thing standing between a match and attributing a stranger's address space to a customer.
func TestPersonsChecksTheEmailDomain(t *testing.T) {
	t.Parallel()

	data := cloudflare()
	data.personHandles = append(data.personHandles, "OTHER1-ARIN")
	data.persons["OTHER1-ARIN"] = personObject("OTHER1-ARIN", "Other", "Elsewhere", "ops@example.com")

	persons, err := serverClient(t, data.handler(t)).Persons(t.Context(), "cloudflare.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handles := make([]string, 0, len(persons))
	for _, person := range persons {
		handles = append(handles, person.Handle)
	}

	if !slices.Equal(handles, []string{"ABUSE2916-ARIN", "ADMIN2521-ARIN"}) {
		t.Errorf("expected only the contacts at the domain, got %v", handles)
	}
}

// TestPersonsIsBounded holds why the bound is there: the search answers with handles alone, so
// every hit is a request of its own.
func TestPersonsIsBounded(t *testing.T) {
	t.Parallel()

	data := cloudflare()
	client := serverClient(t, data.handler(t), arin_config.WithMaxPersons(1))

	persons, err := client.Persons(t.Context(), "cloudflare.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(persons) != 1 {
		t.Errorf("expected the bound to hold, got %d", len(persons))
	}
}

// TestPersonsBoundsWhatItReadsRatherThanWhatItKeeps holds which of the two the bound counts. A
// search answers with as many as 256 hits, and a bound counting only the contacts that survive the
// e-mail check would read every one of them whenever few do -- which is the case where being gentle
// with the database matters most.
func TestPersonsBoundsWhatItReadsRatherThanWhatItKeeps(t *testing.T) {
	t.Parallel()

	data := cloudflare()
	// The first hit is a contact the check will reject, so a bound counting survivors would carry
	// on to the next.
	data.personHandles = append([]string{"OTHER1-ARIN"}, data.personHandles...)
	data.persons["OTHER1-ARIN"] = personObject("OTHER1-ARIN", "Other", "Elsewhere", "ops@example.com")

	client := serverClient(t, data.handler(t), arin_config.WithMaxPersons(1))

	persons, err := client.Persons(t.Context(), "cloudflare.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(persons) != 0 {
		t.Errorf("expected the bound to stop the walk, got %+v", persons)
	}

	// The search, and the one contact the bound allowed.
	if len(data.asked) != 2 {
		t.Errorf("expected two requests, got %v", data.asked)
	}
}

// TestRangesIsBoundedByOrganizations holds the other bound: a short name matches a great many
// organisations, and each one is two further requests.
func TestRangesIsBoundedByOrganizations(t *testing.T) {
	t.Parallel()

	data := cloudflare()
	data.organizations["Cloudflare*"] = []string{"OTHER-1", "OTHER-2", "CLOUD14"}
	data.organizationPersons["OTHER-1"] = []string{"STRANGER1-ARIN"}
	data.organizationPersons["OTHER-2"] = []string{"STRANGER2-ARIN"}

	client := serverClient(t, data.handler(t), arin_config.WithMaxOrganizations(2))

	ranges, err := client.Ranges(t.Context(), "cloudflare.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The bound fell before the organisation that would have answered, which is what a bound does.
	if len(ranges) != 0 {
		t.Errorf("expected the bound to hold, got %v", networksOf(ranges))
	}
	if slices.ContainsFunc(data.asked, func(path string) bool {
		return strings.Contains(path, "CLOUD14")
	}) {
		t.Errorf("expected nothing past the bound to be asked for, got %v", data.asked)
	}
}

// TestRangesWithoutContacts holds that a domain ARIN knows nothing about is an answer rather than a
// failure: a party registered with another registry is not found here, and most are not.
func TestRangesWithoutContacts(t *testing.T) {
	t.Parallel()

	data := &database{}

	ranges, err := serverClient(t, data.handler(t)).Ranges(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ranges) != 0 {
		t.Errorf("expected nothing, got %+v", ranges)
	}

	// Nothing was searched for past the contacts, there being nothing to search with.
	if len(data.asked) != 1 {
		t.Errorf("expected the walk to stop at the contacts, got %v", data.asked)
	}
}

// TestListDecodesOneAndSeveral holds what the mapping from XML costs. A document with one <pocRef>
// child and a document with several are the same document to a reader that walks elements, and the
// difference only appears once it has been rendered as JSON -- so a search narrow enough to match
// exactly what was asked for answers with a shape a plain slice cannot read.
func TestListDecodesOneAndSeveral(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		body   string
		expect []string
	}{
		{name: "one", body: `{"orgs":{"orgRef":{"@handle":"A"}}}`, expect: []string{"A"}},
		{name: "several", body: `{"orgs":{"orgRef":[{"@handle":"A"},{"@handle":"B"}]}}`, expect: []string{"A", "B"}},
		{name: "none", body: `{"orgs":{}}`, expect: []string{}},
		{name: "null", body: `{"orgs":{"orgRef":null}}`, expect: []string{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if _, err := fmt.Fprint(writer, testCase.body); err != nil {
					t.Errorf("could not write: %v", err)
				}
			})

			organizations, err := client.Organizations(t.Context(), "Example")
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			handles := make([]string, 0, len(organizations))
			for _, organization := range organizations {
				handles = append(handles, organization.Handle)
			}

			if !slices.Equal(handles, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, handles)
			}
		})
	}
}

// TestSearchNames holds the bridge. ARIN has no search from a domain to an organisation, so the
// name is what carries the walk across, and it is read off the contacts rather than guessed.
func TestSearchNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		domain    string
		companies []string
		expect    []string
	}{
		{
			// Trimmed at the comma, the search being a prefix search: "Cloudflare" reaches the
			// organisation registered as "Cloudflare, Inc." and the one registered as "Cloudflare".
			// The domain's own label is the same name here, and the search does not distinguish
			// case, so it is not searched for twice.
			name:      "the company, trimmed at the comma",
			domain:    "cloudflare.com",
			companies: []string{"Cloudflare, Inc."},
			expect:    []string{"Cloudflare"},
		},
		{
			name:      "the same company given twice",
			domain:    "cloudflare.com",
			companies: []string{"Cloudflare, Inc.", "Cloudflare, Inc", "Cloudflare"},
			expect:    []string{"Cloudflare"},
		},
		{
			// A contact that left the company out, or gave a person's name, still has the domain to
			// fall back on.
			name:      "no company at all",
			domain:    "example.co.uk",
			companies: []string{""},
			expect:    []string{"example"},
		},
		{
			// Sorted, so that the bound on how many organisations are checked falls in the same
			// place on every run rather than wherever the search happened to order its hits.
			name:      "several companies, sorted",
			domain:    "example.com",
			companies: []string{"Zeta", "Alpha"},
			expect:    []string{"Alpha", "Zeta", "example"},
		},
		{name: "no contacts", domain: "example.com", companies: nil, expect: []string{"example"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := SearchNames(testCase.domain, testCase.companies)
			if !slices.Equal(got, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

// TestSearchTermIsEscaped holds that a term is a value rather than part of the path. ARIN takes a
// search term as a matrix parameter, so a term holding a slash or a semicolon would otherwise
// address something else entirely.
func TestSearchTermIsEscaped(t *testing.T) {
	t.Parallel()

	var asked string

	client := serverClient(t, func(writer http.ResponseWriter, request *http.Request) {
		asked = request.URL.EscapedPath()
		writer.WriteHeader(http.StatusNotFound)
	})

	if _, err := client.Organizations(t.Context(), "a/b;c"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(strings.TrimPrefix(asked, OrganizationSearchPath+";name="), "/") {
		t.Errorf("expected the term escaped, got %q", asked)
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Persons(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Person(t.Context(), "AA1-ARIN"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Organizations(t.Context(), "Example"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.OrganizationPersons(t.Context(), "EX-1"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.OrganizationRanges(t.Context(), "EX-1"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Ranges(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}

	client := NewClient()
	if _, err := client.Persons(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if _, err := client.Person(t.Context(), ""); err == nil {
		t.Error("expected an empty handle to be an error")
	}
	if _, err := client.Organizations(t.Context(), ""); err == nil {
		t.Error("expected an empty name to be an error")
	}
	if _, err := client.OrganizationPersons(t.Context(), ""); err == nil {
		t.Error("expected an empty handle to be an error")
	}
	if _, err := client.OrganizationRanges(t.Context(), ""); err == nil {
		t.Error("expected an empty handle to be an error")
	}
	if _, err := client.Ranges(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}
}
