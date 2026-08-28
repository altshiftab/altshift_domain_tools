package ripe

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe/ripe_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func serverClient(t *testing.T, handler http.HandlerFunc, options ...ripe_config.Option) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewClient(
		slices.Concat(
			[]ripe_config.Option{
				ripe_config.WithBaseUrl(serverUrl),
				ripe_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
			},
			options,
		)...,
	)
}

// person renders one full-text search hit.
func person(handle string, name string, email string) string {
	return fmt.Sprintf(
		`{"doc":{"strs":[
			{"str":{"name":"object-type","value":"person"}},
			{"str":{"name":"nic-hdl","value":%q}},
			{"str":{"name":"person","value":%q}},
			{"str":{"name":"e-mail","value":%q}}
		]}}`,
		handle, name, email,
	)
}

// role renders a contact that is a job rather than somebody. It carries a nic-hdl like a person and
// no person attribute, which is the whole of the difference here.
func role(handle string, name string, email string) string {
	return fmt.Sprintf(
		`{"doc":{"strs":[
			{"str":{"name":"object-type","value":"role"}},
			{"str":{"name":"nic-hdl","value":%q}},
			{"str":{"name":"role","value":%q}},
			{"str":{"name":"e-mail","value":%q}}
		]}}`,
		handle, name, email,
	)
}

// organization renders the party a range belongs to, which is named by its own attribute rather
// than by a nic-hdl.
func organization(handle string, name string, email string) string {
	return fmt.Sprintf(
		`{"doc":{"strs":[
			{"str":{"name":"object-type","value":"organisation"}},
			{"str":{"name":"organisation","value":%q}},
			{"str":{"name":"org-name","value":%q}},
			{"str":{"name":"e-mail","value":%q}}
		]}}`,
		handle, name, email,
	)
}

// TestPersonsChecksTheEmailDomain holds what a live run showed: the full-text search matches the
// domain anywhere in an object, so a person whose postal address or remarks mention it comes back
// alongside the ones whose e-mail is actually there. Attributing a stranger's address space to a
// customer on that basis would be a serious error.
func TestPersonsChecksTheEmailDomain(t *testing.T) {
	t.Parallel()

	var asked url.Values

	client := serverClient(t, func(writer http.ResponseWriter, request *http.Request) {
		asked = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		body := `{"result":{"numFound":4,"docs":[` +
			person("AA1-RIPE", "At The Domain", "someone@example.com") + "," +
			person("BB2-RIPE", "At A Subdomain", "ops@mail.example.com") + "," +
			// The live case: matched the domain elsewhere in the object, not in its address.
			person("CC3-RIPE", "Mentions It", "someone@unrelated.test") + "," +
			person("DD4-RIPE", "Ends The Same Way", "someone@notexample.com") +
			`]}}`
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	})

	persons, err := client.Persons(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handles := make([]string, 0, len(persons))
	for _, item := range persons {
		handles = append(handles, item.NicHandle)
	}

	if !slices.Equal(handles, []string{"AA1-RIPE", "BB2-RIPE"}) {
		t.Errorf("expected only the contacts actually at the domain, got %v", handles)
	}

	// Roles and organisations as well as people: a range is as often registered to "Example NOC" as
	// to somebody, and an inetnum's org is the party that holds it.
	q := asked.Get("q")
	for _, objectType := range ObjectTypes {
		if !strings.Contains(q, "object-type:"+objectType) {
			t.Errorf("expected %s objects searched for, got %q", objectType, q)
		}
	}

	// Asked for, because the database answers with ten unless it is -- which for a party of any
	// size is the first ten of something rather than what it holds.
	if rows := asked.Get("rows"); rows != strconv.Itoa(DefaultSearchRows) {
		t.Errorf("expected the hits asked for, got %q", rows)
	}
}

// TestRegistrantsReadsRolesAndOrganizations holds the two kinds of object a person search misses. A
// role is a contact like any other, and an organisation is the party a range belongs to rather than
// somebody to write to about it.
func TestRegistrantsReadsRolesAndOrganizations(t *testing.T) {
	t.Parallel()

	client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		body := `{"result":{"numFound":4,"docs":[` +
			person("AA1-RIPE", "A Person", "someone@example.com") + "," +
			role("NOC1-RIPE", "Example NOC", "noc@example.com") + "," +
			organization("ORG-EX1-RIPE", "Example Ltd", "ripe@example.com") + "," +
			// A stranger the search matched, whatever kind of object it is.
			organization("ORG-EX2-RIPE", "Elsewhere Ltd", "ripe@elsewhere.test") +
			`]}}`
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	})

	registrants, err := client.Registrants(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handles := make([]string, 0, len(registrants.Persons))
	for _, item := range registrants.Persons {
		handles = append(handles, item.NicHandle)
	}

	if !slices.Equal(handles, []string{"AA1-RIPE", "NOC1-RIPE"}) {
		t.Errorf("expected the role kept alongside the person, got %v", handles)
	}
	// A role has no person attribute, being a job rather than somebody.
	if len(registrants.Persons) == 2 && registrants.Persons[1].Name != "Example NOC" {
		t.Errorf("expected the role's name, got %q", registrants.Persons[1].Name)
	}

	if len(registrants.Organizations) != 1 || registrants.Organizations[0].Handle != "ORG-EX1-RIPE" {
		t.Errorf("expected only the organisation at the domain, got %+v", registrants.Organizations)
	}
	if len(registrants.Organizations) == 1 && registrants.Organizations[0].Name != "Example Ltd" {
		t.Errorf("expected the organisation's name, got %+v", registrants.Organizations[0])
	}
}

// TestOrganizations holds the convenience the other half of a search deserves. Registrants answers
// with both kinds of object, and a caller wanting one of them should not have to sort them itself.
func TestOrganizations(t *testing.T) {
	t.Parallel()

	client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		body := `{"result":{"numFound":2,"docs":[` +
			person("AA1-RIPE", "A Person", "someone@example.com") + "," +
			organization("ORG-EX1-RIPE", "Example Ltd", "ripe@example.com") +
			`]}}`
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	})

	organizations, err := client.Organizations(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(organizations) != 1 || organizations[0].Handle != "ORG-EX1-RIPE" {
		t.Errorf("expected the organisation alone, got %+v", organizations)
	}
}

// TestOrganizationRanges holds the other inverse search. An inetnum's org is the party that holds
// it, where its administrative and technical contacts may be a provider's staff.
func TestOrganizationRanges(t *testing.T) {
	t.Parallel()

	var asked url.Values

	client := serverClient(t, func(writer http.ResponseWriter, request *http.Request) {
		asked = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		body := `{"objects":{"object":[
			{"attributes":{"attribute":[
				{"name":"inet6num","value":"2001:db8::/32"},
				{"name":"netname","value":"EXAMPLE-V6"}
			]}}
		]}}`
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	})

	ranges, err := client.OrganizationRanges(t.Context(), "ORG-EX1-RIPE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 1 || !slices.Equal(ranges[0].Networks, []string{"2001:db8::/32"}) {
		t.Fatalf("expected the allocation as CIDR, got %+v", ranges)
	}

	if got := asked["inverse-attribute"]; !slices.Equal(got, OrganizationInverseAttributes) {
		t.Errorf("expected the org inverse, got %v", got)
	}
}

// TestPersonsStopsAtTheBound holds why the bound exists: every handle becomes a query of its own,
// so the two steps multiply.
func TestPersonsStopsAtTheBound(t *testing.T) {
	t.Parallel()

	client := serverClient(
		t,
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			docs := make([]string, 0, 10)
			for index := range 10 {
				docs = append(docs, person(fmt.Sprintf("H%d-RIPE", index), "Someone", "a@example.com"))
			}
			body := `{"result":{"numFound":10,"docs":[` + joinComma(docs) + `]}}`
			if _, err := fmt.Fprint(writer, body); err != nil {
				t.Errorf("could not write: %v", err)
			}
		},
		ripe_config.WithMaxPersons(3),
	)

	persons, err := client.Persons(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(persons) != 3 {
		t.Errorf("expected the bound to hold, got %d", len(persons))
	}
}

func joinComma(items []string) string {
	joined := ""
	for index, item := range items {
		if index != 0 {
			joined += ","
		}
		joined += item
	}

	return joined
}

func TestRanges(t *testing.T) {
	t.Parallel()

	var asked url.Values

	client := serverClient(t, func(writer http.ResponseWriter, request *http.Request) {
		asked = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		body := `{"objects":{"object":[
			{"attributes":{"attribute":[
				{"name":"inetnum","value":"193.10.7.0 - 193.10.7.255"},
				{"name":"netname","value":"SE-SPTIME"},
				{"name":"status","value":"ASSIGNED PA"},
				{"name":"country","value":"SE"}
			]}}
		]}}`
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	})

	ranges, err := client.Ranges(t.Context(), "BJN1-RIPE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 1 {
		t.Fatalf("expected one range, got %d", len(ranges))
	}
	if !slices.Equal(ranges[0].Networks, []string{"193.10.7.0/24"}) {
		t.Errorf("expected the range as CIDR, got %v", ranges[0].Networks)
	}
	if ranges[0].NetName != "SE-SPTIME" {
		t.Errorf("expected the registry's name for it, got %+v", ranges[0])
	}

	// Every role: a party administering a range, one operating it and one taking the complaints
	// about it are equally good evidence that the space is theirs.
	if inverse := asked["inverse-attribute"]; !slices.Equal(inverse, PersonInverseAttributes) {
		t.Errorf("expected every role to be searched, got %v", inverse)
	}

	// Both families. This is the one that was wrong: a filter naming only inetnum excludes inet6num
	// rather than covering it, so a party holding v6 space looked as though it held none.
	if filters := asked["type-filter"]; !slices.Equal(filters, TypeFilters) {
		t.Errorf("expected both address families, got %v", filters)
	}
}

// TestRangesWhenNothingIsRegistered holds that a handle with no ranges is an answer rather than a
// failure. The database says so with a 404.
func TestRangesWhenNothingIsRegistered(t *testing.T) {
	t.Parallel()

	client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	})

	ranges, err := client.Ranges(t.Context(), "ZZ9-RIPE")
	if err != nil {
		t.Fatalf("expected a 404 to be an empty answer, got %v", err)
	}
	if len(ranges) != 0 {
		t.Errorf("expected nothing, got %+v", ranges)
	}
}

// TestNetworks holds the conversion the registry forces. It writes an allocation as a first and
// last address, and an arbitrary range of addresses is not one prefix.
func TestNetworks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		inetnum     string
		expect      []string
		expectError bool
	}{
		{name: "a range that is one prefix", inetnum: "193.10.7.0 - 193.10.7.255", expect: []string{"193.10.7.0/24"}},
		{name: "a large range", inetnum: "130.237.0.0 - 130.237.255.255", expect: []string{"130.237.0.0/16"}},
		{name: "a single address", inetnum: "10.0.0.0 - 10.0.0.0", expect: []string{"10.0.0.0/32"}},
		{
			// The case that makes this more than a string rewrite: an unaligned range needs
			// several prefixes to cover it exactly, and the alternative -- one prefix too large --
			// would attribute addresses the party does not hold.
			name:    "an unaligned range needs several prefixes",
			inetnum: "10.0.0.1 - 10.0.0.6",
			expect:  []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"},
		},
		{name: "already a prefix", inetnum: "192.0.2.0/24", expect: []string{"192.0.2.0/24"}},
		// An inet6num is written as a prefix rather than as two addresses, so it is the no-dash case.
		{name: "an inet6num", inetnum: "2001:db8::/32", expect: []string{"2001:db8::/32"}},
		// A v6 allocation written as two addresses is covered like any other. It used to be dropped,
		// which made a party holding v6 space look as though it held none.
		{
			name:    "a v6 range",
			inetnum: "2606:4700:: - 2606:4700:ffff:ffff:ffff:ffff:ffff:ffff",
			expect:  []string{"2606:4700::/32"},
		},
		{name: "not a range at all", inetnum: "nonsense", expectError: true},
		{name: "the end before the start", inetnum: "10.0.0.6 - 10.0.0.1", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := Networks(testCase.inetnum)

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

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Persons(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Ranges(t.Context(), "AA1-RIPE"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := NewClient().Persons(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}
	if _, err := NewClient().Ranges(t.Context(), ""); err == nil {
		t.Error("expected an empty nic handle to be an error")
	}
}
