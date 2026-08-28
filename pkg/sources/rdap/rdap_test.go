package rdap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap/rdap_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

func serverClient(t *testing.T, handler http.HandlerFunc, options ...rdap_config.Option) *Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewClient(
		slices.Concat(
			[]rdap_config.Option{
				rdap_config.WithBaseUrl(serverUrl),
				rdap_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
			},
			options,
		)...,
	)
}

// card renders a jCard: the two levels of array RDAP wraps a contact card in.
func card(name string, kind string, address string) string {
	return fmt.Sprintf(
		`["vcard",[["version",{},"text","4.0"],["fn",{},"text",%q],["kind",{},"text",%q],`+
			`["adr",{"label":"a street"},"text",["","","","","","",""]],["email",{},"text",%q]]]`,
		name, kind, address,
	)
}

func entityJson(handle string, name string, kind string, address string, networks string) string {
	body := fmt.Sprintf(`{"handle":%q,"vcardArray":%s`, handle, card(name, kind, address))
	if networks != "" {
		body += `,"networks":[` + networks + `]`
	}

	return body + "}"
}

func networkJson(handle string, name string, prefix string, length int) string {
	return fmt.Sprintf(
		`{"handle":%q,"name":%q,"country":"SE","cidr0_cidrs":[{"v4prefix":%q,"length":%d}]}`,
		handle, name, prefix, length,
	)
}

// database is a live run reduced to what the walk needs: a name search that reaches the domain's own
// party and a stranger, and the parties themselves with their ranges.
type database struct {
	search   map[string][]string
	entities map[string]string

	asked []string
	lock  sync.Mutex
}

func (data *database) paths() []string {
	data.lock.Lock()
	defer data.lock.Unlock()

	return slices.Clone(data.asked)
}

func (data *database) handler(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(writer http.ResponseWriter, request *http.Request) {
		data.lock.Lock()
		data.asked = append(data.asked, request.URL.RequestURI())
		data.lock.Unlock()

		writer.Header().Set("Content-Type", ContentType)

		if strings.HasPrefix(request.URL.Path, EntitySearchPath) {
			results, ok := data.search[request.URL.Query().Get("fn")]
			if !ok {
				// Some of these servers answer a search that matched nothing with a 404 and some
				// with an empty result. Both have to be read as the same answer.
				writer.WriteHeader(http.StatusNotFound)

				return
			}

			if _, err := fmt.Fprintf(writer, `{"entitySearchResults":[%s]}`, strings.Join(results, ",")); err != nil {
				t.Errorf("could not write: %v", err)
			}

			return
		}

		body, ok := data.entities[strings.TrimPrefix(request.URL.Path, EntityPath+"/")]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}
}

func example() *database {
	return &database{
		search: map[string][]string{
			"Example": {
				// A search answers with the party's people as readily as with the party, and
				// without the ranges.
				entityJson("EP1-EXAMPLE", "Example Person", "individual", "ops@example.com", ""),
				entityJson("ORG-EX1", "Example Ltd", "org", "noc@example.com", ""),
				// A stranger the name happened to reach.
				entityJson("ORG-EX2", "Example Unrelated Ltd", "org", "noc@elsewhere.test", ""),
			},
		},
		entities: map[string]string{
			"EP1-EXAMPLE": entityJson("EP1-EXAMPLE", "Example Person", "individual", "ops@example.com", ""),
			"ORG-EX1": entityJson("ORG-EX1", "Example Ltd", "org", "noc@example.com",
				networkJson("NET-1", "EXAMPLE-NET", "192.0.2.0", 24)),
			"ORG-EX2": entityJson("ORG-EX2", "Example Unrelated Ltd", "org", "noc@elsewhere.test",
				networkJson("NET-2", "SOMEONE-ELSE", "198.51.100.0", 24)),
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

// TestRanges holds the whole walk: a name reaches parties, and the address on the contact card is
// what says which of them the domain may claim.
func TestRanges(t *testing.T) {
	t.Parallel()

	data := example()

	ranges, err := serverClient(t, data.handler(t)).Ranges(t.Context(), "example.com", []string{"Example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24"}) {
		t.Fatalf("expected the domain's range alone, got %v", networksOf(ranges))
	}

	if ranges[0].NetName != "EXAMPLE-NET" || ranges[0].Country != "SE" {
		t.Errorf("expected the server's detail kept, got %+v", ranges[0])
	}
	if ranges[0].Entity == nil || ranges[0].Entity.Handle != "ORG-EX1" {
		t.Errorf("expected the party kept, got %+v", ranges[0].Entity)
	}
}

// TestRangesChecksTheCard holds the check the name search forces. A name is a poor thing to
// attribute address space on, and a stranger sharing one would otherwise have its space handed to
// the domain's owner.
func TestRangesChecksTheCard(t *testing.T) {
	t.Parallel()

	data := example()

	ranges, err := serverClient(t, data.handler(t)).Ranges(t.Context(), "example.com", []string{"Example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if slices.Contains(networksOf(ranges), "198.51.100.0/24") {
		t.Errorf("expected the stranger's space left alone, got %v", networksOf(ranges))
	}

	// The card on the search result was enough to drop it, so it was never read in full.
	if slices.ContainsFunc(data.paths(), func(path string) bool {
		return strings.Contains(path, EntityPath+"/ORG-EX2")
	}) {
		t.Errorf("expected the stranger never read, got %v", data.paths())
	}
}

// TestRangesReadsOrganizationsFirst holds the ordering. Only organisations hold allocations -- a
// person or a role is a contact on one -- so without this the bound would routinely be spent on
// contacts before it reached the organisation that had the ranges.
func TestRangesReadsOrganizationsFirst(t *testing.T) {
	t.Parallel()

	data := example()

	// Room for one party only, and the search answers with the person first.
	client := serverClient(t, data.handler(t), rdap_config.WithMaxEntities(1))

	ranges, err := client.Ranges(t.Context(), "example.com", []string{"Example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24"}) {
		t.Errorf("expected the organisation reached within the bound, got %v", networksOf(ranges))
	}
}

// TestEntitiesAppendsTheNameSuffix holds what the setting is for: the registries do not agree on how
// a name search matches, and the same term has to be written two ways.
func TestEntitiesAppendsTheNameSuffix(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		suffix string
		expect string
	}{
		{name: "a server matching a prefix", suffix: ApnicNameSuffix, expect: "Example*"},
		{name: "a server matching a token", suffix: "", expect: "Example"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var asked string

			client := serverClient(
				t,
				func(writer http.ResponseWriter, request *http.Request) {
					asked = request.URL.Query().Get("fn")
					writer.WriteHeader(http.StatusNotFound)
				},
				rdap_config.WithNameSuffix(testCase.suffix),
			)

			if _, err := client.Entities(t.Context(), "Example"); err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			if asked != testCase.expect {
				t.Errorf("%s: expected %q, got %q", testCase.name, testCase.expect, asked)
			}
		})
	}
}

// TestEntityNetworks holds the two ways a server writes an allocation. The cidr0 extension is the
// server's own answer and is preferred; the two addresses are what a server without it writes, and
// an arbitrary range of addresses is not one prefix.
func TestEntityNetworks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		network string
		expect  []string
	}{
		{
			name:    "the cidr0 extension",
			network: `{"handle":"NET-1","cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}]}`,
			expect:  []string{"192.0.2.0/24"},
		},
		{
			name:    "a v6 prefix",
			network: `{"handle":"NET-1","cidr0_cidrs":[{"v6prefix":"2001:db8::","length":32}]}`,
			expect:  []string{"2001:db8::/32"},
		},
		{
			name:    "two addresses, where the extension is absent",
			network: `{"handle":"NET-1","startAddress":"192.0.2.0","endAddress":"192.0.2.255"}`,
			expect:  []string{"192.0.2.0/24"},
		},
		{
			// The case the conversion exists for: a range that is not one prefix.
			name:    "an unaligned range",
			network: `{"handle":"NET-1","startAddress":"10.0.0.1","endAddress":"10.0.0.2"}`,
			expect:  []string{"10.0.0.1/32", "10.0.0.2/32"},
		},
		{
			name:    "neither",
			network: `{"handle":"NET-1"}`,
			expect:  []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			client := serverClient(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", ContentType)
				body := fmt.Sprintf(
					`{"handle":"ORG-1","vcardArray":%s,"networks":[%s]}`,
					card("Example Ltd", "org", "noc@example.com"),
					testCase.network,
				)
				if _, err := fmt.Fprint(writer, body); err != nil {
					t.Errorf("could not write: %v", err)
				}
			})

			found, err := client.Entity(t.Context(), "ORG-1")
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if found == nil {
				t.Fatalf("%s: expected a party", testCase.name)
			}

			got := make([]string, 0)
			for _, item := range found.Ranges {
				got = append(got, item.Networks...)
			}

			if !slices.Equal(got, testCase.expect) {
				t.Errorf("%s: expected %v, got %v", testCase.name, testCase.expect, got)
			}
		})
	}
}

// TestVcardProperty holds the shape a contact card arrives in. RDAP renders it as jCard: an array
// whose first element is the string "vcard" and whose second is the properties, each of them an
// array of four.
func TestVcardProperty(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		card     []any
		property string
		expect   string
	}{
		{
			name:     "a property that is there",
			card:     []any{"vcard", []any{[]any{"email", map[string]any{}, "text", "noc@example.com"}}},
			property: "email",
			expect:   "noc@example.com",
		},
		{
			// A property whose value is not a string is skipped rather than read: an address is
			// written as an array of its lines, and reading it as a string would panic.
			name: "a property whose value is an array",
			card: []any{"vcard", []any{
				[]any{"adr", map[string]any{}, "text", []any{"", "a street"}},
				[]any{"email", map[string]any{}, "text", "noc@example.com"},
			}},
			property: "email",
			expect:   "noc@example.com",
		},
		{
			name:     "an address read as a string",
			card:     []any{"vcard", []any{[]any{"adr", map[string]any{}, "text", []any{"", "a street"}}}},
			property: "adr",
			expect:   "",
		},
		{
			name:     "a property that is not there",
			card:     []any{"vcard", []any{[]any{"fn", map[string]any{}, "text", "Example"}}},
			property: "email",
			expect:   "",
		},
		{name: "no card at all", card: nil, property: "email", expect: ""},
		{name: "a card with nothing in it", card: []any{"vcard"}, property: "email", expect: ""},
		{
			name:     "a property too short to hold a value",
			card:     []any{"vcard", []any{[]any{"email", map[string]any{}, "text"}}},
			property: "email",
			expect:   "",
		},
		{
			name:     "the properties are not an array",
			card:     []any{"vcard", "not an array"},
			property: "email",
			expect:   "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := vcardProperty(testCase.card, testCase.property); got != testCase.expect {
				t.Errorf("%s: expected %q, got %q", testCase.name, testCase.expect, got)
			}
		})
	}
}

// TestRangesIsBoundedByNames holds why the bound is there: each name is a search of its own, and a
// caller handing over every company its other registries turned up would otherwise make as many.
func TestRangesIsBoundedByNames(t *testing.T) {
	t.Parallel()

	data := example()
	client := serverClient(t, data.handler(t), rdap_config.WithMaxNames(1))

	if _, err := client.Ranges(t.Context(), "example.com", []string{"Example", "Second", "Third"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	searches := 0
	for _, path := range data.paths() {
		if strings.HasPrefix(path, EntitySearchPath) {
			searches++
		}
	}

	if searches != 1 {
		t.Errorf("expected one search, got %d: %v", searches, data.paths())
	}
}

// TestSearchWithoutResults holds that a name matching nothing is an answer. Most names do.
func TestSearchWithoutResults(t *testing.T) {
	t.Parallel()

	data := example()

	ranges, err := serverClient(t, data.handler(t)).Ranges(t.Context(), "example.com", []string{"Nobody"})
	if err != nil {
		t.Fatalf("expected a search matching nothing to be an answer, got %v", err)
	}
	if len(ranges) != 0 {
		t.Errorf("expected nothing, got %v", networksOf(ranges))
	}
}

func TestArgumentChecks(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if _, err := nilClient.Entities(t.Context(), "Example"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Entity(t.Context(), "ORG-1"); err == nil {
		t.Error("expected a nil client to be an error")
	}
	if _, err := nilClient.Ranges(t.Context(), "example.com", nil); err == nil {
		t.Error("expected a nil client to be an error")
	}

	client := NewClient(rdap_config.WithBaseUrl(ApnicBaseUrl))
	if _, err := client.Entities(t.Context(), ""); err == nil {
		t.Error("expected an empty name to be an error")
	}
	if _, err := client.Entity(t.Context(), ""); err == nil {
		t.Error("expected an empty handle to be an error")
	}
	if _, err := client.Ranges(t.Context(), "", nil); err == nil {
		t.Error("expected an empty domain to be an error")
	}

	// A client with no server has none it could sensibly mean, and says so rather than guessing.
	withoutServer := NewClient()
	if _, err := withoutServer.Entities(t.Context(), "Example"); err == nil {
		t.Error("expected a client without a base url to be an error")
	}
	if _, err := withoutServer.Entity(t.Context(), "ORG-1"); err == nil {
		t.Error("expected a client without a base url to be an error")
	}
}
