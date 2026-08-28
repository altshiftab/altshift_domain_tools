package finder

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/finder/finder_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/network_range/spf"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/arin/arin_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/rdap/rdap_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripe/ripe_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripestat"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/ripestat/ripestat_config"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois"
	"github.com/altshiftab/altshift_domain_tools/pkg/sources/whois/whois_config"
	"github.com/altshiftab/utils_go/pkg/http/types/fetch_config"
)

type stubResolver struct {
	records     map[string][]string
	nameServers map[string][]string
	addresses   map[string][]string

	lock sync.Mutex
}

func (stub *stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	records, ok := stub.records[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	return records, nil
}

// The reverse-delegation walk asks for these, and the stub answers with nothing rather than leaving
// the finder to fall back on the real resolver -- which would have every run of the test suite
// query the DNS about whatever the test made up.
func (stub *stubResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	nameServers, ok := stub.nameServers[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}

	found := make([]*net.NS, 0, len(nameServers))
	for _, host := range nameServers {
		found = append(found, &net.NS{Host: host})
	}

	return found, nil
}

func (stub *stubResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	stub.lock.Lock()
	defer stub.lock.Unlock()

	addresses, ok := stub.addresses[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	found := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		found = append(found, netip.MustParseAddr(address))
	}

	return found, nil
}

// newFinder stands the registries up on a test server and gives the walk a stubbed resolver.
//
// Both are pointed at the server rather than only the one a test is about: a client the finder
// builds for itself talks to the live database, so leaving one unset would have every run of the
// test suite query a registry that asks callers to be gentle -- and answer from whatever that
// registry happens to hold for the domain the test made up.
func newFinder(t *testing.T, handler http.HandlerFunc, records map[string][]string) *Finder {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	return NewFinder(
		finder_config.WithRipe(ripe.NewClient(
			ripe_config.WithBaseUrl(serverUrl),
			ripe_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		finder_config.WithArin(arin.NewClient(
			arin_config.WithBaseUrl(serverUrl),
			arin_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		// Supplying one confines the run to what was supplied, which is what keeps the registries
		// this test is not about off the network entirely.
		finder_config.WithRdap(MethodApnic, rdap.NewClient(
			rdap_config.WithBaseUrl(serverUrl),
			rdap_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		// Pointed at the server even where a test turns up no networks to ask about, because a
		// fixture that later does would otherwise reach the live service without anyone noticing.
		finder_config.WithRipestat(ripestat.NewClient(
			ripestat_config.WithBaseUrl(serverUrl),
			ripestat_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		finder_config.WithResolver(&stubResolver{records: records}),
	)
}

// whoisServer stands a whois service up on a port of the operating system's choosing, and answers
// the two queries the abuse mailbox route makes.
func whoisServer(t *testing.T, answer func(query string) string) *whois.Client {
	t.Helper()

	listenConfig := &net.ListenConfig{}

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() {
					_ = connection.Close()
				}()

				query, err := bufio.NewReader(connection).ReadString('\n')
				if err != nil {
					return
				}

				_, _ = connection.Write([]byte(answer(strings.TrimRight(query, "\r\n"))))
			}()
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("could not split the address: %v", err)
	}

	return whois.NewClient(host, whois_config.WithPort(port))
}

// registryHandler answers both RIPE steps: the person search, then the ranges. ARIN is answered
// with nothing, so that a test about the one registry is about the one registry.
func registryHandler(t *testing.T, inetnum string) http.HandlerFunc {
	t.Helper()

	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")

		// ARIN's paths all begin here, and a search that matched nothing is a 404 rather than an
		// empty result. The RDAP paths are answered the same way, so that a test about the one
		// registry is about the one registry.
		if strings.HasPrefix(request.URL.Path, "/rest/") ||
			strings.HasPrefix(request.URL.Path, "/entities") ||
			strings.HasPrefix(request.URL.Path, "/entity/") {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		if strings.Contains(request.URL.Path, "fulltextsearch") {
			body := `{"result":{"numFound":1,"docs":[{"doc":{"strs":[
				{"str":{"name":"nic-hdl","value":"AA1-RIPE"}},
				{"str":{"name":"e-mail","value":"ops@example.com"}}
			]}}]}}`
			if _, err := fmt.Fprint(writer, body); err != nil {
				t.Errorf("could not write: %v", err)
			}

			return
		}

		body := fmt.Sprintf(`{"objects":{"object":[{"attributes":{"attribute":[
			{"name":"inetnum","value":%q},
			{"name":"netname","value":"EXAMPLE-NET"},
			{"name":"status","value":"ASSIGNED PA"}
		]}}]}}`, inetnum)
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}
}

// registriesHandler answers both registries from one server, so that a test can say what each of
// them holds. The ARIN walk is four requests to RIPE's two, which is what the switch is.
func registriesHandler(t *testing.T, inetnum string, first string, last string) http.HandlerFunc {
	t.Helper()

	write := func(writer http.ResponseWriter, body string) {
		writer.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}

	return func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path

		switch {
		case strings.Contains(path, "fulltextsearch"):
			write(writer, `{"result":{"docs":[{"doc":{"strs":[
				{"str":{"name":"nic-hdl","value":"AA1-RIPE"}},
				{"str":{"name":"e-mail","value":"ops@example.com"}}
			]}}]}}`)
		case strings.HasPrefix(path, "/rest/pocs;"):
			write(writer, `{"pocs":{"pocRef":{"@handle":"OPS1-ARIN"}}}`)
		case strings.HasPrefix(path, "/rest/poc/"):
			write(writer, `{"poc":{"handle":{"$":"OPS1-ARIN"},"companyName":{"$":"Example, Inc."},
				"emails":{"email":{"$":"ops@example.com"}}}}`)
		case strings.HasPrefix(path, "/entities"), strings.HasPrefix(path, "/entity/"):
			writer.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(path, "/rest/orgs;"):
			write(writer, `{"orgs":{"orgRef":{"@handle":"EX-1","@name":"Example, Inc."}}}`)
		case strings.HasSuffix(path, "/pocs"):
			// The organisation the name search found is the domain's, its contacts being the ones
			// the domain search turned up.
			write(writer, `{"pocs":{"pocLinkRef":{"@handle":"OPS1-ARIN","@function":"AD"}}}`)
		case strings.HasSuffix(path, "/nets"):
			write(writer, fmt.Sprintf(
				`{"nets":{"netRef":{"@handle":"NET-1","@name":"EXAMPLE-ARIN-NET","@startAddress":%q,"@endAddress":%q}}}`,
				first, last,
			))
		default:
			write(writer, fmt.Sprintf(`{"objects":{"object":[{"attributes":{"attribute":[
				{"name":"inetnum","value":%q},
				{"name":"netname","value":"EXAMPLE-NET"},
				{"name":"status","value":"ASSIGNED PA"}
			]}}]}}`, inetnum))
		}
	}
}

func networksOf(ranges []*Range) []string {
	found := make([]string, 0, len(ranges))
	for _, item := range ranges {
		found = append(found, item.Network)
	}

	return found
}

// TestFindMergesBothSources holds why both run: the registry knows what a party was allocated, and
// a mail policy declares what it sends from. Neither is a superset of the other.
func TestFindMergesBothSources(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		registryHandler(t, "192.0.2.0 - 192.0.2.255"),
		map[string][]string{"example.com": {"v=spf1 ip4:198.51.100.0/24 -all"}},
	)

	ranges, err := subdomainFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("expected both sources, sorted, got %v", networksOf(ranges))
	}

	// The registry's range keeps the registry's detail; the declared one has none to keep.
	if ranges[0].NetName != "EXAMPLE-NET" {
		t.Errorf("expected the registry name kept, got %+v", ranges[0])
	}
	if ranges[0].Confidence() != RipeConfidence {
		t.Errorf("expected the registry confidence, got %d", ranges[0].Confidence())
	}
	if ranges[1].Confidence() != spf.Confidence {
		t.Errorf("expected the declared confidence, got %d", ranges[1].Confidence())
	}
}

// TestFindRaisesConfidenceWhenBothAgree holds the point of carrying inferences rather than a
// boolean: a range two independent sources found is better attributed than one a single weak signal
// produced.
func TestFindRaisesConfidenceWhenBothAgree(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		registryHandler(t, "192.0.2.0 - 192.0.2.255"),
		map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}},
	)

	ranges, err := subdomainFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 1 {
		t.Fatalf("expected the one range both found, got %d: %v", len(ranges), networksOf(ranges))
	}
	if len(inference.Methods(ranges[0].Inferences)) != 2 {
		t.Errorf("expected both reasons kept, got %+v", ranges[0].Inferences)
	}
	if got := ranges[0].Confidence(); got != RipeConfidence+1 {
		t.Errorf("expected agreement to raise the confidence, got %d", got)
	}
}

// TestFindMergesTheRegistries holds why there are two of them: they are separate databases
// answering about separate parts of the world, and a party holding space in both is found in both.
func TestFindMergesTheRegistries(t *testing.T) {
	t.Parallel()

	rangeFinder := newFinder(
		t,
		registriesHandler(t, "192.0.2.0 - 192.0.2.255", "198.51.100.0", "198.51.100.255"),
		nil,
	)

	ranges, err := rangeFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("expected both registries, sorted, got %v", networksOf(ranges))
	}

	// Each keeps the name its own registry gave it.
	if ranges[0].NetName != "EXAMPLE-NET" || ranges[1].NetName != "EXAMPLE-ARIN-NET" {
		t.Errorf("expected each registry's name kept, got %q and %q", ranges[0].NetName, ranges[1].NetName)
	}
	if got := inference.Methods(ranges[1].Inferences); !slices.Equal(got, []inference.Method{MethodArin}) {
		t.Errorf("expected the range attributed to the other registry, got %v", got)
	}
}

// TestFindRaisesConfidenceWhenTheRegistriesAgree holds why they are separate methods rather than one
// "registry": a range both databases name is a range two records agree on, which is worth more than
// either alone.
func TestFindRaisesConfidenceWhenTheRegistriesAgree(t *testing.T) {
	t.Parallel()

	rangeFinder := newFinder(
		t,
		registriesHandler(t, "192.0.2.0 - 192.0.2.255", "192.0.2.0", "192.0.2.255"),
		nil,
	)

	ranges, err := rangeFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ranges) != 1 {
		t.Fatalf("expected the one range both hold, got %d: %v", len(ranges), networksOf(ranges))
	}
	if got := ranges[0].Confidence(); got != RipeConfidence+1 {
		t.Errorf("expected agreement to raise the confidence, got %d", got)
	}
}

// TestFindReachesTheRegistriesThatCannotSearchByDomain holds the two routes into a database that
// offers no search from a domain: the inverse search on the conventional abuse mailbox, and the name
// search checked against the address on a party's contact card. Neither is a superset of the other,
// so both run.
func TestFindReachesTheRegistriesThatCannotSearchByDomain(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/rdap+json")

		card := `["vcard",[["fn",{},"text","Example Ltd"],["kind",{},"text","org"],` +
			`["email",{},"text","noc@example.com"]]]`

		if strings.HasPrefix(request.URL.Path, "/entities") {
			body := fmt.Sprintf(`{"entitySearchResults":[{"handle":"ORG-EX1","vcardArray":%s}]}`, card)
			if _, err := fmt.Fprint(writer, body); err != nil {
				t.Errorf("could not write: %v", err)
			}

			return
		}

		body := fmt.Sprintf(
			`{"handle":"ORG-EX1","vcardArray":%s,"networks":[{"handle":"NET-1","name":"EXAMPLE-RDAP",`+
				`"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`,
			card,
		)
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	whoisClient := whoisServer(t, func(query string) string {
		if strings.HasPrefix(query, "-i abuse-mailbox") {
			return "role:  Example NOC\nnic-hdl:  ENOC1-EXAMPLE\nabuse-mailbox: abuse@example.com\n"
		}

		return "inetnum: 198.18.0.0 - 198.18.0.255\nnetname: EXAMPLE-WHOIS\ncountry: SE\n"
	})

	rangeFinder := NewFinder(
		// The registries that do search by domain are left out, so that what comes back is only
		// what these two routes found.
		finder_config.WithRipe(ripe.NewClient(ripe_config.WithBaseUrl(&url.URL{Scheme: "http", Host: "127.0.0.1:1"}))),
		finder_config.WithArin(arin.NewClient(arin_config.WithBaseUrl(&url.URL{Scheme: "http", Host: "127.0.0.1:1"}))),
		finder_config.WithWhois(MethodApnic, whoisClient),
		finder_config.WithRdap(MethodApnic, rdap.NewClient(
			rdap_config.WithBaseUrl(serverUrl),
			rdap_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		finder_config.WithResolver(&stubResolver{}),
	)

	ranges, err := rangeFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"198.18.0.0/24", "203.0.113.0/24"}) {
		t.Fatalf("expected both routes to answer, got %v", networksOf(ranges))
	}

	// Both are the same registry's records and are worth the same; the steps are what say which
	// route found which.
	for _, item := range ranges {
		if got := inference.Methods(item.Inferences); !slices.Equal(got, []inference.Method{MethodApnic}) {
			t.Errorf("expected the range attributed to the registry, got %v", got)
		}
		if item.Confidence() != ApnicConfidence {
			t.Errorf("expected the registry confidence, got %d", item.Confidence())
		}
	}

	if via := ranges[0].Inferences[0].Via; len(via) == 0 || via[0] != ViaAbuseMailbox {
		t.Errorf("expected the abuse mailbox route named, got %v", via)
	}
	if via := ranges[1].Inferences[0].Via; len(via) == 0 || via[0] != ViaName {
		t.Errorf("expected the name route named, got %v", via)
	}
}

// TestFindSurvivesOneRouteFailing holds that the two routes into a registry are independent: port 43
// being blocked must not cost the answers of the name search, which is a different transport to a
// different server.
func TestFindSurvivesOneRouteFailing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/rdap+json")

		card := `["vcard",[["fn",{},"text","Example Ltd"],["kind",{},"text","org"],` +
			`["email",{},"text","noc@example.com"]]]`

		if strings.HasPrefix(request.URL.Path, "/entities") {
			if _, err := fmt.Fprintf(writer, `{"entitySearchResults":[{"handle":"ORG-EX1","vcardArray":%s}]}`, card); err != nil {
				t.Errorf("could not write: %v", err)
			}

			return
		}

		body := fmt.Sprintf(
			`{"handle":"ORG-EX1","vcardArray":%s,"networks":[{"handle":"NET-1","name":"EXAMPLE-RDAP",`+
				`"cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}]}]}`,
			card,
		)
		if _, err := fmt.Fprint(writer, body); err != nil {
			t.Errorf("could not write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("could not parse the server url: %v", err)
	}

	rangeFinder := NewFinder(
		finder_config.WithRipe(ripe.NewClient(ripe_config.WithBaseUrl(&url.URL{Scheme: "http", Host: "127.0.0.1:1"}))),
		finder_config.WithArin(arin.NewClient(arin_config.WithBaseUrl(&url.URL{Scheme: "http", Host: "127.0.0.1:1"}))),
		// A port nothing is listening on, which is what a blocked port 43 looks like.
		finder_config.WithWhois(MethodApnic, whois.NewClient("127.0.0.1", whois_config.WithPort("1"))),
		finder_config.WithRdap(MethodApnic, rdap.NewClient(
			rdap_config.WithBaseUrl(serverUrl),
			rdap_config.WithFetchOptions(fetch_config.WithHttpClient(server.Client())),
		)),
		finder_config.WithResolver(&stubResolver{}),
	)

	ranges, err := rangeFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"203.0.113.0/24"}) {
		t.Errorf("expected the working route to survive, got %v", networksOf(ranges))
	}
}

// TestFindFollowsTheNetworksToTheirPrefixes holds the second axis. An allocation is what a party was
// given and a prefix is what its network routes, and space routed under someone else's allocation
// appears only here -- so the registry answer and the routing answer are different sets.
func TestFindFollowsTheNetworksToTheirPrefixes(t *testing.T) {
	t.Parallel()

	rangeFinder := newFinder(
		t,
		func(writer http.ResponseWriter, request *http.Request) {
			path := request.URL.Path
			write := func(body string) {
				writer.Header().Set("Content-Type", "application/json")
				if _, err := fmt.Fprint(writer, body); err != nil {
					t.Errorf("could not write: %v", err)
				}
			}

			switch {
			case strings.HasPrefix(path, "/rest/"), strings.HasPrefix(path, "/entities"),
				strings.HasPrefix(path, "/entity/"):
				writer.WriteHeader(http.StatusNotFound)
			case strings.Contains(path, "fulltextsearch"):
				write(`{"result":{"docs":[{"doc":{"strs":[
					{"str":{"name":"nic-hdl","value":"AA1-RIPE"}},
					{"str":{"name":"e-mail","value":"ops@example.com"}}
				]}}]}}`)
			case strings.Contains(path, ripestat.RoasPath):
				write(`{"data":{"roas":[{"asn":"64500","prefix":"192.0.2.0/24","maxLength":24,"ta":"RIPE NCC RPKI Root"}]}}`)
			case strings.Contains(path, ripestat.AnnouncedPrefixesPath):
				// Announced but not authorised, which is the case the two answers differ on.
				write(`{"data":{"prefixes":[{"prefix":"192.0.2.0/24"},{"prefix":"198.51.100.0/24"}]}}`)
			case strings.Contains(request.URL.RawQuery, "aut-num"):
				write(`{"objects":{"object":[{"attributes":{"attribute":[
					{"name":"aut-num","value":"AS64500"},
					{"name":"as-name","value":"EXAMPLE-AS"}
				]}}]}}`)
			case strings.Contains(request.URL.RawQuery, "route"):
				write(`{"objects":{"object":[{"attributes":{"attribute":[
					{"name":"route","value":"203.0.113.0/24"},
					{"name":"origin","value":"AS64500"}
				]}}]}}`)
			default:
				write(`{"objects":{"object":[{"attributes":{"attribute":[
					{"name":"inetnum","value":"10.0.0.0 - 10.0.0.255"},
					{"name":"netname","value":"EXAMPLE-NET"}
				]}}]}}`)
			}
		},
		nil,
	)

	ranges, err := rangeFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	networks := networksOf(ranges)
	for _, expected := range []string{"10.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		if !slices.Contains(networks, expected) {
			t.Errorf("expected %s, got %v", expected, networks)
		}
	}

	byNetwork := make(map[string]*Range, len(ranges))
	for _, item := range ranges {
		byNetwork[item.Network] = item
	}

	// The authorisation and the announcement are separate methods, so the prefix both name is worth
	// more than either alone -- which is the point of keeping them apart.
	both := byNetwork["192.0.2.0/24"]
	if both == nil || len(inference.Methods(both.Inferences)) != 2 {
		t.Fatalf("expected the prefix both name to carry both, got %+v", both)
	}
	if both.Confidence() != RpkiConfidence+1 {
		t.Errorf("expected agreement to raise the confidence, got %d", both.Confidence())
	}

	// Announced and not authorised is an observation, and a transit provider makes it about its
	// customers' space as readily as about its own.
	announced := byNetwork["198.51.100.0/24"]
	if announced == nil || announced.Confidence() != BgpConfidence {
		t.Errorf("expected an announcement alone to be worth less, got %+v", announced)
	}

	if declared := byNetwork["203.0.113.0/24"]; declared == nil ||
		!slices.Contains(inference.Methods(declared.Inferences), MethodRouteObject) {
		t.Errorf("expected the route object's prefix, got %+v", declared)
	}
}

// TestFindSurvivesASourceFailing holds that the sources are independent: the registry being down
// must not cost the answers of the mail policy.
func TestFindSurvivesASourceFailing(t *testing.T) {
	t.Parallel()

	subdomainFinder := newFinder(
		t,
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		},
		map[string][]string{"example.com": {"v=spf1 ip4:198.51.100.0/24 -all"}},
	)

	ranges, err := subdomainFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(networksOf(ranges), []string{"198.51.100.0/24"}) {
		t.Errorf("expected the working source to survive, got %v", networksOf(ranges))
	}
}

func TestCollapse(t *testing.T) {
	t.Parallel()

	// A registry answer routinely holds a large allocation and several assignments inside it.
	// Reporting all of them would make one allocation look like a dozen.
	collapsed := Collapse([]*Range{
		{Network: "10.0.0.0/16", Inferences: []*inference.Inference{inference.New(MethodRipe, RipeConfidence)}},
		{Network: "10.0.1.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
		{Network: "10.0.2.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
		{Network: "192.0.2.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
		{Network: "not a network"},
		nil,
	})

	if !slices.Equal(networksOf(collapsed), []string{"10.0.0.0/16", "192.0.2.0/24"}) {
		t.Fatalf("expected the contained ranges folded in, got %v", networksOf(collapsed))
	}

	// The narrower range's reasoning is worth keeping: it may have come from a source the wider
	// one did not.
	methods := inference.Methods(collapsed[0].Inferences)
	if len(methods) != 2 {
		t.Errorf("expected the folded reasons kept, got %v", methods)
	}
}

// TestCollapseKeepsOneOfTwoIdentical holds the tie-break. Identical ranges contain each other, so
// without one they would both be dropped.
func TestCollapseKeepsOneOfTwoIdentical(t *testing.T) {
	t.Parallel()

	collapsed := Collapse([]*Range{
		{Network: "10.0.0.0/24", Inferences: []*inference.Inference{inference.New(MethodRipe, RipeConfidence)}},
		{Network: "10.0.0.0/24", Inferences: []*inference.Inference{inference.New(spf.Method, spf.Confidence)}},
	})

	if len(collapsed) != 1 {
		t.Fatalf("expected exactly one to survive, got %d", len(collapsed))
	}
	if len(inference.Methods(collapsed[0].Inferences)) != 2 {
		t.Errorf("expected both reasons kept, got %+v", collapsed[0].Inferences)
	}
}

func TestFindArgumentChecks(t *testing.T) {
	t.Parallel()

	if _, err := NewFinder().Find(t.Context(), ""); err == nil {
		t.Error("expected an empty domain to be an error")
	}

	var nilFinder *Finder
	if _, err := nilFinder.Find(t.Context(), "example.com"); err == nil {
		t.Error("expected a nil finder to be an error")
	}

	var nilRange *Range
	if got := nilRange.Confidence(); got != 0 {
		t.Errorf("expected a nil range to have no confidence, got %d", got)
	}
}

// TestTenureFromStatus holds the distinction the registries word differently and mean the same by.
// A party with an address inside a provider's block has that address and does not hold the block.
func TestTenureFromStatus(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		status string
		expect Tenure
	}{
		// RIPE says it as provider-aggregatable against provider-independent.
		{name: "assigned inside another allocation", status: "ASSIGNED PA", expect: TenureUsed},
		{name: "sub-allocated", status: "SUB-ALLOCATED PA", expect: TenureUsed},
		{name: "provider independent", status: "ASSIGNED PI", expect: TenureHeld},
		// An LIR's own allocation is the thing it was given.
		{name: "an allocation of the party's own", status: "ALLOCATED PA", expect: TenureHeld},
		{name: "allocated provider independent", status: "ALLOCATED PI", expect: TenureHeld},
		{name: "legacy space", status: "LEGACY", expect: TenureHeld},
		{name: "anycast", status: "ASSIGNED ANYCAST", expect: TenureHeld},
		// APNIC and AFRINIC say it outright.
		{name: "portable", status: "ALLOCATED PORTABLE", expect: TenureHeld},
		{name: "assigned portable", status: "ASSIGNED PORTABLE", expect: TenureHeld},
		{name: "non-portable", status: "ALLOCATED NON-PORTABLE", expect: TenureUsed},
		{name: "assigned non-portable", status: "ASSIGNED NON-PORTABLE", expect: TenureUsed},
		{name: "lower case", status: "assigned pa", expect: TenureUsed},
		// The v6 statuses say who handed the space over. ALLOCATED-BY-LIR opens like an allocation
		// of the party's own and is the opposite of one, which is why the order matters.
		{name: "allocated by the registry", status: "ALLOCATED-BY-RIR", expect: TenureHeld},
		{name: "allocated by a provider", status: "ALLOCATED-BY-LIR", expect: TenureUsed},
		{name: "aggregated by a provider", status: "AGGREGATED-BY-LIR", expect: TenureUsed},
		{name: "a bare v6 assignment", status: "ASSIGNED", expect: TenureUsed},
		// Most sources say nothing: an announcement and a mail policy describe use, not title.
		{name: "nothing said", status: "", expect: TenureUnknown},
		{name: "something else entirely", status: "SOMETHING", expect: TenureUnknown},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := TenureFromStatus(testCase.status); got != testCase.expect {
				t.Errorf("%s: expected %q, got %q", testCase.name, testCase.expect, got)
			}
		})
	}
}

// TestCollapseKeepsTheStrongerTenure holds that a range held inside one only used is still held: the
// containing range is the extent of what the party was given, and the narrower claim cannot weaken
// it.
func TestCollapseKeepsTheStrongerTenure(t *testing.T) {
	t.Parallel()

	collapsed := Collapse([]*Range{
		{Network: "10.0.0.0/16", Tenure: TenureUsed, Inferences: []*inference.Inference{
			inference.New(MethodRipe, RipeConfidence),
		}},
		{Network: "10.0.1.0/24", Tenure: TenureHeld, Inferences: []*inference.Inference{
			inference.New(MethodArin, ArinConfidence),
		}},
	})

	if len(collapsed) != 1 {
		t.Fatalf("expected one range, got %d", len(collapsed))
	}
	if collapsed[0].Tenure != TenureHeld {
		t.Errorf("expected the stronger claim kept, got %q", collapsed[0].Tenure)
	}
}

// TestFindMarksTenure holds that what a registry said about who holds a range reaches the answer. It
// is what lets a consumer tell space a party owns from an address it rents inside somebody else's.
func TestFindMarksTenure(t *testing.T) {
	t.Parallel()

	rangeFinder := newFinder(
		t,
		registryHandler(t, "192.0.2.0 - 192.0.2.255"),
		map[string][]string{"example.com": {"v=spf1 ip4:198.51.100.0/24 -all"}},
	)

	ranges, err := rangeFinder.Find(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byNetwork := make(map[string]*Range, len(ranges))
	for _, item := range ranges {
		byNetwork[item.Network] = item
	}

	// The registry said ASSIGNED PA, which is an address inside an allocation somebody else holds.
	if got := byNetwork["192.0.2.0/24"]; got == nil || got.Tenure != TenureUsed {
		t.Errorf("expected the registry's claim read, got %+v", got)
	}
	// A mail policy describes use rather than title, and says nothing either way.
	if got := byNetwork["198.51.100.0/24"]; got == nil || got.Tenure != TenureUnknown {
		t.Errorf("expected nothing said about the declared range, got %+v", got)
	}
}
