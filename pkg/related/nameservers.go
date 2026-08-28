package related

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/altshiftab/altshift_domain_tools/pkg/inference"
	"github.com/altshiftab/altshift_domain_tools/pkg/resolver"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// MethodSharedNameServers is a domain placed with the others by where its DNS is served, and
// SharedNameServersConfidence is what that is worth.
//
// It is corroboration rather than attribution: on its own it says a domain is served from the same
// place as another, which is a fact about a nameserver. What makes it worth recording is that it is
// arrived at independently of the registration records the other methods read, so a domain a
// registration search found and this agrees with is a domain two unrelated things say the same
// about -- and Combined raises exactly that case.
const (
	MethodSharedNameServers = inference.Method("shared name servers")

	SharedNameServersConfidence = inference.ConfidenceModest
)

// DefaultNameServerClusterSize is how many domains must share one set of nameservers before the
// sharing says anything.
//
// Two domains on one nameserver is a coincidence a large host makes thousands of times a day. A
// group of them, on a set no ordinary host uses, is a party's registrar keeping its portfolio in
// one place -- which is what a defensive registration looks like from outside, and what this is for.
const DefaultNameServerClusterSize = 3

// DefaultNameServerConcurrency bounds how many domains are looked up at once.
const DefaultNameServerConcurrency = 16

// sharedNameServerMarkers name the hosts that serve everybody.
//
// The check rests on a set of nameservers belonging to one party, and the large providers' do not:
// Cloud DNS hands each zone one of a few dozen fixed sets, so two zones carrying the same four
// names have not been shown to share anything at all -- there are millions of zones and a few dozen
// sets. A reverse-whois preview on the NameServers field says as much for free, and answers with
// the counting ceiling for every one of these; the list is that answer, written down, so the check
// needs no API key and no request to know what it already knows.
//
// Matched as substrings rather than suffixes, the providers numbering their hosts into the domain
// itself -- ns-1531.awsdns-63.org is one of a great many awsdns names sharing no suffix.
var sharedNameServerMarkers = []string{
	"akam.net",
	"akamaidns",
	"awsdns",
	"azure-dns",
	"cloudflare.com",
	"digitalocean.com",
	"dnsimple.com",
	"dnsmadeeasy.com",
	"domaincontrol.com",
	"googledomains.com",
	"nsone.net",
	"registrar-servers.com",
	"ultradns",
	"worldnic.com",
}

// nameServerResolver is the configured resolver, or the standard library's where none was set.
func (finder *Finder) nameServerResolver() resolver.NameServerResolver {
	if configured := finder.config.NameServerResolver; configured != nil {
		return configured
	}

	return net.DefaultResolver
}

// nameServerClusterSize is the configured size, or the default where none was set.
func (finder *Finder) nameServerClusterSize() int {
	if size := finder.config.NameServerClusterSize; size > 0 {
		return size
	}

	return DefaultNameServerClusterSize
}

// shared reports whether the nameserver is one of the hosts everybody is on.
func shared(nameServer string) bool {
	for _, marker := range sharedNameServerMarkers {
		if strings.Contains(nameServer, marker) {
			return true
		}
	}

	return false
}

// nameServerSet is a domain's nameservers as one comparable value: lower case, sorted, joined.
//
// It is empty where the domain has no delegation, where any of the nameservers belongs to a host
// everybody is on, or where the lookup failed. All three mean the same thing here -- that this
// check has nothing to say about the domain -- and none of them means the domain is unrelated.
func nameServerSet(ctx context.Context, nameServers resolver.NameServerResolver, domainName string) string {
	found, err := nameServers.LookupNS(ctx, domainName)
	if err != nil || len(found) == 0 {
		return ""
	}

	names := make([]string, 0, len(found))
	for _, nameServer := range found {
		if nameServer == nil {
			continue
		}

		name := strings.ToLower(strings.TrimSuffix(nameServer.Host, "."))
		if name == "" {
			continue
		}

		// One shared host in the set is enough to make the whole set say nothing: a zone served by
		// a large provider carries that provider's names, and those are not the party's.
		if shared(name) {
			return ""
		}

		names = append(names, name)
	}

	if len(names) == 0 {
		return ""
	}

	slices.Sort(names)

	return strings.Join(slices.Compact(names), " ")
}

// Corroborate adds an inference to the domains whose nameservers place them with the searched
// domain or with one another.
//
// It is the check the registration search cannot make. A reverse-whois answer is a list of names
// and nothing else, so there is no registrant to compare against the party -- unlike the registry
// walks in pkg/network_range, which keep an organisation only where its own contacts carry an
// address at the domain. The DNS is the one thing about these domains that can be read without
// asking the API, and it is read here.
//
// Two things count. A domain served from the same nameservers as the searched domain is the
// stronger of them. A group of domains served from one set of nameservers that no large provider
// owns is the other, and in practice the more useful: a party's defensive registrations sit with
// its brand-protection registrar rather than with the party's own DNS, so they cluster with each
// other and not with the domain that was searched for.
//
// Nothing is removed. A domain this cannot corroborate is a domain this has nothing to say about --
// it may have no delegation at all -- and an absent nameserver is not evidence of an absent
// relationship. The inferences are added to the domains given, which are returned for convenience.
func (finder *Finder) Corroborate(
	ctx context.Context,
	domainName string,
	domains []*Domain,
) ([]*Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if finder == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("finder"))
	}

	if domainName == "" || len(domains) == 0 {
		return domains, nil
	}

	nameServers := finder.nameServerResolver()

	var (
		sets      = make(map[string]string, len(domains))
		setsMutex sync.Mutex
		waitGroup sync.WaitGroup
	)

	// The searched domain is looked up alongside the rest, its own set being what the first of the
	// two rules compares against.
	names := append([]string{domainName}, domainNames(domains)...)

	// A candidate set can be as large as a match limit allows, and a lookup apiece run all at once
	// would be a burst at whatever resolver the caller uses.
	tokens := make(chan struct{}, DefaultNameServerConcurrency)

	for _, name := range names {
		waitGroup.Go(func() {
			tokens <- struct{}{}
			defer func() { <-tokens }()

			set := nameServerSet(ctx, nameServers, name)
			if set == "" {
				return
			}

			setsMutex.Lock()
			defer setsMutex.Unlock()
			sets[name] = set
		})
	}

	waitGroup.Wait()

	// How many of the domains found share each set, which is what says a set is a party's rather
	// than a coincidence. The searched domain is left out of the count: it is what the other rule
	// compares against, and counting it would have one match look like two.
	counts := make(map[string]int, len(sets))
	for _, domain := range domains {
		if domain == nil {
			continue
		}

		if set := sets[domain.Domain]; set != "" {
			counts[set]++
		}
	}

	clusterSize := finder.nameServerClusterSize()
	searchedSet := sets[domainName]

	for _, domain := range domains {
		if domain == nil {
			continue
		}

		set := sets[domain.Domain]
		if set == "" {
			continue
		}

		withSearched := searchedSet != "" && set == searchedSet
		inCluster := counts[set] >= clusterSize

		if !withSearched && !inCluster {
			continue
		}

		via := []string{set}
		if withSearched {
			via = append(via, domainName)
		}

		domain.Inferences = inference.Merge(
			append(
				domain.Inferences,
				inference.New(MethodSharedNameServers, SharedNameServersConfidence, via...),
			),
		)
	}

	return domains, nil
}

// domainNames is the names the domains carry, in a stable order.
func domainNames(domains []*Domain) []string {
	names := make(map[string]struct{}, len(domains))

	for _, domain := range domains {
		if domain != nil && domain.Domain != "" {
			names[domain.Domain] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(names))
}
