# altshift_domain_tools

What can be learned about a domain from outside it.

## Packages

| Package | What it answers |
| --- | --- |
| `pkg/subdomain/finder` | What hangs off this domain? `vpn.example.com` |
| `pkg/related` | What else does this owner have? `example.net` |
| `pkg/sources/crtsh` | Certificate transparency logs |
| `pkg/sources/hackertarget` | Host search and reverse IP |
| `pkg/sources/whoisxml` | Reverse whois |
| `pkg/subdomain/brute` | Wordlist brute force over DNS |
| `pkg/subdomain/wordlist` | The embedded default list |
| `pkg/network_range` | What address space does this owner hold? `192.0.2.0/24` |
| `pkg/sources/ripe` | Registry contacts and their allocations, for Europe and around it |
| `pkg/sources/arin` | The same, for North America |
| `pkg/sources/whois` | Inverse queries over port 43, for the registries with nothing better |
| `pkg/sources/rdap` | Parties by name, for the same |
| `pkg/sources/ripestat` | What a network authorises and announces |
| `pkg/asn` | An autonomous system number, written the one way |
| `pkg/network_range/reverse` | Whose reverse DNS is this block delegated to? |
| `pkg/cidr` | An address range as the prefixes that cover it |
| `pkg/email` | Is this registered address at the domain? |
| `pkg/organization` | Is this party's name worth searching a registry on? |
| `pkg/inference` | How something was found, and what that is worth |
| `pkg/resolver` | Does this name resolve, where does it point, and why not |

Each source is a `Client` built from a config package of its own -- `crtsh_config`, and so on --
carrying a base URL and the fetch options every call it makes is given. The two finders take the
same shape, and hold the source clients they use.

The three halves answer different questions and share no sources but HackerTarget, which serves two
of them through different endpoints. None finds what the others do.

## Command

```
go install github.com/altshiftab/altshift_domain_tools/cmd/altshift_domain_tools@latest
```

```
altshift_domain_tools subdomains [-b] [-r ADDRESS] [-c N] [-j] DOMAIN
altshift_domain_tools related    [-w PATH] [-t PATH] [-o NAME] [-s TYPE] [-j] DOMAIN
altshift_domain_tools ranges     [-j] DOMAIN
```

One item per line by default, so a run pipes into whatever comes next the way the shell scripts this
replaces did; `--json` adds how each result was found and what that is worth.

Completions come from the parser's own declaration, so they cannot disagree with what the program
accepts:

```
altshift_domain_tools --completion zsh > ~/.zsh/completions/_altshift_domain_tools
```

`ranges` needs no credentials at all. `related` reads its keys from a file (`-w`, `-t`) or from
`WHOISXML_API_KEY` and `HACKERTARGET_API_KEY` -- there is deliberately no flag taking a key itself,
because an argument is visible in the process table to every user on the machine.

The wordlist pass is opt-in (`-b`): it is visible in the target's resolver logs, so a run that did
not ask for it does not do it.

## Subdomains

```go
subdomainFinder := finder.NewFinder(finder_config.WithResolver(dnsResolver))

result, err := subdomainFinder.Find(ctx, "example.com", wordlist.Names())
```

The passive sources cost the target nothing. The active pass is skipped where the domain answers to
every name -- see `brute.CanBrute` -- because a wildcard record makes every name in the list a false
hit. `Result.Bruted` says whether it ran, which is how an empty answer is told from a skipped one.

`Resolver` is an interface, so a caller already holding a DNS client passes that. `pkg/resolver` is
for callers who hold none; it reads the response code, which the standard library does not report
and which is what tells a name that does not exist from a resolver that has stopped answering. An
implementation must be safe for concurrent use: the brute force calls it from many goroutines at
once.

A finder given no source clients builds them with their own defaults, so the call above is the whole
of the ordinary setup. A caller wanting its own HTTP client, timeout or headers passes them, either
once on the finder or per call:

```go
subdomainFinder := finder.NewFinder(
    finder_config.WithResolver(dnsResolver),
    finder_config.WithCrtsh(crtsh.NewClient(crtsh_config.WithBaseUrl(mirror))),
    finder_config.WithFetchOptions(fetch_config.WithHttpClient(httpClient)),
    finder_config.WithConcurrency(64),
)
```

## Related domains

```go
relatedFinder := related.NewFinder(related_config.WithWhoisXmlApiKey(apiKey))

domains, err := relatedFinder.ReverseWhois(ctx, "example.com", nil)
```

Each domain carries the inferences that attributed it, with a confidence: a registration record
naming the same party is worth more than sharing an address. An address serving more than
`DefaultSharedHostingDomainLimit` domains is discarded, because everything on shared hosting would
otherwise be attributed to everything else. `related_config.WithSharedHostingDomainLimit` overrides
it.

Reverse whois bills, so a search is previewed before it is bought. A preview costs nothing and
answers with a count, which is what decides whether the purchase is worth making: a term matching
nothing is not bought, and neither is one matching more than `DefaultReverseWhoisMatchLimit`, which
has stopped describing one party and started describing a privacy service or a registrar. The count
stops at ten thousand -- the addresses at `google.com` preview as ten thousand whatever the true
number is -- so that is where the limit sits, and a term reaching it has said only that it matched
too much to count. `related_config.WithReverseWhoisMatchLimit` raises it, and a purchase then reads
as many pages as the limit allows, one credit each. What a run cannot do is return part of an answer
and let it pass for the whole of one: a search too big for the budget is left unbought and said so,
and a walk that stops early says that too.

### Which records to read

The registry keeps two sets, and they answer different questions at the same price. The historic
records hold what redaction has since taken out of the current ones -- `kivra.com` matches no
address in the current records and thirty-seven in the historic -- so they are worth sweeping once
for a domain. The current records are what a domain looks like now, and are what a monitor asks for
again on every run.

So the choice is the caller's, per call or on the finder, and `DefaultSearchTypes` is the current
records alone: reading both by default would have every repeat buy the past over again.

```go
// Once, when a domain is first looked at.
domains, err := relatedFinder.ReverseWhois(ctx, "kivra.com", []string{whoisxml.SearchTypeCurrent, whoisxml.SearchTypeHistoric})

// And thereafter, on a finder built for monitoring.
relatedFinder := related.NewFinder(
    related_config.WithWhoisXmlApiKey(apiKey),
    related_config.WithSearchTypes(whoisxml.SearchTypeCurrent),
)
```

A match in the historic records is worth one step less than the same match in the current ones,
because the package claims present ownership. One step and not two: redaction means the past is
frequently the only place the evidence survives, so a historic-only match is often a current domain
whose record went dark rather than one the party let go. Both are the same `Method` -- two search
types are one search against two copies of one registry, not two methods agreeing, and separating
them would have `Combined` raise every domain that appears in both.

A term that fails does not take the others with it. What the others bought is kept and the failure
is logged, because a purchase already billed is not worth discarding; every term failing is returned
as an error, since that is the key or the API rather than a domain with no relations. The same holds
for reverse IP, where one address failing does not discard what the others found.

The DNS both halves reach for is an interface apiece in `pkg/resolver`, narrow and separate because
they ask different questions: `AddressResolver` for where a domain is hosted, which is where the
reverse-IP search starts, and `NameServerResolver` for where its DNS is served from, which is what
the corroboration check compares. A caller already holding a client passes it -- `net.DefaultResolver`
satisfies both as it stands, and is the fallback -- and a test passes a table, so neither search
needs the network to be tested.

### The organisation pivot

```go
domains, err := relatedFinder.ReverseWhoisOrganization(ctx, "kivra.com", "", nil)
```

Most gTLD registrations made since 2018 carry no registrant e-mail, so the address search finds
nothing for them however many domains the party holds: `kivra.com` matches none, and its
organisation matches seventeen. This is the search that finds those, over the registrant
organisation and the registrant contact name.

It is weaker evidence and is recorded as such. The registry walks in `pkg/network_range` keep an
organisation only where its own contacts carry an address at the domain, because a name is a poor
thing to attribute on; here the API answers with bare domain names and there is nothing to check
them against. So results carry `MethodReverseWhoisOrganization` at `ConfidenceFair`, below what an
address at the domain is worth -- a separate method rather than a weaker grade of the same one, so
that a domain both pivots found still outranks one either found alone.

Two gates stand in for the check that cannot be made. The name is judged before it is searched:
`pkg/organization` strips the company form and the words every company shares, and rejects what is
left if it is under `organization.MinimumLength` letters or is nothing but those shared words --
`Data Group AB` identifies nobody, and `Kivra AB` is searched for as `Kivra`, the shorter substring
matching strictly more. The count is judged before it is bought, against
`DefaultReverseWhoisOrganizationMatchLimit`, which sits far below the address search's because a
name matches far more loosely: a portfolio is seventeen domains, or a few hundred; a term matching
thousands has matched the language rather than the company.

An organisation name of `""` is guessed from the domain's own label, which is what most parties are
registered under. A guess that fails the name gate is dropped with a warning; a name the caller
named and that fails it is an error, the caller having asked for something that cannot be done.

### Corroboration

```go
domains, err = relatedFinder.Corroborate(ctx, "kivra.com", domains)
```

A reverse-whois answer is a list of bare names, so there is no registrant to check against the
party. The DNS is the one thing about those names that can be read without asking the API, and
`Corroborate` reads it: a domain served from the same nameservers as the searched domain, or from a
set that `DefaultNameServerClusterSize` of the others share, has been placed there by something
other than the search that found it. It costs no credits and reaches no registry.

It records `MethodSharedNameServers` at `ConfidenceModest` rather than filtering, so `Combined`
raises what two independent things agree on and leaves the rest where it was. Nothing is removed --
a domain with no delegation is one this has nothing to say about, not one shown to be unrelated.

A set belonging to a large provider is discarded outright, because it identifies nobody: Cloud DNS
hands each zone one of a few dozen fixed sets between millions of zones, so two zones carrying the
same four names have been shown to share nothing. That is conservative on purpose, and it costs
real matches -- a party whose own DNS is on such a provider gets no corroboration for the domains
that genuinely sit beside it.

On `kivra.com` the split is the useful one: the nineteen domains its brand-protection registrar
holds -- the country registrations and the typo defensives alike -- rise to 4, and the three that
merely contain the word `kivra` stay at 3.

## Network ranges

```go
rangeFinder := finder.NewFinder()

ranges, err := rangeFinder.Find(ctx, "example.com")
```

Four registries, the routing system and a mail policy, run together. A registry knows what a party
was *allocated*, including space it is not using; the routing system knows what its networks
*authorise and announce*, including space held under someone else's allocation; the domain's SPF
record declares what it *sends from*. None is a superset of another.

The SPF walk follows `include:` and `redirect:` only within the same registered domain. Without
that, a domain whose record says `include:_spf.google.com` would contribute Google's entire mail
estate to its owner -- wrong, and enormous.

Each registry is its own method rather than all of them being "the registry", so a range more than
one of them names is a range independent records agree on and is scored accordingly. All four are
worth the same, because all four rest on the same thing: an address at the domain, found in the
registry's own record. What differs is the route taken to it, and that is what the inference's steps
say. LACNIC is the one that is missing, so an empty answer is still not evidence that a party holds
nothing.

**RIPE** answers a full-text search with the objects registered at a domain, and an inverse search
with the ranges those objects are referenced by. Both steps are wider than the obvious version, and
each way they are wider was a party's space going unfound: the search reads roles and organisations
as well as people -- a range is as often registered to "Example NOC" as to somebody, and an
inetnum's `org` is the party that holds it where its contacts may be a provider's staff -- and asks
for more than the ten hits the database answers with by default. The inverse search reads `abuse-c`
alongside `admin-c` and `tech-c`, and asks for `inet6num` as well as `inetnum`: a filter naming only
the latter *excludes* the former rather than covering it, so a party holding v6 space looked as
though it held none.

**ARIN** has a real search over contacts' e-mail addresses -- stricter than RIPE's full-text guess --
but none from a contact to the space they administer: only an organisation holds ranges, and an
organisation is reachable by name. So the name is the bridge, read off the contacts the domain search
found, and the organisations it turns up are checked back against those same contacts:

```
pocs;domain=example.com -> poc/{handle} -> orgs;name={company}* -> org/{handle}/pocs -> org/{handle}/nets
                                                                   ^ the check
```

**APNIC and AFRINIC** offer no search from a domain at all. Both refuse an inverse search on e-mail
outright -- `%ERROR:105: "e-mail" is not an inverse searchable attribute`, the same removal RIPE made
-- and RDAP defines only two searchable properties for a party, its name and its handle (RFC 9082).
So there are two ways in, neither a superset of the other, and both run:

```
whois -i abuse-mailbox abuse@example.com  ->  -i admin-c,tech-c {handle}  ->  inetnum
rdap  /entities?fn={name}  ->  /entity/{handle}  ->  networks
                               ^ the check: an address at the domain, on the party's card
```

The first works because an abuse contact is conventionally at the party's own domain. That is a
convention rather than a rule, so it finds a party that follows it and not one whose registered abuse
contact is at its provider's domain or is a named individual. The second needs a name, and takes the
domain's own label together with whatever ARIN turned out to call the owner -- which is why the
registries that search by domain run first.

Every one of these ends in the same check: an address at the domain, in the registry's own record.
Without it a name would be doing the attributing, and a stranger sharing one would have its address
space handed to the domain's owner. All the walks are bounded -- `MaxPersons`, `MaxOrganizations`,
`MaxContacts`, `MaxNames`, `MaxEntities` -- because the steps multiply and the databases ask callers
to be gentle.

`pkg/sources/whois` is the only thing here that is not HTTP: port 43 is a line of text in and a
document out, with no status code, no content type and no length. What structure there is comes from
RPSL, and errors arrive in comments -- `%ERROR:101` for nothing found, which is an answer, against
`%ERROR:105` for a refused query, which is not.

### The other axis

An allocation is what a party was *given*. A prefix is what its network *routes*, and space routed
under someone else's allocation appears in no registry record a search would reach. So once a walk
has found a party, it also asks what networks are registered to it -- `-i org -T aut-num`, or ARIN's
`/asns`, or the `autnums` an RDAP party already answers with -- and follows each one to its prefixes
three ways:

| | What it asserts | Worth |
| --- | --- | --- |
| **RPKI authorisation** | The address holder *signing* that this network may originate the prefix | strong |
| **Route object** | The registry's own version of the same statement, by the space's maintainer | strong |
| **BGP announcement** | Observation: this is being routed by that network right now | fair |

The last is deliberately worth less. A transit provider originates its customers' space, so an
announcement alone attributes a customer's addresses to its provider -- it is evidence the prefix
and the network belong together, not evidence of who holds the addresses.

No further check is owed here, and that is the point of running it last: a network is only ever
followed if it was registered to a contact or an organisation an earlier round had already checked
against the domain, so the prefixes rest on exactly the evidence the allocations do.

This axis is also global. The routing data covers every registry's space, which makes it the one
route into the region no registry search here reaches.

### Reverse delegation

A registry hands a reverse zone to the holder of the address space and to nobody else. Getting
`8.8.8.in-addr.arpa` answered by `ns1.google.com` is something only the party allocated `8.8.8.0/24`
can arrange, so a delegation pointing into the domain is close to a statement of holding — and the
zone name *is* the prefix, one label per octet.

It is not a PTR. A reverse record says what an address is *called*, which whoever operates it
decides: an address inside a provider's block is named by the provider, so a PTR reveals who runs
the machine. The delegation is a level above and says who the block was handed to.

It is asked two ways, because the fact is recorded in two places:

- **In the registry.** RIPE, APNIC and AFRINIC keep the delegation as a `domain:` object with the
  party's own contacts on it, so one more type filter on the inverse search already in use finds
  them. No resolver involved.
- **In the DNS.** `pkg/network_range/reverse` resolves the domain, then walks *up* from the most
  specific zone until one answers — because the delegation sits at whatever boundary the holder
  took, and nothing in an address says which. Google's is a `/24`, SUNET's a `/16`, Cloudflare's a
  `/16`. The walk stops at the first zone that answers rather than climbing past it: the zone above
  a party's is delegated to its provider, which is not evidence about this party. And *every*
  nameserver must be within the domain, or a secondary somebody agreed to run would attribute a
  block.

Both are the same fact seen from two sides, so they share one method rather than corroborating each
other into a higher score.

### Held or used

A party with an address inside a provider's block genuinely has that address, and does not hold the
block. Both facts are worth having and they are not the same one, so a range carries a `Tenure`
saying which the registry said it was:

```
185.133.68.0/22        held     ALLOCATED PA
193.104.32.0/24        held     ASSIGNED PI
2a05:2440::/29         held     ALLOCATED-BY-RIR
77.88.104.0/29         used     ASSIGNED PA
2a00:2381:112e::/56    used     ASSIGNED
```

The registries word it differently and mean the same thing: RIPE writes provider-aggregatable
against provider-independent, APNIC and AFRINIC say portable and non-portable outright, and the v6
statuses say whether the registry or a provider handed the space over -- `ALLOCATED-BY-LIR` opens
like an allocation of the party's own and is the opposite of one.

Most sources say nothing either way, and that is honest rather than missing: a routing announcement
and a mail policy describe use, not title.

The distinction matters most as a rule about what *not* to do. Attributing one address inside a
provider's block is correct; treating that address as an anchor and taking the block around it would
hand a customer its provider's entire estate -- the same mistake as following an SPF record into a
mail provider. Excluding provider space outright would be the opposite error, throwing away an
address the party really does have.

`pkg/cidr` is what turns a registry's "first address - last address" into prefixes. An arbitrary
range is not one prefix: `10.0.0.1 - 10.0.0.6` is a `/32`, a `/30` and a `/31`, and the alternative
-- one prefix too large -- would attribute addresses the party does not hold. Both ends are host
addresses, neither a network nor a broadcast address: the registry is stating the extent of what a
party holds rather than an addressing plan.

## Inference

Everything here is inferred rather than known, and the kinds of evidence are not worth the same. So
a discovered thing carries the inferences that produced it -- a method, a confidence, and the steps
behind it -- rather than a bare boolean.

`inference.Combined` is the strongest of them, raised by one where two or more *distinct* methods
agree, capped at the top of the scale. The conservatism is deliberate: five reverse-IP hits are one
piece of evidence seen five times, because they all come from the same shared host, and summing them
would make co-location look like proof.

## Credentials

`crtsh`, all four registries, the routing data and the SPF walk need none. HackerTarget's host search is metered anonymously and
reports what is left of the allowance; its reverse IP lookup and WhoisXML both need keys, which are
given to `related.NewFinder` rather than passed per call.
