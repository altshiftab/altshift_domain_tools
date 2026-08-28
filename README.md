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
| `pkg/cidr` | An address range as the prefixes that cover it |
| `pkg/email` | Is this registered address at the domain? |
| `pkg/inference` | How something was found, and what that is worth |
| `pkg/resolver` | Does this name resolve, and why not |

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
altshift_domain_tools related    [-w PATH] [-t PATH] [-H] [-j] DOMAIN
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

domains, err := relatedFinder.ReverseWhois(ctx, "example.com", false)
```

Each domain carries the inferences that attributed it, with a confidence: a registration record
naming the same party is worth more than sharing an address. An address serving more than
`DefaultSharedHostingDomainLimit` domains is discarded, because everything on shared hosting would
otherwise be attributed to everything else. `related_config.WithSharedHostingDomainLimit` overrides
it.

## Network ranges

```go
rangeFinder := finder.NewFinder()

ranges, err := rangeFinder.Find(ctx, "example.com")
```

Four registries and a mail policy, run together. A registry knows what a party was *allocated*,
including space it is not using; the domain's SPF record declares what it *sends from*, including
space it uses under someone else's allocation. None is a superset of another.

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

`crtsh`, all four registries and the SPF walk need none. HackerTarget's host search is metered anonymously and
reports what is left of the allowance; its reverse IP lookup and WhoisXML both need keys, which are
given to `related.NewFinder` rather than passed per call.
