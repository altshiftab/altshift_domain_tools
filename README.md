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
| `pkg/sources/ripe` | Registry contacts and their allocations |
| `pkg/inference` | How something was found, and what that is worth |
| `pkg/resolver` | Does this name resolve, and why not |

Each source is a `Client` built from a config package of its own -- `crtsh_config`, and so on --
carrying a base URL and the fetch options every call it makes is given. The two finders take the
same shape, and hold the source clients they use.

The three halves answer different questions and share no sources but HackerTarget, which serves two
of them through different endpoints. None finds what the others do.

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

Two sources, run together. The registry knows what a party was *allocated*, including space it is
not using; the domain's SPF record declares what it *sends from*, including space it uses under
someone else's allocation. Neither is a superset of the other.

The SPF walk follows `include:` and `redirect:` only within the same registered domain. Without
that, a domain whose record says `include:_spf.google.com` would contribute Google's entire mail
estate to its owner -- wrong, and enormous.

RIPE covers Europe, the Middle East and Central Asia, so an empty answer is not evidence that a
party holds nothing.

## Inference

Everything here is inferred rather than known, and the kinds of evidence are not worth the same. So
a discovered thing carries the inferences that produced it -- a method, a confidence, and the steps
behind it -- rather than a bare boolean.

`inference.Combined` is the strongest of them, raised by one where two or more *distinct* methods
agree, capped at the top of the scale. The conservatism is deliberate: five reverse-IP hits are one
piece of evidence seen five times, because they all come from the same shared host, and summing them
would make co-location look like proof.

## Credentials

`crtsh`, `ripe` and the SPF walk need none. HackerTarget's host search is metered anonymously and
reports what is left of the allowance; its reverse IP lookup and WhoisXML both need keys, which are
given to `related.NewFinder` rather than passed per call.
