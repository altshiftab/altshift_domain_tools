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
| `pkg/resolver` | Does this name resolve, and why not |

Each source is a `Client` built from a config package of its own -- `crtsh_config`, and so on --
carrying a base URL and the fetch options every call it makes is given. The two finders take the
same shape, and hold the source clients they use.

The two halves answer different questions and share no sources but HackerTarget, which serves both
through different endpoints. Neither finds what the other does.

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

## Credentials

`crtsh` needs none. HackerTarget's host search is metered anonymously and reports what is left of
the allowance; its reverse IP lookup and WhoisXML both need keys, which are given to
`related.NewFinder` rather than passed per call.
