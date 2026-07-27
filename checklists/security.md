# Security Checklist

- [ ] Loopback is default target profile.
- [ ] All resolved IPv4/IPv6 answers are validated and selected address is pinned.
- [ ] Metadata/link-local/multicast/unspecified targets remain blocked.
- [ ] Redirects and proxy environment are disabled.
- [ ] Public target requires config, runtime authorization, and test challenge.
- [ ] TLS verifies by default.
- [ ] Secrets are references, resolved late, never persisted/logged.
- [ ] Paths are contained and final symlinks rejected.
- [ ] Command/lifecycle execution uses argv and no shell.
- [ ] Request/response/process/concurrency/disk limits apply.
- [ ] Terminal, JSON, XML, and HTML output is safely encoded.
- [ ] Secret canaries cover every output/error path.
- [ ] CI permissions/artifacts and supply-chain provenance are verified.
- [ ] Every high-risk threat has an automated negative test.
