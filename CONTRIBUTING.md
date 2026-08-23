# Contributing to wg-frag-go

Issues and pull requests are welcome. This project is experimental and is
maintained on a best-effort basis; a contribution does not imply a support or
release commitment.

## Before opening a pull request

Use the checked-in tool module and run the relevant checks:

```sh
go test ./...
make lint
make proto-check
make test-race
```

Run the bounded local fuzz suite when changing a parser, protocol decoder, or
state machine:

```sh
make fuzz
```

Linux network-namespace tests require `CAP_NET_ADMIN`, `CAP_NET_RAW`, and
`/dev/net/tun`:

```sh
make test-netns
```

## Change expectations

- Keep the v1 protocol compatible unless the change explicitly updates the
  protocol version and documentation.
- Preserve bounded memory and avoid hot-path allocations unless measurements
  justify a trade-off.
- Add focused tests for behavior changes. Add a minimized fuzz input under
  `testdata/fuzz` when fuzzing finds a regression.
- Update user-facing documentation when changing configuration, command
  behavior, protocol rules, or operational requirements.
- Keep generated protobuf files synchronized with their `.proto` sources by
  running `make proto`.

## Reporting security issues

Do not disclose vulnerabilities in a public issue or pull request. Follow
[`SECURITY.md`](SECURITY.md) instead.
