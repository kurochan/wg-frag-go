.PHONY: build clean lint tools-download proto proto-check test test-race test-release-scripts fuzz release-notes-generate \
	release-notes-check release-tag-check \
	test-netns test-netns-manager bench-netns \
	test-netns-control-recovery test-netns-base-recovery \
	test-netns-base-failure-recovery test-netns-no-fragment test-netns-no-fragmentation

build:
	mkdir -p bin
	go build -trimpath -o bin/wgf ./cmd/wgf

clean:
	rm -rf bin wgf wgf.exe

# Tools are built from tools/go.mod, independently of the product module. The
# linter runs with the host toolchain; Linux-only code is checked by the Linux
# build and test targets.
lint:
	@set -eu; \
	tool="$$(mktemp "$${TMPDIR:-/tmp}/wgf-golangci.XXXXXX")"; \
	trap 'rm -f "$$tool"' EXIT; \
	(cd tools && go build -trimpath -o "$$tool" github.com/golangci/golangci-lint/v2/cmd/golangci-lint); \
	env -u GOOS -u GOARCH "$$tool" run

tools-download:
	cd tools && go mod download

FUZZTIME ?= 5s

# The checked-in tool module is used locally, so generation does not upload
# schemas to a remote plugin registry.
proto:
	go tool -modfile=tools/go.mod buf generate

proto-check:
	go tool -modfile=tools/go.mod buf generate
	git diff --exit-code -- proto

release-notes-generate:
	ruby scripts/generate_debian_changelog.rb

release-notes-check:
	ruby scripts/check_release_notes_sync.rb

release-tag-check:
	test -n "$(VERSION)"
	ruby scripts/check_release_tag_order.rb --version "$(VERSION)"

test:
	go test ./...

test-race:
	go test -race ./...

test-release-scripts:
	ruby scripts/validate_ppa_source_test.rb

# Linux-only privileged integration: creates and removes two temporary network
# namespaces, veth interfaces, TUN interfaces, and test keys from Go.
test-netns:
	WGF_RUN_NETNS=1 go test -tags=integration -count=1 -run '^TestWGFNetNSWireGuardUDP$$' ./cmd/wgf

test-netns-manager:
	WGF_RUN_NETNS=1 go test -tags=integration -count=1 -run '^TestWGFManagerNetNSLifecycle$$' ./cmd/wgf

# Fault-injection variants are opt-in and require the same isolated Linux VM
# and CAP_NET_ADMIN/CAP_NET_RAW as test-netns.
test-netns-control-recovery:
	WGF_RUN_NETNS=1 WGF_NETNS_CONTROL_RECOVERY=1 go test -tags=integration -count=1 -run '^TestWGFNetNSWireGuardUDP$$' ./cmd/wgf

test-netns-base-recovery:
	# Asserts CONTROL ERROR at MTU 700, then restores MTU 1500 and re-gates DATA.
	WGF_RUN_NETNS=1 WGF_NETNS_BASE_FAILURE_RECOVERY=1 go test -tags=integration -count=1 -run '^TestWGFNetNSWireGuardUDP$$' ./cmd/wgf

test-netns-base-failure-recovery: test-netns-base-recovery

test-netns-no-fragment:
	WGF_RUN_NETNS=1 WGF_NETNS_NO_UNDERLAY_FRAGMENTATION=1 go test -tags=integration -count=1 -run '^TestWGFNetNSWireGuardUDP$$' ./cmd/wgf

test-netns-no-fragmentation: test-netns-no-fragment

# Optional measurement, not a CI pass/fail threshold. It reuses the Go netns
# integration topology and reports TCP inner goodput.
bench-netns:
	WGF_RUN_NETNS=1 WGF_NETNS_REQUIRE_PMTU=1 WGF_NETNS_BENCH_BYTES=67108864 go test -tags=integration -count=1 -v -run '^TestWGFNetNSWireGuardUDP$$' ./cmd/wgf

# Keep worker count bounded: fuzz targets must remain usable on developer
# laptops as well as in the isolated Linux validation VM.
fuzz:
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzParse -fuzztime=$(FUZZTIME) ./internal/config
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzParse -fuzztime=$(FUZZTIME) ./internal/core/innerip
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzParseRoundTrip -fuzztime=$(FUZZTIME) ./internal/core/carrier
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzParseEnvelope -fuzztime=$(FUZZTIME) ./internal/core/carrier
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzCodecParseRoundTrip -fuzztime=$(FUZZTIME) ./internal/core/control
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzReceiverAcceptCarrier -fuzztime=$(FUZZTIME) ./internal/core/datapath
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzAcceptAndExpire -fuzztime=$(FUZZTIME) ./internal/core/reassembly
	GOMAXPROCS=2 go test -run='^$$' -parallel=1 -fuzz=FuzzHandleInbound -fuzztime=$(FUZZTIME) ./internal/controlplane
