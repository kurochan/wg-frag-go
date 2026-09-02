# Release Notes

## 0.6.1 - 2026-09-02T08:50:58Z

<!-- debian: urgency=medium -->

- Add a dedicated, vendor-neutral monitoring guide covering the OpenMetrics endpoint, scrape behavior, metric selection, labels, and the metric inventory.
- Include the monitoring guide in Debian and GoReleaser packages and link it from the README, configuration reference, and Control API documentation.

## 0.6.0 - 2026-09-01T10:27:37Z

<!-- debian: urgency=medium -->

- Make concurrent `wgf quick` operations wait with bounded, owner-aware retries instead of failing immediately, including parallel systemd interface startup.
- Extend the systemd lifecycle timeouts to accommodate serialized `wgf quick` startup, reload, and teardown operations.
- Move the canonical configuration directory to `/etc/wgf`, with legacy `/etc/wg-frag` fallback and migration through `SaveConfig` until v0.7.0.
- Apply the Debian post-install systemd reload handling to GoReleaser-built `.deb` packages.

## 0.5.0 - 2026-08-31T03:20:53Z

<!-- debian: urgency=medium -->

- Add public in-process Go and Unix-domain gRPC APIs for dynamically managing WGF interfaces and peers.
- Add `wgf manager` for owning multiple interfaces in one process while keeping `wgf run` as the single-interface mode.
- Add peer-only live updates and persistent-TUN runtime restarts, including `wgf quick reload` and systemd reload support.
- Expose process-wide OpenMetrics consistently for single- and multi-interface operation, with counter continuity across runtime generations and same-identity recreation.
- Validate generated Launchpad PPA source packages before signing and uploading them.

## 0.4.1 - 2026-08-30T13:51:12Z

<!-- debian: urgency=medium -->

- Reject release tags that do not advance beyond the latest existing release, using Semantic Versioning ordering for release candidates.
- Add `make release-tag-check VERSION=vX.Y.Z` for the same validation before creating a tag.

## 0.4.0 - 2026-08-30T13:38:47Z

<!-- debian: urgency=medium -->

- Add an optional OpenMetrics endpoint with loopback-only default binding and configurable metric selection.
- Allow `wgf check` to validate configurations that include `wgf quick` settings without running hooks or inspecting host routes.
- Document installation from the Launchpad PPA and the OpenMetrics configuration.

## 0.3.0 - 2026-08-27T09:49:00Z

<!-- debian: urgency=medium -->

- Move Ubuntu package publishing to the `kurochan/wg-frag-go` Launchpad PPA.

## 0.2.1 - 2026-08-25T03:26:10Z

<!-- debian: urgency=medium -->

- Publish a macOS arm64 `wgf` archive on GitHub Releases.
- Verify release source on macOS before publishing release assets.

## 0.2.0 - 2026-08-25T01:49:35Z

<!-- debian: urgency=medium -->

- Add native macOS support, including Darwin UDP transport and runtime integration.
- Add an end-to-end tunnel test between a macOS host and an isolated QEMU Linux guest.
- Add a helper to update and verify the pinned Alpine netboot artifacts used by the macOS E2E test.
- Run fuzz smoke tests and lint checks in dedicated CI workflows.
- Make curated release notes the source for Debian changelogs and GitHub Release highlights.

## 0.1.1 - 2026-08-24

<!-- debian: urgency=medium -->

- Separate platform-neutral runtime and data-plane setup from Linux UDP and routing integration as groundwork for macOS support.
- Add macOS CI coverage for the portable test suite and Darwin amd64/arm64 builds.
- Select the default daemon runtime directory per platform.

## 0.1.0 - 2026-08-24

<!-- debian: urgency=medium -->

- Add a complete WGF configuration reference and example configuration.
- Include operational, protocol, threat-model, and configuration documents in Debian packages.
- Add the reassembly fuzz target to the bounded fuzz suite and full CI.
- Document additional CLI status and peer-configuration operations.
- Correct the README benchmark label for the Kernel WireGuard baseline.

## 0.0.4 - 2026-08-22T06:20:26Z

<!-- debian: urgency=medium -->

- Verify the Debian package version against the release tag before publishing.

## 0.0.3-rc.5 - 2026-08-14

<!-- debian: urgency=medium -->

- Add build target.

## 0.0.3-rc.4 - 2026-08-14

<!-- debian: urgency=medium -->

- Fix Launchpad PPA builds when sbuild provides a non-writable HOME by using a build-local Go cache.

## 0.0.3-rc.3 - 2026-08-14

<!-- debian: urgency=medium -->

- Publish Launchpad PPA source packages for each supported Ubuntu series in parallel.
- Support Ubuntu 22.04 (jammy), 24.04 (noble), and 26.04 (resolute) PPA builds with series-specific package version suffixes.
- Document the Ubuntu support policy and PPA rebuild versioning.

## 0.0.3-rc.2 - 2026-08-14

<!-- debian: urgency=medium -->

- Fix Launchpad source package generation.

## 0.0.3-rc.1 - 2026-08-14

<!-- debian: urgency=medium -->

- Prepare the 0.0.3 release candidate.

## 0.0.2-rc.1 - 2026-08-13

<!-- debian: urgency=medium -->

- Package wg-frag-go for the Launchpad PPA.
