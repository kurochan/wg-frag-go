# Release Notes

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
