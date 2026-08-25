---
name: release-notes
description: "Draft and review curated release notes before a tagged release, using RELEASE_NOTES.md as the source for Debian changelog entries and GitHub Release highlights. Use for release preparation; never use it to publish, tag, commit, or push."
---

# Release Notes

Create an evidence-based release-note draft for the repository in scope. This
skill prepares text for human review; it does not perform a release.

## Boundaries

- Do not create a tag, commit, push, GitHub Release, package upload, or other
  external publication.
- Treat `RELEASE_NOTES.md` as the editable release-note source. Do not hand
  edit `debian/changelog`; synchronize it with the repository script instead.
- Do not invent PR numbers, contributors, performance claims, compatibility,
  or security claims. State unavailable evidence plainly.
- Treat the current checked-out worktree and the reachable Git history as the
  primary evidence. Preserve unrelated local changes.

## Gather evidence

1. Read repository instructions such as `AGENTS.md`, then inspect `git status`.
2. Identify the target release version and the previous reachable release tag.
   If an edit is requested but the target version is unspecified, ask for it;
   do not guess a version.
   Check whether the target's `v` tag already exists. A tagged version is
   published: do not edit its entry unless the user explicitly requests a
   historical correction. For an untagged version, update an existing entry
   rather than adding a duplicate.
3. Review the commit range from the previous tag to `HEAD`, plus the current
   top entry in `RELEASE_NOTES.md`. Inspect changed files when a commit subject
   is insufficient to explain the user-visible effect.
4. When the repository has a release workflow or GoReleaser configuration,
   confirm its changelog/version contract before proposing an edit.
5. When GitHub attribution is requested and `gh` is available and authenticated,
   gather merged PR numbers and contributor handles from the release range.
   Otherwise omit attribution rather than inferring it from commit authors.

## Draft content

Write release content in English unless the user requests another language.

- Prefer 2--6 concise bullets describing user-visible changes, compatibility,
  packaging, verification, or important fixes.
- Group related implementation changes into one outcome-focused bullet.
- Omit exploratory history, routine refactors with no observable effect, and
  transient CI failures.
- Use the same curated bullets for the next `RELEASE_NOTES.md` entry and the
  GitHub Release `## Highlights` section. The Debian changelog is derived from
  those bullets.
- Do not manually maintain contributor lists in the curated text. When the
  release workflow uses GitHub's generated release notes, that deterministic
  workflow section owns PR and contributor attribution.

## Debian header metadata

Each release entry carries its Debian urgency as a hidden metadata line:

```md
<!-- debian: urgency=medium -->
```

Assess whether the release has a specific operational reason for a different
urgency, such as a security fix or a severe data-loss or availability defect.
If so, tell the user the proposed level and reason. Change the metadata only
after the user explicitly approves it; otherwise use `medium`.

Return:

1. the assumed target version and evidence range;
2. a proposed `RELEASE_NOTES.md` section; and
3. a GitHub Release `## Highlights` section.

## Apply mode

Only after an explicit request to apply the draft:

1. confirm that the target's `v` tag does not exist. If it does, stop unless
   the user explicitly requests a historical correction. Then add the new
   version section at the top of `RELEASE_NOTES.md`, using the
   repository's `## VERSION - TIMESTAMP` heading syntax, a UTC timestamp
   obtained at edit time (for example, with `date -u`) in RFC 3339 format
   (`YYYY-MM-DDTHH:MM:SSZ`), and `<!-- debian: urgency=medium -->`. Do not
   infer the timestamp. Existing day-only headings are legacy entries and
   remain supported.
2. run `make release-notes-generate`, then `make release-notes-check`;
3. show the diff and verify that the rendered GitHub highlights match the
   intended release summary.

Stop after the local edit and validation. Leave committing, tagging, and
publishing to the user.
