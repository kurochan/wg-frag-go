"""MkDocs hook that points links escaping docs/ at the GitHub repository.

The Markdown sources keep repository-relative links so they resolve when the
files are read from a checkout or from the installed package.
"""

import re

import mkdocs.plugins

REPO_BLOB = "https://github.com/kurochan/wg-frag-go/blob/main/"
ESCAPING_LINK = re.compile(r"\]\(\.\./([^)\s#]+)(#[^)]*)?\)")


# Runs after include-markdown has expanded README.md into index.md.
@mkdocs.plugins.event_priority(-100)
def on_page_markdown(markdown, page, config, files):
    del page, config, files

    def to_repository(match):
        return f"]({REPO_BLOB}{match.group(1)}{match.group(2) or ''})"

    return ESCAPING_LINK.sub(to_repository, markdown)
