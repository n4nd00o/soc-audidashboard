"""Narrow screens: data tables scroll inside their own box, never the whole page."""

import re

from audidash_server.app import STATIC_DIR, TEMPLATES_DIR


def test_every_data_table_is_wrapped_in_a_scroll_container() -> None:
    checked = 0
    for template in sorted(TEMPLATES_DIR.rglob("*.html")):
        text = template.read_text(encoding="utf-8")
        opened = len(re.findall(r'<table class="data', text))
        wrapped = len(re.findall(r'<div class="table-wrap">\s*<table class="data', text))
        assert opened == wrapped, template.name
        checked += opened
    assert checked >= 12


def test_table_wrap_scrolls_horizontally() -> None:
    css = (STATIC_DIR / "css" / "app.css").read_text(encoding="utf-8")
    assert re.search(r"\.table-wrap\s*\{[^}]*overflow-x:\s*auto", css)
    # A grid item defaults to min-width:auto and would grow to the table's width instead.
    assert re.search(r"\.shell\.with-nav \.content\s*\{[^}]*min-width:\s*0", css)
