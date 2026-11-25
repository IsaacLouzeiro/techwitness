"""Extracts from an HTML page, JS file or source map what the engine looks at."""

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


@dataclass
class Page:
    url: str
    title: str = ""
    metas: list = field(default_factory=list)     # (name, content)
    scripts: list = field(default_factory=list)
    styles: list = field(default_factory=list)
    assets: list = field(default_factory=list)    # images, frames and other links
    links: list = field(default_factory=list)     # <a href>
    forms: list = field(default_factory=list)
    inline: list = field(default_factory=list)
    comments: list = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.page, self.base, self._in, self._buf = Page(url), url, None, []

    def _abs(self, value):
        try:
            u = urljoin(self.base, value.strip())
            s = urlsplit(u)
            s.port      # raises on an invalid port
        except ValueError:
            return None
        return u if s.scheme in ("http", "https") and s.hostname else None

    def _add(self, bucket, value):
        u = self._abs(value) if value else None
        if u and u not in bucket:
            bucket.append(u)

    def handle_starttag(self, tag, attrs):
        a = {k: v or "" for k, v in attrs}
        p = self.page
        if tag == "base" and a.get("href"):
            self.base = self._abs(a["href"]) or self.base
        elif tag == "meta":
            name = a.get("name") or a.get("property")
            if name:
                p.metas.append((name.lower(), a.get("content", "")))
        elif tag == "script":
            self._add(p.scripts, a.get("src"))
            self._in, self._buf = "script", []
        elif tag == "title" and not p.title:
            self._in, self._buf = "title", []
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel or a.get("as") == "style":
                self._add(p.styles, a.get("href"))
            elif "modulepreload" in rel or a.get("as") == "script":
                self._add(p.scripts, a.get("href"))
            else:
                self._add(p.assets, a.get("href"))
        elif tag in ("a", "area"):
            self._add(p.links, a.get("href"))
        elif tag in ("img", "iframe", "source", "video", "audio", "embed", "input"):
            self._add(p.assets, a.get("src"))
        elif tag == "form":
            self._add(p.forms, a.get("action"))

    def handle_endtag(self, tag):
        if tag == self._in:
            text = "".join(self._buf).strip()
            if tag == "title":
                self.page.title = " ".join(text.split())[:200]
            elif text:
                self.page.inline.append(text)
            self._in = None

    def handle_data(self, data):
        if self._in:
            self._buf.append(data)

    def handle_comment(self, data):
        text = " ".join(data.split())
        if text:
            self.page.comments.append(text)


def parse(html, url):
    p = _Parser(url)
    try:
        p.feed(html)
        p.close()
    except (AssertionError, ValueError):    # html.parser on hopelessly broken markup
        pass
    return p.page


# /*! Something v1.2.3 ...   or   @license Something 1.2.3
_LICENSE = re.compile(
    r"(?:/\*[!*]?|@license|@preserve|@overview)[\s*]{0,20}"
    r"([A-Za-z@][\w.@/\-]{1,40}(?: [A-Za-z][\w.\-]{1,30}){0,3}?),?"
    r"(?:[ \t]{1,3}-)?[ \t]{1,3}(?:version:?[ \t]{1,3}|v)?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)\b", re.I)


def license_banners(js):
    """(name, version) of the licence comments that minifiers keep."""
    out = []
    for m in _LICENSE.finditer(js):
        item = (m.group(1).strip(" -,"), m.group(2))
        if item not in out:
            out.append(item)
        if len(out) >= 100:
            break
    return out


_ENDPOINT = re.compile(
    r"[\"'`]((?:https?://[\w.\-]+(?::\d+)?)?/(?:api|rest|graphql|wp-json|oauth2?|auth|v\d{1,2}|ws)"
    r"(?:/[\w\-./{}:$]{0,120})?(?:\?[\w\-=&%.]{0,80})?)[\"'`]", re.I)


def endpoints(js):
    return list(dict.fromkeys(m.group(1) for m in _ENDPOINT.finditer(js)))[:200]


_MAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"*]{1,300})\s*$", re.M)


def source_map_url(js, url):
    found = _MAP.findall(js[-4000:])
    if not found or found[-1].startswith("data:"):
        return None
    return urljoin(url, found[-1])


_NODE = re.compile(r"node_modules/((?:@[\w.\-]+/)?\w[\w.\-]*)/")


def source_map_packages(text):
    """npm packages bundled in a JS file, read from its source map (None: not one)."""
    try:
        data = json.loads(text.removeprefix(")]}'").lstrip())
        sources = list(data["sources"]) if "sections" not in data else []
        for section in data.get("sections") or []:
            sources += section["map"].get("sources") or []
    except (ValueError, AttributeError, KeyError, TypeError, RecursionError):
        return None
    return sorted({n for s in sources if isinstance(s, str) for n in _NODE.findall(s)})
