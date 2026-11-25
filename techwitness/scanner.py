"""One scan: fetches, feeds the engine and collects everything worth reporting."""

import re
import secrets
import socket
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import page as pg
from .engine import Engine
from .fetch import FetchError, clean_url, grab_banner, site_of

# response headers that usually say something about the stack
BANNER_HEADERS = {"server", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via", "x-runtime",
                  "x-backend-server", "x-served-by", "x-cache", "x-varnish", "x-drupal-cache", "x-jenkins",
                  "powered-by", "x-server", "x-debug-token", "x-application-context", "x-amz-cf-id",
                  "cf-ray", "x-vercel-id", "x-umbraco-version", "x-owa-version"}
VERSION_HEADERS = {"server", "x-powered-by", "x-generator", "x-aspnet-version", "x-aspnetmvc-version",
                   "x-jenkins", "x-umbraco-version", "x-owa-version"}
_SKIP_EXT = re.compile(r"\.(?:pdf|zip|rar|7z|gz|tgz|exe|dmg|apk|iso|mp[34]|avi|mov|webm|jpe?g|png|gif|svg|webp|"
                       r"ico|woff2?|ttf|eot|docx?|xlsx?|pptx?|csv|xml|json|css|js)$", re.I)
# never follow links that may change state when a session cookie is in use
_UNSAFE = re.compile(r"log-?_?out|sign-?_?out|log-?off|\bsair\b|delete|remove|excluir|unsubscribe|destroy", re.I)
_INTERESTING = re.compile(r"\b(?:todo|fixme|password|senha|passwd|debug|staging|homolog|internal|backup)\b|"
                          r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}\b", re.I)
_WP = re.compile(r"/wp-content/(plugins|themes)/([\w\-.]+)/(?:[^\"'<>\s?]*\?ver=(\d[\w.\-]*))?", re.I)
_CHALLENGE = re.compile(r"just a moment|client challenge|attention required|access denied|"
                        r"checking your browser|verify you are human|request rejected", re.I)


@dataclass
class Options:
    level: int = 2
    max_pages: int = 10
    max_scripts: int = 30
    threads: int = 8
    ports: tuple = ()
    follow: bool = True


@dataclass
class Result:
    target: str
    url: str = ""
    status: int = 0
    reason: str = ""
    title: str = ""
    ip: str = ""
    http_version: str = ""
    redirects: list = field(default_factory=list)       # (status, url)
    tls: dict = field(default_factory=dict)
    banner: list = field(default_factory=list)          # (header, value)
    services: list = field(default_factory=list)        # (port, banner)
    technologies: list = field(default_factory=list)
    leaks: list = field(default_factory=list)
    packages: list = field(default_factory=list)        # npm packages without a signature
    components: list = field(default_factory=list)      # WP plugins/themes, unknown licence comments
    endpoints: list = field(default_factory=list)
    internal_links: list = field(default_factory=list)
    external_hosts: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    comments: list = field(default_factory=list)
    pages: int = 0
    scripts: int = 0
    requests: int = 0
    warning: str = ""
    error: str = ""


def candidates(target):
    """URLs to try, in order. Without a scheme: https first, then http."""
    t = target.strip()
    urls = [t] if "://" in t else ["https://" + t, "http://" + t]
    for u in urls:
        s = urlsplit(u)
        s.port      # ValueError when it is not a number
        if s.scheme not in ("http", "https") or not s.hostname or re.search(r"\s", u):
            raise ValueError(f"invalid target: {target}")
        if s.username is not None:
            raise ValueError("credentials in the URL are not supported, use -H 'Authorization: ...'")
    return urls


class Scanner:
    def __init__(self, client, options=None, log=lambda msg: None):
        self.client, self.opt, self.log = client, options or Options(), log

    def scan(self, target):
        self.engine, self.res = Engine(), Result(target)
        res, start = self.res, self.client.requests
        # dicts used as ordered sets
        self._links, self._ext, self._subs = {}, {}, {}
        self._endpoints, self._packages, self._components = {}, {}, {}
        try:
            first = self._open(target)
        except (FetchError, ValueError) as exc:
            res.error = str(exc)
            res.requests = self.client.requests - start
            return res
        self.host = (urlsplit(first.url).hostname or "").lower()
        self.site = site_of(self.host)
        self._describe(first)
        scripts = self._crawl(first)
        if self.opt.level >= 2:
            self._scripts(scripts)
            self._error_page(first.url)
        if self.opt.level >= 3:
            self._probes(first.url)
        if self.opt.ports:
            self._services()
        self._leaks()
        res.technologies = self.engine.results()
        res.endpoints = list(self._endpoints)
        res.packages = sorted(self._packages)
        known = {t.name.lower().replace(" ", "-") for t in res.technologies}
        res.components = [f"{n} {v}".strip() for n, v in sorted(self._components.items())
                          if n.rsplit(": ", 1)[-1].lower() not in known]
        res.internal_links = list(self._links)
        res.external_hosts = sorted(self._ext)
        res.subdomains = sorted(self._subs)
        res.requests = self.client.requests - start
        return res

    # ------------------------------------------------------------ first page
    def _open(self, target):
        error = None
        for url in candidates(target):
            self.client.allow(urlsplit(url).hostname)
            try:
                return self.client.get(url, follow=self.opt.follow)
            except FetchError as exc:
                error = error or exc
        raise error

    def _describe(self, r):
        res = self.res
        res.url, res.status, res.reason, res.http_version = r.url, r.status, r.reason, r.http_version
        res.tls = r.tls
        res.redirects = [(c.status, c.url) for c in r.chain]
        if not self.client.proxy:   # behind a proxy the name may not even resolve here
            try:
                res.ip = socket.getaddrinfo(self.host, None, type=socket.SOCK_STREAM)[0][4][0]
            except (OSError, UnicodeError):
                pass
        for hop in r.chain:
            # a redirect from another site says nothing about this one
            if site_of(urlsplit(hop.url).hostname) == self.site:
                self._response(hop)
        for k, v in r.headers:
            if k.lower() in BANNER_HEADERS or k.lower().startswith("x-powered"):
                res.banner.append((k, v))
        if r.tls.get("issuer"):
            self.engine.match("cert", r.tls["issuer"], r.url, "certificate")
        for name in r.tls.get("names", ()):
            name = name.lower().removeprefix("*.")
            if site_of(name) == self.site and name != self.host:
                self._subs[name] = 1

    # ------------------------------------------------------------ analysis
    def _response(self, r):
        for k, v in r.headers:
            if k.lower() != "set-cookie":
                self.engine.match_pair("header", k, v, r.url)
        for c in r.cookie_names:
            self.engine.match("cookie", c, r.url)

    def _same_host(self, url):
        return (urlsplit(url).hostname or "").lower() == self.host

    def _own(self, url):
        return site_of(urlsplit(url).hostname) == self.site

    def _page(self, r):
        """Analyses one page; returns its parsed form (None when it is not HTML)."""
        self._response(r)
        self.res.pages += 1
        if not r.is_html:
            return None
        p, e = pg.parse(r.body, r.url), self.engine
        e.match("html", r.body, r.url)
        for name, content in p.metas:
            e.match_pair("meta", name, content, r.url)
        files = set(p.scripts + p.styles + p.assets)
        for s in p.scripts:
            e.match("script", s, r.url)
        for s in p.styles:
            e.match("css", s, r.url)
        for s in p.scripts + p.styles + p.assets + p.forms + p.links:
            # a static file may live on a sibling host, but a link to one says nothing about this one
            if self._same_host(s) or (self._own(s) and s in files):
                e.match("asset", s, r.url)
                for m in _WP.finditer(s):
                    key = f"WordPress {m.group(1)[:-1].lower()}: {m.group(2)}"
                    self._components[key] = m.group(3) or self._components.get(key, "")
        for code in p.inline:
            self._code(code, r.url)
        for c in p.comments:
            if len(c) <= 300 and _INTERESTING.search(c) and c not in self.res.comments:
                self.res.comments.append(c)
        pages = set(p.links + p.forms)
        for u in p.links + p.forms + p.scripts + p.styles + p.assets:
            h = (urlsplit(u).hostname or "").lower()
            if h == self.host:
                if u in pages:
                    self._links[urlunsplit(urlsplit(u)._replace(fragment=""))] = 1
            elif site_of(h) == self.site:
                self._subs[h] = 1
            else:
                self._ext[h] = 1
        return p

    def _code(self, js, url):
        self.engine.match("js", js, url)
        for name, version in pg.license_banners(js):
            if not self.engine.add_license(name, version, url):
                self._components.setdefault(f"JS: {name}", version)
        for ep in pg.endpoints(js):
            self._endpoints[ep] = 1

    # ------------------------------------------------------------ requests
    def _get_many(self, urls):
        def one(u):
            try:
                return u, self.client.get(u, same_site=self.site)
            except (FetchError, ValueError) as exc:
                self.log(f"{u}: {exc}")
                return u, None
        with ThreadPoolExecutor(self.opt.threads) as pool:
            return list(pool.map(one, urls))

    def _crawl(self, first):
        scripts, seen, queue = {}, {first.url}, deque()

        def collect(parsed):
            for s in parsed.scripts if parsed else ():
                if self._own(s):
                    scripts[clean_url(s)] = 1
            for link in parsed.links if parsed else ():
                u = clean_url(link)
                s = urlsplit(u)
                if ((s.hostname or "").lower() == self.host and u not in seen
                        and not _SKIP_EXT.search(s.path) and not _UNSAFE.search(s.path + "?" + s.query)):
                    seen.add(u)
                    queue.append(u)

        p = self._page(first)
        if p:
            self.res.title = p.title
        if _CHALLENGE.search(self.res.title) or (first.status in (403, 429, 503)):
            self.res.warning = ("the answer looks like a block or challenge page (WAF / anti-bot): "
                                "the real site may use other technologies")
        collect(p)
        while self.opt.level >= 2 and queue and self.res.pages < self.opt.max_pages:
            n = min(self.opt.threads, self.opt.max_pages - self.res.pages, len(queue))
            batch = [queue.popleft() for _ in range(n)]
            self.log(f"crawling {n} page(s)")
            for _, r in self._get_many(batch):
                if r is None:
                    self.res.pages += 1     # failures count, so a dead site ends quickly
                elif not self._same_host(r.url):
                    self.res.pages += 1     # redirected to a sibling host: another server
                elif r.url not in seen or not r.chain:
                    seen.add(r.url)
                    collect(self._page(r))
                else:
                    self.res.pages += 1     # redirected to a page already queued or read
        return list(scripts)

    def _scripts(self, urls):
        maps = {}
        self.log(f"reading {min(len(urls), self.opt.max_scripts)} script(s)")
        for _, r in self._get_many(urls[:self.opt.max_scripts]):
            # a soft 404 (HTML) is not JavaScript
            if r is None or r.status != 200 or "html" in r.header("content-type").lower():
                continue
            self.res.scripts += 1
            if self._same_host(r.url):
                self._response(r)
            self._code(r.body, r.url)
            try:
                m = r.header("sourcemap") or r.header("x-sourcemap")
                m = urljoin(r.url, m) if m else pg.source_map_url(r.body, r.url)
                if m and m.startswith(("http://", "https://")) and self._own(m):
                    maps[m] = 1
            except ValueError:
                pass
        if self.opt.level < 3:
            return
        for _, r in self._get_many(list(maps)[:10]):
            packages = pg.source_map_packages(r.body) if r and r.status == 200 else None
            if packages is None:
                continue
            self.res.leaks.append(f"Source map exposed: {r.url}")
            for name in packages:
                if not self.engine.add_npm(name, r.url):
                    self._packages[name] = 1

    def _error_page(self, base):
        (_, r), (_, robots) = self._get_many([urljoin(base, "/" + secrets.token_hex(8)),
                                              urljoin(base, "/robots.txt")])
        if r is not None and self._same_host(r.url):
            self._response(r)
            if r.status >= 400:
                self.engine.match("error", r.body, r.url, "error page")
        if robots is not None and robots.status == 200 and not robots.is_html:
            self.engine.match("robots", robots.body, robots.url, "robots.txt")

    def _probes(self, base):
        todo = {}
        for sig in self.engine.signatures.values():
            for path, pattern in sig.probe:
                todo.setdefault(urljoin(base, path), []).append((sig, pattern))
        self.log(f"probing {len(todo)} known paths")
        for u, r in self._get_many(list(todo)):
            for sig, pattern in todo[u] if r else ():
                self.engine.match_probe(sig, pattern, r.body, u)

    def _services(self):
        self.log(f"reading the banner of {len(self.opt.ports)} port(s)")
        with ThreadPoolExecutor(self.opt.threads) as pool:
            banners = pool.map(lambda p: (p, grab_banner(self.host, p, min(self.client.timeout, 5))), self.opt.ports)
            for port, banner in banners:
                if banner is None:
                    continue
                self.res.services.append((port, " ".join(banner.split())))
                self.engine.match("banner", banner, f"tcp/{port}", f"banner tcp/{port}")

    def _leaks(self):
        for k, v in self.res.banner:
            if k.lower() in VERSION_HEADERS and re.search(r"\d+\.\d+", v):
                self.res.leaks.append(f"Version in response header: {k}: {v}")
        if self.res.tls and not self.res.tls["trusted"]:
            self.res.leaks.append(f"TLS certificate not verified: {self.res.tls.get('error') or 'unknown reason'}")
