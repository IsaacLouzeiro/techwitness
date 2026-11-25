"""Small HTTP client on top of http.client: keeps the raw headers (order and
repetitions), records the redirect chain and limits how much is downloaded."""

import base64
import http.client
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

MAX_BODY = 3 * 1024 * 1024
MAX_REDIRECTS = 8
DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/140.0.0.0 Safari/537.36")


class FetchError(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list               # [(name, value)], as received
    body: str
    http_version: str = ""
    truncated: bool = False
    chain: list = field(default_factory=list)   # responses that redirected here
    tls: dict = field(default_factory=dict)

    def header(self, name):
        return next((v for k, v in self.headers if k.lower() == name.lower()), "")

    @property
    def cookie_names(self):
        return [v.split("=", 1)[0].strip() for k, v in self.headers
                if k.lower() == "set-cookie" and "=" in v]

    @property
    def is_html(self):
        ctype = self.header("content-type").lower()
        return "html" in ctype or (not ctype and "<" in self.body[:500])


def clean_url(url):
    """Drops the fragment and percent-encodes whatever cannot go on a request line."""
    s = urlsplit(url)
    return urlunsplit((s.scheme.lower(), s.netloc, quote(s.path or "/", safe="/%:@!$&'()*+,;=~-._"),
                       quote(s.query, safe="=&%:/?@!$'()*+,;~-._[]"), ""))


def origin(url):
    s = urlsplit(url)
    return s.scheme, (s.hostname or "").lower(), s.port or (443 if s.scheme == "https" else 80)


# Second-level labels used as public suffixes, as in example.com.br
_SLD = {"com", "co", "gov", "org", "net", "edu", "ac", "mil", "jus", "leg", "ind", "art", "blog", "dev",
        "app", "eco", "adv", "mp", "def", "tv", "or", "ne", "go"}


def site_of(host):
    """Approximate registrable domain (no public suffix list)."""
    host = (host or "").lower().rstrip(".")
    labels = host.split(".")
    if host.replace(".", "").isdigit() or ":" in host or len(labels) <= 2:
        return host
    n = 3 if len(labels[-1]) == 2 and labels[-2] in _SLD else 2
    return ".".join(labels[-n:])


def _permissive_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:    # old servers are exactly what a recon tool runs into
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ssl.SSLError, ValueError):
        pass
    return ctx


def _tls_info(sock, verified):
    info = {"version": sock.version() or "", "cipher": (sock.cipher() or [""])[0], "trusted": verified}
    cert = sock.getpeercert() or {}
    for key in ("issuer", "subject"):
        pairs = [p for rdn in cert.get(key, ()) for p in rdn]
        info[key] = ", ".join(f"{'O' if k == 'organizationName' else 'CN'}={v}" for k, v in pairs
                              if k in ("organizationName", "commonName"))
    info["expires"] = cert.get("notAfter", "")
    info["names"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    return info


class Client:
    def __init__(self, timeout=10, user_agent=DEFAULT_UA, headers=(), proxy=None, max_body=MAX_BODY):
        self.timeout = timeout
        self.user_agent = user_agent
        self.extra = list(headers)
        self.max_body = max_body
        self.proxy = None
        if proxy:
            p = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            if p.scheme != "http" or not p.hostname:
                raise ValueError("only http:// proxies are supported")
            self.proxy = p
        self.allowed = set()    # hosts that may receive the custom headers
        self.requests = 0
        self._unverified = set()
        self.tls_errors = {}

    def allow(self, host):
        host = (host or "").lower()
        self.allowed |= {host, host[4:] if host.startswith("www.") else "www." + host}

    def _headers(self, host):
        h = {"User-Agent": self.user_agent,
             "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
             "Accept-Language": "en;q=0.9,pt-BR;q=0.8", "Connection": "close"}
        if host in self.allowed:
            for name, value in self.extra:
                h = {k: v for k, v in h.items() if k.lower() != name.lower()}
                h[name] = value
        # the body has to stay readable whatever the user passes
        h = {k: v for k, v in h.items() if k.lower() != "accept-encoding"}
        h["Accept-Encoding"] = "gzip, deflate"
        return h

    def _proxy_auth(self):
        if not (self.proxy and self.proxy.username):
            return {}
        cred = f"{unquote(self.proxy.username)}:{unquote(self.proxy.password or '')}"
        return {"Proxy-Authorization": "Basic " + base64.b64encode(cred.encode()).decode()}

    def _connect(self, scheme, host, port, verify):
        addr = (self.proxy.hostname, self.proxy.port or 8080) if self.proxy else (host, port)
        if scheme == "https":
            ctx = ssl.create_default_context() if verify else _permissive_context()
            conn = http.client.HTTPSConnection(*addr, timeout=self.timeout, context=ctx)
            if self.proxy:
                conn.set_tunnel(host, port, self._proxy_auth())
        else:
            conn = http.client.HTTPConnection(*addr, timeout=self.timeout)
        return conn

    def _once(self, url):
        scheme, host, port = origin(url)
        if scheme not in ("http", "https") or not host:
            raise FetchError(f"unsupported URL: {url}")
        s = urlsplit(url)
        target = (s.path or "/") + ("?" + s.query if s.query else "")
        headers = self._headers(host)
        if self.proxy and scheme == "http":
            hostport = f"[{host}]" if ":" in host else host
            target = f"http://{hostport}:{port}{target}"
            headers.setdefault("Host", hostport + (f":{port}" if port != 80 else ""))
            headers.update(self._proxy_auth())
        verify = (host, port) not in self._unverified
        self.requests += 1
        conn = self._connect(scheme, host, port, verify)
        try:
            try:
                conn.connect()
            except ssl.SSLError as exc:
                if not verify:
                    raise
                conn.close()
                self._unverified.add((host, port))
                self.tls_errors[(host, port)] = getattr(exc, "verify_message", "") or exc.reason or str(exc)
                verify = False
                conn = self._connect(scheme, host, port, False)
                conn.connect()
            tls = _tls_info(conn.sock, verify) if scheme == "https" else {}
            if tls and not verify:
                tls["error"] = self.tls_errors.get((host, port), "")
            conn.request("GET", target, headers=headers)
            r = conn.getresponse()
            body, truncated = self._read(r)
            version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(r.version, "")
            hdrs = list(r.getheaders())
        except (OSError, http.client.HTTPException, ValueError, EOFError) as exc:
            raise FetchError(describe(exc)) from exc
        finally:
            conn.close()
        return Response(url, r.status, r.reason, hdrs, self._decode(body, hdrs), version, truncated, [], tls)

    def _read(self, r):
        encoding = (r.getheader("Content-Encoding") or "").lower()
        inflate = None
        if encoding in ("gzip", "x-gzip", "deflate"):
            inflate = zlib.decompressobj(47 if "gzip" in encoding else 15)
        out, deadline = bytearray(), time.monotonic() + self.timeout * 2
        while len(out) < self.max_body:
            try:
                chunk = r.read1(65536)
            except (OSError, http.client.HTTPException):
                if out:
                    return bytes(out), True     # keep what arrived
                raise
            if not chunk:
                return bytes(out), False
            if inflate:
                room = self.max_body - len(out)
                raw = chunk
                try:
                    chunk = inflate.decompress(raw, room)
                except zlib.error:
                    if encoding != "deflate" or out:
                        return bytes(out), True
                    inflate = zlib.decompressobj(-15)   # headerless deflate
                    try:
                        chunk = inflate.decompress(raw, room)
                    except zlib.error:
                        return b"", True
            out += chunk
            if time.monotonic() > deadline:
                break
        return bytes(out[:self.max_body]), True

    @staticmethod
    def _decode(body, headers):
        ctype = next((v for k, v in headers if k.lower() == "content-type"), "").lower()
        charset = ctype.split("charset=", 1)[1].split(";")[0].strip(" \"'") if "charset=" in ctype else "utf-8"
        try:
            return body.decode(charset, "replace")
        except (LookupError, ValueError):
            return body.decode("latin-1")

    def get(self, url, follow=True, same_site=None):
        """GET. With same_site, redirects that leave that site are not followed."""
        url, chain = clean_url(url), []
        while True:
            r = self._once(url)
            location = r.header("location")
            if not (follow and r.status in (301, 302, 303, 307, 308) and location):
                break
            try:
                nxt = clean_url(urljoin(url, location))
                host = origin(nxt)[1]
            except ValueError:
                break
            if not nxt.startswith(("http://", "https://")) or len(chain) >= MAX_REDIRECTS or nxt == url:
                break
            if same_site and site_of(host) != same_site:
                break
            chain.append(r)
            url = nxt
        r.chain = chain
        return r


def describe(exc):
    if isinstance(exc, TimeoutError):
        return "connection timed out"
    if isinstance(exc, socket.gaierror):
        return "could not resolve host"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, http.client.RemoteDisconnected):
        return "server closed the connection without answering"
    return f"{type(exc).__name__}: {exc}"


# ------------------------------------------------------------------ TCP banners
DEFAULT_PORTS = (21, 22, 25, 110, 143, 587, 3306, 6379)


def grab_banner(host, port, timeout=4):
    """Connects and returns what the service says on its own (None: closed/filtered)."""
    try:
        with socket.create_connection((host, port), timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(512)
            except OSError:
                # silent service: an empty line makes some of them answer
                try:
                    s.sendall(b"\r\n")
                    data = s.recv(512)
                except OSError:
                    return ""
            return data.decode("latin-1")
    except (OSError, UnicodeError):
        return None
