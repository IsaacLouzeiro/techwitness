import io
import json
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from techwitness import cli, output, page  # noqa: E402
from techwitness.engine import Engine  # noqa: E402
from techwitness.fetch import Client, grab_banner, site_of  # noqa: E402
from techwitness.scanner import Options, Scanner, candidates  # noqa: E402
from techwitness.signatures import SIGNATURES  # noqa: E402

HOME = """<html><head><title>Shop &amp; Co</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css?ver=5.8.1">
<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css?ver=1.3">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="/app.js"></script></head>
<body><!-- TODO remove staging password -->
<a href="/about">about</a> <a href="/logout">x</a> <a href="https://other.example/wp-content/x">o</a></body></html>"""
APP = ("/*! DataTables 1.13.4 (c) */ var a='/api/v1/users';"
       "\n/*! Unheard Lib v2.1.0 */\n//# sourceMappingURL=app.js.map")
MAP = json.dumps({"version": 3, "sources": ["webpack:///node_modules/react/index.js",
                                            "webpack:///./node_modules/@acme/kit/a.js", "src/x.js"]})


class Handler(BaseHTTPRequestHandler):
    server_version, sys_version = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3", ""
    hits = []

    def do_GET(self):
        Handler.hits.append((self.path, self.headers.get("Cookie")))
        routes = {"/denied": ("text/html", "<title>Access Denied</title>"), "/": ("text/html", HOME), "/about": ("text/html", "<p data-v-app>x</p>"),
                  "/app.js": ("application/javascript", APP), "/app.js.map": ("application/json", MAP)}
        if self.path == "/go":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/")
            self.end_headers()
            return
        ctype, body = routes.get(self.path, ("text/html", "<pre>Cannot GET /x</pre>"))
        self.send_response(200 if self.path in routes else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Set-Cookie", "PHPSESSID=abc; path=/")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class ScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def scan(self, path="", headers=(), **kw):
        Handler.hits.clear()
        res = Scanner(Client(5, headers=headers), Options(**kw)).scan(self.url + path)
        return res, {t.name: t for t in res.technologies}

    def test_default_scan(self):
        res, t = self.scan()
        self.assertEqual(res.title, "Shop & Co")
        for name, version in (("Apache HTTP Server", "2.4.41"), ("PHP", "7.4.3"), ("OpenSSL", "1.1.1f"),
                              ("WordPress", "6.4.2"), ("jQuery", "3.6.0"), ("DataTables", "1.13.4"),
                              ("Contact Form 7", "5.8.1")):
            self.assertEqual(t[name].version, [version], name)
        self.assertIn("Ubuntu", t)
        self.assertEqual(t["MySQL / MariaDB"].implied_by, ["WordPress"])
        self.assertNotIn("Magento", t)
        self.assertIn("Express", t)      # 404 page
        self.assertIn("Vue.js", t)       # only on the crawled page
        self.assertIn("/api/v1/users", res.endpoints)
        self.assertIn("WordPress theme: mytheme 1.3", res.components)
        self.assertIn("JS: Unheard Lib 2.1.0", res.components)
        self.assertTrue(any("staging" in c for c in res.comments))
        self.assertEqual(res.external_hosts, ["code.jquery.com", "other.example"])

    def test_never_follows_logout_or_probes_by_default(self):
        self.scan()
        paths = {p for p, _ in Handler.hits}
        for path in ("/logout", "/wp-login.php", "/app.js.map"):
            self.assertNotIn(path, paths)

    def test_level_1_is_a_single_request(self):
        res, _ = self.scan(level=1)
        self.assertEqual((len(Handler.hits), res.requests), (1, 1))

    def test_level_3_reads_source_map(self):
        res, t = self.scan(level=3)
        self.assertIn("React", t)
        self.assertEqual(res.packages, ["@acme/kit"])
        self.assertTrue(any("Source map" in x for x in res.leaks))

    def test_max_pages(self):
        self.assertEqual(self.scan(max_pages=1)[0].pages, 1)

    def test_custom_headers_do_not_follow_a_redirect_to_another_host(self):
        self.scan("go", headers=[("Cookie", "secret=1")], level=1)
        sent = dict(Handler.hits)
        self.assertEqual(sent["/go"], "secret=1")
        self.assertIsNone(sent["/"])

    def test_cli_json_and_files(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main([self.url, "-j", "-o", f"{d}/r.csv"]), 0)
            self.assertEqual(json.loads(out.getvalue())[0]["status"], 200)
            self.assertIn("WordPress,6.4.2", Path(d, "r.csv").read_text())
            with redirect_stdout(io.StringIO()):
                cli.main([self.url, "-q", "-v", "-l", "-o", f"{d}/r.txt"])
            self.assertIn("Third-party hosts", Path(d, "r.txt").read_text())

    def test_sibling_hosts_do_not_count(self):
        s = Scanner(Client())
        s.host, s.site = "www.example.com", "example.com"
        self.assertTrue(s._own("https://blog.example.com/x"))
        self.assertFalse(s._same_host("https://blog.example.com/x"))

    def test_block_page_warning(self):
        self.assertIn("challenge", self.scan("denied", level=1)[0].warning)
        self.assertEqual(self.scan()[0].warning, "")

    def test_unreachable(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        res = Scanner(Client(2)).scan(f"http://127.0.0.1:{port}")
        self.assertEqual(res.error, "connection refused")

    def test_tcp_banner(self):
        s = socket.create_server(("127.0.0.1", 0))

        def serve():
            c, _ = s.accept()
            c.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        text = grab_banner("127.0.0.1", s.getsockname()[1], 2)
        s.close()
        e = Engine()
        e.match("banner", text)
        found = {t.name: t.version for t in e.results()}
        self.assertEqual(found["OpenSSH"], ["8.9p1"])
        self.assertIn("Ubuntu", found)


class UnitTest(unittest.TestCase):
    def names(self, kind, text):
        e = Engine()
        e.match(kind, text)
        return {t.name: t.version for t in e.results()}

    def server(self, value):
        e = Engine()
        e.match_pair("header", "Server", value)
        return {t.name: t.version for t in e.results()}

    def test_implied_names_exist(self):
        for s in SIGNATURES.values():
            for i in s.implies:
                self.assertIn(i, SIGNATURES)

    def test_script_urls(self):
        for url, name, version in (
                ("https://cdn.jsdelivr.net/npm/vue@3.4.1/dist/vue.global.js", "Vue.js", "3.4.1"),
                ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", "jQuery", "3.7.1"),
                ("https://x.y/js/jquery.min.js?ver=3.5.1", "jQuery", "3.5.1"),
                ("https://x.y/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js", "Bootstrap", "5.3.2"),
                ("https://x.y/angular.js/1.8.2/angular.min.js", "AngularJS", "1.8.2")):
            self.assertEqual(self.names("script", url).get(name), [version], url)

    def test_no_false_positives(self):
        self.assertNotIn("jQuery", self.names("script", "https://x.y/jquery.cookie.js"))
        self.assertNotIn("React", self.names("script", "https://x.y/react-calendar.js"))
        self.assertNotIn("Apache HTTP Server", self.server("Apache-Coyote/1.1"))
        self.assertNotIn("nginx", self.server("not-nginx"))
        self.assertEqual(self.names("html", "<p>We love WordPress, Drupal and Laravel</p>"), {})

    def test_weak_evidence_adds_up(self):
        e = Engine()
        e.match_pair("header", "Server", "Werkzeug/3.0.1 Python/3.11.4")
        self.assertNotIn("Flask", {t.name for t in e.results()})
        e.match("error", "The requested URL was not found on the server. If you entered the URL manually")
        self.assertIn("Flask", {t.name for t in e.results()})

    def test_same_rule_counts_once(self):
        e = Engine()
        for u in ("a", "b", "c"):
            e.match_pair("header", "Server", "Werkzeug/3.0", u)
        self.assertNotIn("Flask", {t.name for t in e.results()})

    def test_less_detailed_version_is_dropped(self):
        e = Engine()
        for v in ("1.18", "1.18.0", "1.18"):
            e.add("nginx", "x", v, version=v)
        self.assertEqual(e.results()[0].version, ["1.18.0"])

    def test_site_of(self):
        self.assertEqual(site_of("a.b.example.com.br"), "example.com.br")
        self.assertEqual(site_of("www.example.com"), "example.com")
        self.assertEqual(site_of("10.0.0.1"), "10.0.0.1")

    def test_targets(self):
        self.assertEqual(candidates("a.com:8080"), ["https://a.com:8080", "http://a.com:8080"])
        for bad in ("ftp://a.com", "http://", "http://a:x/", "http://u:p@a.com"):
            with self.assertRaises(ValueError):
                candidates(bad)

    def test_untrusted_text(self):
        self.assertEqual(output.safe("a\x1b[31mb‮"), "a?[31mb?")
        self.assertEqual(output._cell("=cmd()"), "'=cmd()")

    def test_source_map_rejects_other_content(self):
        for text in ("<html>", "[1]", "{}"):
            self.assertIsNone(page.source_map_packages(text))

    def test_broken_html(self):
        p = page.parse("<a href='http://[bad'>x</a><a href='http://h:99x/'>y</a><![foo", "http://a/")
        self.assertEqual(p.links, [])


if __name__ == "__main__":
    unittest.main()
