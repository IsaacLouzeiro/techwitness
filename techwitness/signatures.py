r"""Technology signatures.

Every signature is a T(name, category, ...) call. All patterns are case-insensitive
regular expressions and group 1, when present, captures the version.

Fields:
    header  {header name: pattern}      response headers
    cookie  [pattern]                   cookie names (whole name)
    meta    {meta name: pattern}        <meta name/property=... content=...>
    html    [pattern]                   page HTML
    script  [pattern]                   URL of any <script src>, third parties included
    asset   [pattern]                   URL of scripts, styles, images and links of the
                                        target's own site only
    css     [pattern]                   URL of any stylesheet, third parties included
    js      [pattern]                   inline scripts and downloaded JS files
    error   [pattern]                   body of the 404 page
    robots  [pattern]                   robots.txt
    cert    [pattern]                   TLS certificate issuer
    banner  [pattern]                   TCP service banner (--ports)
    probe   [(path, pattern)]           extra request, aggression level 3 only
    npm     [name]                      package name found in a source map (level 3)
    implies [name]                      other technologies that must also be there

Prefix a pattern with "50%" to lower its confidence (anything from 1% to 99%).
Weak matches of one technology add up; below 50% it is not reported.
"""

import re
from dataclasses import dataclass, field

LIST_FIELDS = ("cookie", "html", "script", "asset", "css", "js", "error",
               "robots", "cert", "banner")
DICT_FIELDS = ("header", "meta")


class Pattern:
    __slots__ = ("regex", "confidence")

    def __init__(self, text):
        m = re.match(r"(\d{1,2})%", text)
        self.confidence = int(m.group(1)) if m else 100
        self.regex = re.compile(text[m.end():] if m else text, re.I)


@dataclass
class Signature:
    name: str
    category: str
    implies: list = field(default_factory=list)
    npm: list = field(default_factory=list)
    probe: list = field(default_factory=list)
    rules: dict = field(default_factory=dict)


SIGNATURES = {}


def T(name, category, implies=(), npm=(), probe=(), **rules):
    if name in SIGNATURES:
        raise ValueError(f"duplicated signature: {name}")
    sig = Signature(name, category, list(implies), list(npm),
                    [(path, Pattern(p)) for path, p in probe])
    for kind, value in rules.items():
        if kind in LIST_FIELDS:
            sig.rules[kind] = [Pattern(p) for p in value]
        elif kind in DICT_FIELDS:
            sig.rules[kind] = {k.lower(): Pattern(p) for k, p in value.items()}
        else:
            raise ValueError(f"{name}: unknown field {kind}")
    SIGNATURES[name] = sig


V = r"(\d+(?:\.\d+)+)"          # 1.2, 1.2.3 ...
NV = r"(?:[ /]v?(\d[\w.\-]*))?"  # optional " 1.2" or "/1.2"


def lib(name, files, category="JavaScript library", js=(), npm=(), **kw):
    """Signature of a JS library: recognises the usual file names and CDN layouts."""
    f = f"(?:{files})"
    script = [
        rf"/{f}(?:\.js)?[@/]v?{V}/",                                # cdn/lib@1.2.3/, cdn/lib/1.2.3/
        rf"/{f}[.\-]v?{V}(?:[.\-](?:slim|min|bundle|umd|prod))*\.js",  # lib-1.2.3.min.js
        rf"/{f}(?:[.\-](?:slim|min|bundle|umd|prod|production))*\.js(?:\?(?:ver|v|version)={V})?(?:$|[?&#])",
    ]
    T(name, category, script=script + list(kw.pop("script", [])), js=list(js),
      npm=npm, **kw)


# ---------------------------------------------------------------- web servers
T("Apache HTTP Server", "Web server",
  header={"server": rf"\bApache(?:/{V}|(?![\w\-]))(?!.*coyote)"},
  error=[rf"<address>Apache(?:/{V})?[^<]* Server at "])
T("nginx", "Web server", header={"server": rf"^nginx(?:/{V})?", },
  error=[rf"<center>nginx(?:/{V})?</center>"])
T("OpenResty", "Web server", implies=["nginx", "Lua"],
  header={"server": rf"openresty(?:/{V})?"}, error=[rf"<center>openresty(?:/{V})?</center>"])
T("Tengine", "Web server", header={"server": rf"tengine(?:/{V})?"},
  error=[rf"<center>tengine(?:/{V})?</center>"])
T("Microsoft IIS", "Web server", implies=["Windows Server"],
  header={"server": rf"Microsoft-IIS(?:/{V})?"},
  error=[r"<title>IIS ([\d.]+) Detailed Error", r"60%<h2>404 - File or directory not found\.</h2>"])
T("Microsoft HTTPAPI", "Web server", implies=["Windows Server"],
  header={"server": rf"Microsoft-HTTPAPI(?:/{V})?"})
T("LiteSpeed", "Web server", header={"server": rf"^LiteSpeed(?:/{V})?", "x-litespeed-cache": r"."},
  error=[r"Proudly powered by LiteSpeed Web Server"])
T("Caddy", "Web server", header={"server": rf"^Caddy(?:/{V})?", "via": r"\bCaddy\b"})
T("lighttpd", "Web server", header={"server": rf"lighttpd(?:/{V})?"},
  error=[rf"<address>lighttpd(?:/{V})?"])
T("Apache Tomcat", "Application server", implies=["Java"],
  header={"server": r"Apache[- ](?:Tomcat|Coyote)"},
  error=[rf"<h3>Apache Tomcat(?:/{V})?"],
  probe=[("/docs/", rf"<title>Apache Tomcat \d+ \({V}\)")])
T("Jetty", "Application server", implies=["Java"],
  header={"server": rf"Jetty\((\d[\w.\-]*)\)?"}, error=[r"Powered by Jetty://\s*(\d[\w.\-]*)?"])
T("WildFly / JBoss", "Application server", implies=["Java"],
  header={"server": r"(?:WildFly|JBoss)", "x-powered-by": r"(?:JBoss|WildFly|Undertow)"})
T("GlassFish", "Application server", implies=["Java"],
  header={"server": rf"GlassFish[\w ]*?(?: {V})?", "x-powered-by": r"GlassFish"})
T("Oracle WebLogic", "Application server", implies=["Java"],
  header={"server": r"WebLogic(?: Server)?(?: ([\d.]+))?", "x-powered-by": r"WebLogic"},
  cookie=[r"ADMINCONSOLESESSION"],
  error=[r"From RFC 2068 <i>Hypertext Transfer Protocol"])
T("IBM WebSphere", "Application server", implies=["Java"],
  header={"server": rf"WebSphere[\w ]*(?:/{V})?", "ibm-web2-location": r"."})
T("Oracle HTTP Server", "Web server", header={"server": rf"Oracle-HTTP-Server(?:-\w+)?(?:/{V})?"})
T("gunicorn", "Application server", implies=["Python"], header={"server": rf"gunicorn(?:/{V})?"})
T("uvicorn", "Application server", implies=["Python"], header={"server": r"uvicorn"})
T("Hypercorn", "Application server", implies=["Python"], header={"server": r"hypercorn"})
T("Werkzeug", "Application server", implies=["Python"],
  header={"server": rf"Werkzeug(?:/{V})?"},
  html=[r"<title>[^<]{0,200}// Werkzeug Debugger</title>"])
T("Waitress", "Application server", implies=["Python"], header={"server": r"waitress"})
T("Kestrel", "Application server", implies=["ASP.NET Core"], header={"server": r"Kestrel"})
T("Phusion Passenger", "Application server",
  header={"server": rf"Phusion[ _]Passenger(?:/{V})?", "x-powered-by": rf"Phusion Passenger\D*(?:{V})?"})
T("Cowboy", "Application server", implies=["Erlang"], header={"server": r"Cowboy"})
T("Zope", "Application server", implies=["Python"], header={"server": rf"Zope/\(?{V}?"})
T("Envoy", "Reverse proxy", header={"server": r"^envoy", "x-envoy-upstream-service-time": r"."})
T("Varnish", "Cache", header={"via": r"varnish(?: \(Varnish/([\d.]+)\))?", "x-varnish": r"."})
T("Squid", "Cache", header={"via": rf"squid(?:/{V})?", "server": rf"squid(?:/{V})?"})
T("HAProxy", "Reverse proxy", cookie=[r"50%SERVERID"], header={"server": r"HAProxy"})
T("Traefik", "Reverse proxy", cookie=[r"_?traefik\w*"], header={"server": r"Traefik"})
T("Kong", "API gateway", header={"via": rf"kong(?:/{V})?", "server": rf"kong(?:/{V})?",
                                 "x-kong-proxy-latency": r"."})

# ---------------------------------------------------------------- languages, OS, TLS
T("PHP", "Programming language", header={"x-powered-by": r"\bPHP(?:/(\d[\w.\-]*))?", "server": rf"\bPHP/{V}"},
  cookie=[r"PHPSESSID"], asset=[r"60%\.php(?:$|[?#])"])
T("Java", "Programming language", cookie=[r"JSESSIONID"],
  header={"x-powered-by": r"(?:Servlet|JSP)\b"}, asset=[r"60%\.(?:jsp|jsf|do)(?:$|[;?#])"])
T("ASP.NET", "Web framework", implies=["Microsoft IIS"],
  header={"x-aspnet-version": r"([\d.]+)", "x-powered-by": r"^ASP\.NET$"},
  cookie=[r"ASP\.NET_SessionId", r"\.ASPXAUTH", r"ASPSESSIONID\w+"],
  html=[r"<input[^>]+name=\"__VIEWSTATE"], asset=[r"60%\.aspx(?:$|[?#])"])
T("ASP.NET MVC", "Web framework", implies=["ASP.NET"], header={"x-aspnetmvc-version": r"([\d.]+)"},
  cookie=[r"__RequestVerificationToken\w*"])
T("ASP.NET Core", "Web framework", cookie=[r"\.AspNetCore\..+"])
T("Blazor", "Web framework", implies=["ASP.NET Core"],
  script=[r"_framework/blazor\.(?:web|server|webassembly)(?:\.\w+)?\.js"])
T("Python", "Programming language", header={"server": rf"\bC?Python/{V}", "x-powered-by": r"\bPython"})
T("Ruby", "Programming language", header={"server": rf"\bRuby/{V}"})
T("Perl", "Programming language", header={"server": rf"\b(?:mod_perl|Perl)/v?{V}"},
  asset=[r"60%\.pl(?:$|[?#])"])
T("Node.js", "Programming language", header={"x-powered-by": r"^Node\.?js"})
T("Lua", "Programming language", header={"server": rf"\bLua(?:JIT)?/{V}"})
T("Erlang", "Programming language", header={"server": rf"Erlang(?: OTP/{V})?"})
T("ColdFusion", "Application server", cookie=[r"CFID", r"CFTOKEN"], asset=[r"60%\.cfm(?:$|[?#])"])
T("OpenSSL", "Server module", header={"server": r"\bOpenSSL/(\d[\w.\-]*)"})
T("mod_ssl", "Server module", header={"server": rf"\bmod_ssl/{V}"})
T("mod_jk", "Server module", header={"server": rf"\bmod_jk/{V}"})
T("mod_wsgi", "Server module", implies=["Python"], header={"server": rf"\bmod_wsgi/{V}"})
T("mod_security", "WAF", header={"server": r"mod_security"}, error=[r"Mod_Security"])
for _os, _re in (("Ubuntu", r"Ubuntu"), ("Debian", r"Debian"), ("CentOS", r"CentOS"),
                 ("Red Hat", r"Red ?Hat"), ("Fedora", r"Fedora"), ("FreeBSD", r"FreeBSD"),
                 ("AlmaLinux", r"AlmaLinux"), ("Rocky Linux", r"Rocky")):
    T(_os, "Operating system", header={"server": rf"\({_re}[^)]*\)|\b{_re}\b", "x-powered-by": rf"\b{_re}"},
      banner=[_re])
T("Windows Server", "Operating system", header={"server": r"\(Win(?:32|64)\)"})
T("Let's Encrypt", "Certificate authority", cert=[r"Let's Encrypt"])
T("DigiCert", "Certificate authority", cert=[r"DigiCert"])
T("Sectigo", "Certificate authority", cert=[r"Sectigo|COMODO"])
T("GlobalSign", "Certificate authority", cert=[r"GlobalSign"])
T("Google Trust Services", "Certificate authority", cert=[r"Google Trust Services"])
T("Amazon Trust Services", "Certificate authority", cert=[r"O=Amazon|\bAmazon\b"])
T("GoDaddy CA", "Certificate authority", cert=[r"GoDaddy"])
T("ZeroSSL", "Certificate authority", cert=[r"ZeroSSL"])

# ---------------------------------------------------------------- frameworks
T("Laravel", "Web framework", implies=["PHP"], cookie=[r"laravel_session", r"laravel_token"],
  js=[r"window\.Laravel\s*="],
  html=[r"<title>Laravel</title>"])
T("Livewire", "Web framework", implies=["Laravel"], html=[r"\swire:(?:id|snapshot)="],
  script=[r"/livewire(?:\.min)?\.js"])
T("Inertia.js", "JavaScript framework", html=[r"<div[^>]+id=\"app\"[^>]+data-page=\"\{"],
  header={"x-inertia": r"."}, npm=["@inertiajs/core"])
T("Symfony", "Web framework", implies=["PHP"], header={"x-debug-token": r".", "x-debug-token-link": r"."},
  html=[r"sfWebDebugToolbar|id=\"sfwdt"])
T("CodeIgniter", "Web framework", implies=["PHP"], cookie=[r"ci_session", r"ci_csrf_token"])
T("CakePHP", "Web framework", implies=["PHP"], cookie=[r"CAKEPHP"])
T("Yii", "Web framework", implies=["PHP"], cookie=[r"YII_CSRF_TOKEN"],
  asset=[r"/assets/\w+/yii(?:\.\w+)?\.js"], html=[r"Powered by <a[^>]+yiiframework\.com"])
T("Zend Framework", "Web framework", implies=["PHP"], header={"x-powered-by": r"Zend"})
T("Django", "Web framework", implies=["Python"], cookie=[r"django_language"],
  html=[r"<input[^>]+name=[\"']csrfmiddlewaretoken"],
  error=[r"You're seeing this error because you have <code>DEBUG = True</code>"])
T("Flask", "Web framework", implies=["Python"],
  error=[r"25%The requested URL was not found on the server\. If you entered the URL manually"],
  header={"server": r"30%Werkzeug"})
T("FastAPI", "Web framework", implies=["Python"], error=[r"60%^\{\"detail\":\"Not Found\"\}$"],
  probe=[("/docs", r"<title>[^<]{0,100}Swagger UI</title>[\s\S]{0,2000}/openapi\.json")])
T("Ruby on Rails", "Web framework", implies=["Ruby"],
  header={"x-powered-by": rf"Phusion Passenger.*Rails|^Rails"},
  meta={"csrf-param": r"^authenticity_token$"}, asset=[r"/assets/application-[0-9a-f]{32,64}\.(?:js|css)"])
T("Sinatra", "Web framework", implies=["Ruby"], error=[r"Sinatra doesn&rsquo;t know this ditty"])
T("Express", "Web framework", implies=["Node.js"], header={"x-powered-by": r"^Express$"},
  error=[r"60%<pre>Cannot GET /"])
T("NestJS", "Web framework", implies=["Node.js"], error=[r"\"message\":\"Cannot GET /[^\"]+\",\"error\":\"Not Found\""])
T("Spring", "Web framework", implies=["Java"], header={"x-application-context": r"."},
  error=[r"Whitelabel Error Page", r"60%\"status\":404,\"error\":\"Not Found\",(?:\"\w+\":\"[^\"]*\",)*\"path\":"],
  probe=[("/actuator", r"\"_links\":\{\"self\":\{\"href\":\"[^\"]+/actuator")])
T("Apache Struts", "Web framework", implies=["Java"], asset=[r"60%\.action(?:$|[;?#])"],
  error=[r"Struts Problem Report|There is no Action mapped for"])
T("JavaServer Faces", "Web framework", implies=["Java"], html=[r"name=\"javax\.faces\.ViewState"],
  asset=[r"/javax\.faces\.resource/"])
T("PrimeFaces", "UI framework", implies=["JavaServer Faces"], asset=[r"primefaces\.js[^\"]*?[?&]v=([\d.]+)", r"ln=primefaces"])
T("Vaadin", "Web framework", implies=["Java"], js=[r"window\.Vaadin\s*=|vaadin\.initApplication"])
T("Play Framework", "Web framework", cookie=[r"PLAY_SESSION"])
T("Phoenix", "Web framework", implies=["Erlang"], html=[r"data-phx-(?:main|session|static)"])
T("Next.js", "JavaScript framework", implies=["React", "Node.js"], npm=["next"],
  header={"x-powered-by": r"^Next\.js ?([\d.]+)?", "x-nextjs-cache": r"."},
  html=[r"<script[^>]+id=\"__NEXT_DATA__\""], script=[r"/_next/static/"],
  js=[r"self\.__next_f\s*=", r"window\.next=\{version:\"([\d.]+)"])
T("Nuxt", "JavaScript framework", implies=["Vue.js"], npm=["nuxt"], script=[r"/_nuxt/"],
  html=[r"<div id=\"__nuxt\""], js=[r"window\.__NUXT__\s*="], header={"x-powered-by": r"^Nuxt"})
T("Gatsby", "Static site generator", implies=["React"], npm=["gatsby"],
  meta={"generator": r"^Gatsby ?([\d.]+)?"}, html=[r"<div id=\"___gatsby\""])
T("Astro", "Static site generator", meta={"generator": r"^Astro v?([\d.]+)?"}, html=[r"<astro-island\b"])
T("Remix", "JavaScript framework", implies=["React"], js=[r"window\.__remixContext\s*="])
T("SvelteKit", "JavaScript framework", implies=["Svelte"], html=[r"data-sveltekit-"], js=[r"__sveltekit_\w+\s*="],
  asset=[r"/_app/immutable/"])
T("Svelte", "JavaScript framework", npm=["svelte"], html=[r"class=\"[^\"]{0,200}\bsvelte-[a-z0-9]{5,7}\b"])
T("Hugo", "Static site generator", meta={"generator": r"^Hugo ?([\d.]+)?"})
T("Jekyll", "Static site generator", meta={"generator": r"^Jekyll ?v?([\d.]+)?"})
T("Hexo", "Static site generator", meta={"generator": r"^Hexo ?([\d.]+)?"})
T("Docusaurus", "Static site generator", implies=["React"], meta={"generator": r"^Docusaurus ?v?([\d.]+)?"})
T("VitePress", "Static site generator", implies=["Vue.js"], meta={"generator": r"^VitePress ?v?([\d.]+)?"})
T("MkDocs", "Static site generator", meta={"generator": r"^mkdocs-([\d.]+)"})
T("Sphinx", "Static site generator", html=[r"Created using <a[^>]+sphinx-doc\.org[^>]*>Sphinx</a> ?([\d.]+)?"])

# ---------------------------------------------------------------- front-end
T("React", "JavaScript framework", npm=["react", "react-dom"],
  script=[rf"/react(?:-dom)?@{V}/", rf"/react(?:-dom)?(?:/umd/react(?:-dom)?)?(?:\.production|\.development)?(?:\.min)?\.js"],
  html=[r"\sdata-reactroot\b"],
  js=[r"rendererPackageName:\"react-dom\"", r"reconcilerVersion:\"([\d.]+)",
      r"@license React\s+\*\s+react-dom", r"Minified React error #"])
lib("Preact", r"preact", category="JavaScript framework", npm=["preact"])
T("Vue.js", "JavaScript framework", npm=["vue"],
  script=[rf"/vue@{V}", rf"/vue/{V}/", r"/vue(?:\.global|\.runtime|\.esm-browser)?(?:\.prod)?(?:\.min)?\.js"],
  html=[r"\sdata-v-[0-9a-f]{8}\b", r"\sdata-v-app\b"],
  js=[r"Vue\.js v([\d.]+)", r"@vue/(?:shared|runtime-dom|runtime-core) v([\d.]+)", r"__VUE_PROD_DEVTOOLS__"])
T("AngularJS", "JavaScript framework", npm=["angular"],
  script=[rf"/angular(?:\.?js)?[/.\-@]{V}", r"/angular(?:\.min)?\.js"], html=[r"<[^>]+\sng-app\b"],
  js=[r"AngularJS v([\d.]+)"])
T("Angular", "JavaScript framework", npm=["@angular/core"], implies=["TypeScript"],
  html=[r"\sng-version=\"([\d.]+)"], js=[r"\"ng-version\",\s*\"([\d.]+)\""])
T("TypeScript", "Programming language")
T("Ember.js", "JavaScript framework", npm=["ember-source"], html=[r"class=\"[^\"]*\bember-application\b"],
  js=[r"Ember\.VERSION\s*=\s*[\"']([\d.]+)"])
lib("Alpine.js", r"alpine(?:js)?", category="JavaScript framework", npm=["alpinejs"],
    html=[r"<[^>]+\sx-data=[\"'{]"])
lib("htmx", r"htmx(?:\.org)?", npm=["htmx.org"], html=[r"<[^>]+\sdata-hx-(?:get|post)=|<[^>]+\shx-(?:get|post)="])
T("Stimulus", "JavaScript framework", npm=["@hotwired/stimulus"], html=[r"40%<[^>]+\sdata-controller=\"[a-z]"])
T("Turbo", "JavaScript library", npm=["@hotwired/turbo"], html=[r"<turbo-frame\b"],
  meta={"turbo-cache-control": r".", "turbo-visit-control": r"."})
lib("Backbone.js", r"backbone", npm=["backbone"], js=[r"Backbone\.js ([\d.]+)"])
lib("Knockout", r"knockout", npm=["knockout"], js=[r"Knockout JavaScript library v([\d.]+)"])
lib("jQuery", r"jquery", npm=["jquery"],
    js=[r"/\*!?\s*\*?\s*jQuery (?:JavaScript Library )?v([\d.]+)"])
lib("jQuery Migrate", r"jquery-migrate", npm=["jquery-migrate"], implies=["jQuery"],
    js=[r"jQuery Migrate - v([\d.]+)"])
lib("jQuery UI", r"jquery-?ui|jquery\.ui|jqueryui", npm=["jquery-ui"], implies=["jQuery"],
    js=[r"jQuery UI - v([\d.]+)"], script=[r"/jquery/ui/core"])
lib("jQuery Mobile", r"jquery\.mobile", implies=["jQuery"], js=[r"jQuery Mobile ([\d.]+)"])
lib("jQuery Validation", r"jquery\.validate|jquery-validate", implies=["jQuery"],
    js=[r"jQuery Validation Plugin v([\d.]+)"])
lib("DataTables", r"(?:jquery\.)?dataTables", js=[r"DataTables ([\d.]+)\s"])
lib("Select2", r"select2(?:\.full)?", js=[r"Select2 ([\d.]+) \|"])
lib("Lodash", r"lodash", npm=["lodash", "lodash-es"], js=[r"@license\s+(?:\*\s+)?Lodash"])
lib("Underscore.js", r"underscore", npm=["underscore"], js=[r"Underscore\.js ([\d.]+)"])
lib("Moment.js", r"moment(?:-with-locales)?", npm=["moment"], js=[r"//! version : ([\d.]+)"])
lib("Day.js", r"dayjs", npm=["dayjs"])
lib("Axios", r"axios", npm=["axios"], js=[r"/\*!? ?[Aa]xios v([\d.]+)"])
lib("D3", r"d3(?:\.v\d)?", npm=["d3"], js=[r"// https://d3js\.org v([\d.]+)"])
lib("Chart.js", r"chart(?:\.umd)?|chart\.js|Chart(?:\.bundle)?", npm=["chart.js"], js=[r"Chart\.js v([\d.]+)"])
lib("three.js", r"three(?:\.module)?", npm=["three"])
lib("GSAP", r"gsap|TweenMax", npm=["gsap"], js=[r"\* GSAP ([\d.]+)"])
lib("Socket.IO", r"socket\.io(?:-client)?", npm=["socket.io-client"], js=[r"Socket\.IO v([\d.]+)"])
lib("Modernizr", r"modernizr(?:[.\-]custom)?", js=[r"modernizr v?([\d.]+)"])
lib("Swiper", r"swiper(?:-bundle)?", npm=["swiper"], js=[r"\* Swiper ([\d.]+)"])
lib("Slick", r"slick(?:-carousel)?", npm=["slick-carousel"])
lib("Owl Carousel", r"owl\.carousel", js=[r"Owl Carousel v([\d.]+)"])
lib("Lightbox", r"lightbox(?:2)?")
lib("FancyBox", r"(?:jquery\.)?fancybox", js=[r"fancyBox v([\d.]+)"])
lib("AOS", r"aos", npm=["aos"])
lib("Popper", r"popper(?:\.js)?", npm=["@popperjs/core", "popper.js"], js=[r"@popperjs/core v([\d.]+)"])
lib("SweetAlert2", r"sweetalert2?(?:\.all)?", npm=["sweetalert2"], js=[r"sweetalert2 v([\d.]+)"])
lib("DOMPurify", r"(?:dom)?purify", npm=["dompurify"], js=[r"@license DOMPurify ([\d.]+)"])
lib("Handlebars", r"handlebars(?:\.runtime)?", npm=["handlebars"], js=[r"handlebars v([\d.]+)"])
lib("Mustache", r"mustache", npm=["mustache"])
lib("RequireJS", r"require(?:js)?", js=[r"RequireJS ([\d.]+)"])
lib("MooTools", r"mootools(?:-core|-more)?")
lib("Prototype", r"prototype")
lib("CKEditor", r"ckeditor\d?", category="Rich text editor")
lib("TinyMCE", r"tinymce", category="Rich text editor", npm=["tinymce"])
lib("Leaflet", r"leaflet", category="Maps", npm=["leaflet"], js=[r"Leaflet ([\d.]+)[,\s]"])
lib("Video.js", r"video(?:js)?", category="Media player", npm=["video.js"], js=[r"Video\.js ([\d.]+) <"])
lib("hls.js", r"hls", category="Media player", npm=["hls.js"])
T("core-js", "JavaScript library", npm=["core-js"],
  js=[r"core-js/blob/v([\d.]+)/LICENSE"])
T("Redux", "JavaScript library", npm=["redux", "@reduxjs/toolkit"], js=[r"__REDUX_DEVTOOLS_EXTENSION"])
T("Webpack", "Build tool", npm=["webpack"], js=[r"webpackJsonp", r"webpackChunk\w*", r"__webpack_require__"])
T("Vite", "Build tool", js=[r"__vite__mapDeps|vite:preloadError"],
  html=[r"<script[^>]+src=\"/@vite/client\""])
T("Parcel", "Build tool", js=[r"parcelRequire\w*"])
T("Bootstrap", "UI framework", npm=["bootstrap"],
  script=[rf"/bootstrap[@/]{V}/", rf"/bootstrap(?:\.bundle)?(?:\.min)?\.js(?:\?(?:ver|v)={V})?"],
  css=[rf"/bootstrap[@/]{V}/", rf"/bootstrap(?:\.min)?\.css(?:\?(?:ver|v)={V})?"],
  js=[r"Bootstrap v([\d.]+) \("])
T("Tailwind CSS", "UI framework", script=[r"cdn\.tailwindcss\.com(?:/([\d.]+))?", r"@tailwindcss/browser"],
  css=[r"/tailwind(?:css)?(?:@[\d.]+)?(?:/|\.min\.css|\.css)"],
  html=[r"/\*!? ?tailwindcss v([\d.]+)", r"--tw-(?:ring-offset-shadow|translate-x)"])
T("Bulma", "UI framework", css=[rf"/bulma(?:[@/]{V})?[/.\w]*\.css"])
T("Foundation", "UI framework", css=[r"/foundation(?:-sites)?(?:@[\d.]+)?[\w./]*\.css"], script=[r"/foundation(?:\.min)?\.js"])
T("Materialize", "UI framework", css=[rf"/materialize(?:/{V})?[\w./]*\.css"])
T("MUI", "UI framework", implies=["React"], npm=["@mui/material", "@material-ui/core"],
  html=[r"class=\"[^\"]{0,200}\bMui[A-Z]\w+-root\b"])
T("Ant Design", "UI framework", npm=["antd"], html=[r"class=\"[^\"]{0,200}\bant-(?:btn|layout|menu|row)\b"])
T("Chakra UI", "UI framework", implies=["React"], npm=["@chakra-ui/react"], html=[r"class=\"[^\"]*\bchakra-(?:ui|stack|text|button)"])
T("Vuetify", "UI framework", implies=["Vue.js"], npm=["vuetify"], html=[r"class=\"[^\"]*\bv-application\b"], css=[rf"/vuetify(?:@{V})?"])
T("Semantic UI", "UI framework", css=[r"/semantic(?:\.min)?\.css"])
T("Font Awesome", "Icons and fonts", css=[rf"font-?awesome(?:-free)?[@/]{V}/", r"font-?awesome", r"/fontawesome[\w\-./]*\.css"],
  script=[r"kit\.fontawesome\.com", r"use\.fontawesome\.com/releases/v([\d.]+)"])
T("Google Fonts", "Icons and fonts", css=[r"//fonts\.googleapis\.com"], html=[r"//fonts\.gstatic\.com"])
T("Adobe Fonts", "Icons and fonts", css=[r"//use\.typekit\.net"], script=[r"//use\.typekit\.net"])
T("Bootstrap Icons", "Icons and fonts", css=[rf"bootstrap-icons(?:@{V})?"])
T("styled-components", "CSS-in-JS", npm=["styled-components"], html=[r"<style[^>]+data-styled(?:-version)?=\"([\d.]+)?"])
T("Emotion", "CSS-in-JS", npm=["@emotion/react"], html=[r"<style[^>]+data-emotion="])

# ---------------------------------------------------------------- CMS
T("WordPress", "CMS", implies=["PHP", "MySQL / MariaDB"],
  meta={"generator": r"^WordPress ?([\d.]+)?"},
  html=[r"<link rel=[\"']https://api\.w\.org/[\"']"],
  header={"link": r"rel=\"https://api\.w\.org/\"", "x-pingback": r"/xmlrpc\.php", "x-redirect-by": r"WordPress"},
  asset=[r"/wp-(?:content|includes)/"], cookie=[r"wordpress_test_cookie", r"wp-settings-.+"],
  robots=[r"/wp-admin/"],
  probe=[("/wp-login.php", r"wp-login\.php\?action=lostpassword|id=\"wp-submit\""),
         ("/feed/", r"<generator>https?://wordpress\.org/\?v=([\d.]+)"),
         ("/readme.html", r"<title>WordPress ")])
T("MySQL / MariaDB", "Database", banner=[r"(\d+\.\d+\.\d+)[\w\-.]*[\s\S]{0,60}(?:mysql_native|caching_sha2|MariaDB)"])
WP = ["WordPress"]
for _name, _slug in (
        ("WooCommerce", "woocommerce"), ("Elementor", "elementor"), ("Contact Form 7", "contact-form-7"),
        ("WPBakery", "js_composer"), ("Slider Revolution", "revslider"), ("WP Rocket", "wp-rocket"),
        ("Jetpack", "jetpack"), ("Wordfence", "wordfence"), ("LiteSpeed Cache", "litespeed-cache"),
        ("Yoast SEO", "wordpress-seo"), ("Rank Math", "seo-by-rank-math"), ("WPForms", "wpforms(?:-lite)?"),
        ("Gravity Forms", "gravityforms"), ("Ninja Forms", "ninja-forms"), ("W3 Total Cache", "w3-total-cache"),
        ("Autoptimize", "autoptimize"), ("Essential Addons", "essential-addons-for-elementor-lite"),
        ("The Events Calendar", "the-events-calendar"), ("Complianz", "complianz-gdpr"), ("WPML", "sitepress-multilingual-cms")):
    _extra = {}
    if _name == "Yoast SEO":
        _extra["html"] = [r"optimized with the Yoast SEO(?: Premium)? plugin v([\d.]+)"]
    if _name == "WooCommerce":
        _extra["meta"] = {"generator": r"^WooCommerce ([\d.]+)"}
    if _name == "Elementor":
        _extra["meta"] = {"generator": r"^Elementor ([\d.]+)"}
    if _name == "Slider Revolution":
        _extra["meta"] = {"generator": r"Slider Revolution ([\d.]+)"}
    if _name == "WP Rocket":
        _extra["html"] = [r"This website is like a Rocket"]
    T(_name, "WordPress plugin", implies=WP,
      asset=[rf"/wp-content/plugins/{_slug}/(?:[^?]*\?ver={V})?"],
      probe=[], **_extra)
T("Joomla", "CMS", implies=["PHP"], meta={"generator": r"^Joomla!?(?: ([\d.]+))?"},
  html=[r"<script[^>]+class=\"joomla-script-options"], asset=[r"/media/(?:jui|system|vendor)/js/(?:core|bootstrap|jquery)"],
  robots=[r"60%/administrator/[\s\S]{0,400}/components/"],
  probe=[("/administrator/manifests/files/joomla.xml", r"<extension[\s\S]{0,1500}<version>([\d.]+)")])
T("Drupal", "CMS", implies=["PHP"], meta={"generator": r"^Drupal ?([\d.]+)?"},
  header={"x-generator": r"^Drupal ?([\d.]+)?", "x-drupal-cache": r".", "x-drupal-dynamic-cache": r"."},
  html=[r"data-drupal-(?:selector|link)"], js=[r"Drupal\.settings"], asset=[r"/sites/(?:default|all)/(?:files|themes|modules)/"],
  robots=[r"/core/[\s\S]{0,400}/profiles/"],
  probe=[("/CHANGELOG.txt", r"^\s*Drupal (\d[\d.]+),")])
T("Magento", "E-commerce", implies=["PHP"], cookie=[r"X-Magento-Vary", r"mage-\w[\w\-]*"],
  header={"x-magento-tags": r".", "x-magento-cache-debug": r"."}, html=[r"text/x-magento-init"],
  asset=[r"/static/(?:version\d+/)?frontend/"],
  probe=[("/magento_version", r"^Magento/([\d.]+)")])
T("PrestaShop", "E-commerce", implies=["PHP"], meta={"generator": r"^PrestaShop"},
  cookie=[r"PrestaShop-\w+"], js=[r"var prestashop\s*=|prestashop = \{"], header={"powered-by": r"PrestaShop"})
T("OpenCart", "E-commerce", implies=["PHP"], cookie=[r"OCSESSID"], asset=[r"/catalog/view/(?:theme|javascript)/"])
T("Shopify", "E-commerce", header={"x-shopid": r".", "x-shopify-stage": r".", "powered-by": r"Shopify"},
  cookie=[r"_shopify_[a-z]+"], script=[r"cdn\.shopify\.com/|/cdn/shop(?:ifycloud)?/"], js=[r"Shopify\.theme\s*="])
T("VTEX", "E-commerce", header={"powered": r"vtex", "x-vtex-router-version": r"."},
  cookie=[r"VtexWorkspace", r"vtex_segment"], script=[r"vtexassets\.com|vteximg\.com"])
T("Nuvemshop", "E-commerce", script=[r"tiendanube\.com|nuvemshop\.com|lojavirtualnuvem"])
T("BigCommerce", "E-commerce", script=[r"cdn\d*\.bigcommerce\.com"])
T("Wix", "Website builder", meta={"generator": r"^Wix\.com"}, header={"x-wix-request-id": r"."},
  script=[r"static\.parastorage\.com"])
T("Squarespace", "Website builder", header={"server": r"Squarespace"}, html=[r"<!-- This is Squarespace\. -->"])
T("Webflow", "Website builder", meta={"generator": r"^Webflow"}, html=[r"<html[^>]+data-wf-(?:page|site)="])
T("Framer", "Website builder", meta={"generator": r"^Framer"})
T("Duda", "Website builder", script=[r"cdn-website\.com|irp\.cdn"])
T("Ghost", "CMS", implies=["Node.js"], meta={"generator": r"^Ghost ?([\d.]+)?"})
T("TYPO3", "CMS", implies=["PHP"], meta={"generator": r"^TYPO3(?: CMS)? ?([\d.]+)?"}, asset=[r"/typo3(?:temp|conf)/"])
T("Umbraco", "CMS", implies=["ASP.NET"], header={"x-umbraco-version": r"([\d.]+)"}, meta={"generator": r"^Umbraco"})
T("Sitecore", "CMS", implies=["ASP.NET"], cookie=[r"SC_ANALYTICS_GLOBAL_COOKIE"], asset=[r"/-/media/"])
T("Kentico", "CMS", implies=["ASP.NET"], cookie=[r"CMSPreferredCulture"], meta={"generator": r"Kentico"})
T("DNN", "CMS", implies=["ASP.NET"], cookie=[r"DotNetNukeAnonymous", r"dnn_IsMobile"], meta={"generator": r"DotNetNuke"})
T("SharePoint", "CMS", header={"microsoftsharepointteamservices": r"([\d.]+)", "sprequestguid": r"."},
  meta={"generator": r"^Microsoft SharePoint"})
T("Adobe Experience Manager", "CMS", implies=["Java"], asset=[r"/etc\.clientlibs/|/content/dam/"])
T("Liferay", "CMS", implies=["Java"], header={"liferay-portal": r"([\d.]+(?: \w+)*)"}, js=[r"Liferay\.(?:Browser|ThemeDisplay)"],
  cookie=[r"GUEST_LANGUAGE_ID"])
T("Plone", "CMS", implies=["Python"], meta={"generator": r"^Plone"})
T("Blogger", "CMS", meta={"generator": r"^Blogger$"})
T("HubSpot CMS", "CMS", meta={"generator": r"^HubSpot"})
T("Contao", "CMS", implies=["PHP"], meta={"generator": r"^Contao"})
T("Concrete CMS", "CMS", implies=["PHP"], meta={"generator": r"^concrete5(?: - ([\d.]+))?"})
T("MediaWiki", "Wiki", implies=["PHP"], meta={"generator": r"^MediaWiki ?([\d.]+)?"})
T("DokuWiki", "Wiki", implies=["PHP"], meta={"generator": r"^DokuWiki"}, cookie=[r"DokuWiki"])
T("Confluence", "Wiki", implies=["Java"], header={"x-confluence-request-time": r"."}, meta={"confluence-request-time": r"."},
  html=[r"Powered by <a[^>]+>Atlassian Confluence</a> ?<[^>]+>([\d.]+)"])
T("Discourse", "Forum", meta={"generator": r"^Discourse ([\d.]+)"})
T("phpBB", "Forum", implies=["PHP"], cookie=[r"phpbb\d?_\w+"], html=[r"Powered by <a[^>]+phpbb\.com"])
T("vBulletin", "Forum", implies=["PHP"], meta={"generator": r"^vBulletin ?([\d.]+)?"})
T("Moodle", "LMS", implies=["PHP"], cookie=[r"MoodleSession\w*"], meta={"keywords": r"^moodle"})

# ---------------------------------------------------------------- applications
T("phpMyAdmin", "Database manager", implies=["PHP"], cookie=[r"phpMyAdmin\w*", r"pma_\w+"],
  html=[r"<title>phpMyAdmin"], probe=[("/phpmyadmin/", r"<title>phpMyAdmin")])
T("Jenkins", "DevOps", implies=["Java"], header={"x-jenkins": r"([\d.]+)"})
T("GitLab", "DevOps", cookie=[r"_gitlab_session"], meta={"og:site_name": r"^GitLab$"})
T("Gitea", "DevOps", cookie=[r"i_like_gitea"], html=[r"Powered by Gitea(?: Version: ([\d.]+))?"])
T("Jira", "Issue tracker", implies=["Java"], meta={"application-name": r"^JIRA"}, cookie=[r"atlassian\.xsrf\.token"],
  html=[r"data-version=\"([\d.]+)\"[^>]+name=\"application-name\" content=\"JIRA"])
T("SonarQube", "DevOps", html=[r"<title>SonarQube"])
T("Grafana", "Monitoring", cookie=[r"grafana_session"], html=[r"<title>Grafana</title>"],
  js=[r"\"buildInfo\":\{[^}]{0,300}\"version\":\"([\d.]+)"])
T("Kibana", "Monitoring", header={"kbn-name": r".", "kbn-version": r"([\d.]+)"})
T("Zabbix", "Monitoring", implies=["PHP"], cookie=[r"zbx_session"], html=[r"Zabbix SIA"])
T("Keycloak", "Authentication", cookie=[r"KC_RESTART", r"AUTH_SESSION_ID"], asset=[r"/resources/\w+/login/keycloak"])
T("Nextcloud", "File sharing", implies=["PHP"], cookie=[r"nc_sameSiteCookie\w+", r"__Host-nc_\w+"],
  probe=[("/status.php", r"\"versionstring\":\"([\d.]+)\"[\s\S]{0,200}\"productname\":\"Nextcloud")])
T("Roundcube", "Webmail", implies=["PHP"], cookie=[r"roundcube_sessid"])
T("Outlook Web App", "Webmail", implies=["Microsoft IIS"], header={"x-owa-version": r"([\d.]+)"}, cookie=[r"OutlookSession"])
T("Swagger UI", "API documentation", script=[r"swagger-ui(?:-bundle)?(?:\.min)?\.js", rf"swagger-ui(?:-dist)?[@/]{V}/"],
  probe=[("/swagger/index.html", r"<title>Swagger UI"), ("/swagger-ui/index.html", r"<title>Swagger UI"),
         ("/api-docs/", r"<title>Swagger UI")])
T("GraphQL", "API", js=[r"[\"'`](?:/[\w\-]+)*/graphql[\"'`?]"],
  probe=[("/graphql?query=%7B__typename%7D", r"\"__typename\":\"\w+\"|Must provide query string")])
T("cPanel", "Hosting panel", header={"server": r"cpsrvd(?:/([\d.]+))?"}, error=[r"cPanel(?:,| Inc)"])
T("Plesk", "Hosting panel", header={"x-powered-by": r"^Plesk", "x-powered-by-plesk": r"."})

# ---------------------------------------------------------------- CDN, hosting, WAF
T("Cloudflare", "CDN / WAF", header={"server": r"^cloudflare", "cf-ray": r"."}, cookie=[r"__cf_bm", r"cf_clearance", r"__cfduid"])
T("Cloudflare Browser Insights", "Analytics", script=[r"static\.cloudflareinsights\.com"])
T("Cloudflare Turnstile", "Captcha", script=[r"challenges\.cloudflare\.com/turnstile"])
T("Amazon CloudFront", "CDN / WAF", header={"x-amz-cf-id": r".", "via": r"CloudFront", "server": r"^CloudFront"})
T("AWS Elastic Load Balancing", "Hosting", header={"server": r"^awselb(?:/([\d.]+))?"}, cookie=[r"AWS(?:ALB|ELB)\w*"])
T("AWS WAF", "CDN / WAF", cookie=[r"aws-waf-token"], header={"x-amzn-waf-action": r"."})
T("Amazon S3", "Hosting", header={"server": r"^AmazonS3", "x-amz-request-id": r"60%."})
T("Amazon API Gateway", "API gateway", header={"x-amz-apigw-id": r"."})
T("Akamai", "CDN / WAF", header={"server": r"AkamaiGHost|AkamaiNetStorage", "x-akamai-transformed": r".", "akamai-grn": r"."},
  cookie=[r"ak_bmsc", r"_abck", r"bm_sz"])
T("Fastly", "CDN / WAF", header={"x-served-by": r"60%cache-\w+", "x-fastly-request-id": r".", "fastly-restarts": r"."})
T("Imperva", "CDN / WAF", header={"x-iinfo": r".", "x-cdn": r"Imperva|Incapsula"}, cookie=[r"visid_incap_\d+", r"incap_ses_\w+"])
T("Sucuri", "CDN / WAF", header={"server": r"Sucuri", "x-sucuri-id": r"."})
T("F5 BIG-IP", "CDN / WAF", cookie=[r"BIGipServer.*", r"F5_ST", r"TS[0-9a-f]{6,10}"], header={"server": r"BIG-?IP"})
T("FortiWeb", "CDN / WAF", cookie=[r"FORTIWAFSID"])
T("Barracuda", "CDN / WAF", cookie=[r"barra_counter_session", r"BNI__BARRACUDA_LB_COOKIE"])
T("Citrix NetScaler", "CDN / WAF", cookie=[r"NSC_\w+", r"citrix_ns_id\w*"], header={"via": r"NS-CACHE"})
T("DataDome", "CDN / WAF", cookie=[r"datadome"], header={"x-datadome": r"."})
T("Azure Front Door", "CDN / WAF", header={"x-azure-ref": r"."})
T("Azure App Service", "Hosting", cookie=[r"ARRAffinity(?:SameSite)?"])
T("Google Cloud", "Hosting", header={"via": r"^1\.1 google$", "server": r"^Google Frontend"})
T("Google Web Server", "Web server", header={"server": r"^(?:gws|ESF|sffe)$"})
T("Vercel", "Hosting", header={"server": r"^Vercel", "x-vercel-id": r"."})
T("Netlify", "Hosting", header={"server": r"^Netlify", "x-nf-request-id": r"."})
T("Heroku", "Hosting", header={"via": r"vegur|heroku", "server": r"^Heroku"})
T("GitHub Pages", "Hosting", header={"server": r"^GitHub\.com", "x-github-request-id": r"60%."})
T("Fly.io", "Hosting", header={"server": r"^Fly/", "fly-request-id": r"."})
T("Render", "Hosting", header={"x-render-origin-server": r"."})
T("Pantheon", "Hosting", header={"x-pantheon-styx-hostname": r"."})
T("WP Engine", "Hosting", header={"x-powered-by": r"WP Engine", "wpe-backend": r"."})
T("Hostinger", "Hosting", header={"platform": r"^hostinger", "server": r"^hcdn"})
T("jsDelivr", "CDN / WAF", script=[r"//cdn\.jsdelivr\.net"], css=[r"//cdn\.jsdelivr\.net"])
T("cdnjs", "CDN / WAF", script=[r"//cdnjs\.cloudflare\.com"], css=[r"//cdnjs\.cloudflare\.com"])
T("unpkg", "CDN / WAF", script=[r"//unpkg\.com"], css=[r"//unpkg\.com"])
T("Google Hosted Libraries", "CDN / WAF", script=[r"//ajax\.googleapis\.com"])

# ---------------------------------------------------------------- analytics, marketing, services
T("Google Analytics", "Analytics", script=[r"google-analytics\.com/(?:ga|analytics)\.js", r"googletagmanager\.com/gtag/js"],
  js=[r"gtag\([\"']config[\"'],\s*[\"'](?:G|UA)-"], cookie=[r"_ga(?:_\w+)?"])
T("Google Tag Manager", "Tag manager", script=[r"googletagmanager\.com/gtm\.js"], js=[r"googletagmanager\.com/gtm\.js"],
  html=[r"googletagmanager\.com/ns\.html\?id=GTM-"])
T("Meta Pixel", "Analytics", script=[r"connect\.facebook\.net/.+/fbevents\.js"], js=[r"connect\.facebook\.net/[^\"']+/fbevents\.js"])
T("Hotjar", "Analytics", script=[r"static\.hotjar\.com"], js=[r"static\.hotjar\.com"])
T("Microsoft Clarity", "Analytics", script=[r"clarity\.ms/tag"], js=[r"clarity\.ms/tag"])
T("Matomo", "Analytics", script=[r"/(?:matomo|piwik)\.js"], js=[r"_paq\.push"], cookie=[r"_pk_(?:id|ses)\..+"])
T("Plausible", "Analytics", script=[r"plausible\.io/js"])
T("Mixpanel", "Analytics", script=[r"cdn\.mxpnl\.com"], js=[r"cdn\.mxpnl\.com"], npm=["mixpanel-browser"])
T("Segment", "Analytics", script=[r"cdn\.segment\.com"], js=[r"cdn\.segment\.com/analytics\.js"])
T("New Relic", "Monitoring", js=[r"NREUM\.(?:loader_config|info)|window\.NREUM"], script=[r"js-agent\.newrelic\.com/nr(?:-\w+)*-(\d+)"])
T("Datadog RUM", "Monitoring", script=[r"datadoghq-browser-agent\.com"], npm=["@datadog/browser-rum"])
T("Sentry", "Monitoring", script=[r"browser\.sentry-cdn\.com/([\d.]+)?", r"js\.sentry-cdn\.com"],
  js=[r"https://[0-9a-f]{32}@[\w.\-]*(?:sentry\.io|ingest[\w.]*)/\d+"], npm=["@sentry/browser"])
T("Dynatrace", "Monitoring", cookie=[r"dtCookie\w*"], script=[r"ruxitagentjs"])
T("LinkedIn Insight", "Analytics", script=[r"snap\.licdn\.com"], js=[r"snap\.licdn\.com"])
T("TikTok Pixel", "Analytics", js=[r"analytics\.tiktok\.com"])
T("RD Station", "Marketing", script=[r"d335luupugsy2\.cloudfront\.net"])
T("HubSpot", "Marketing", script=[r"js(?:-\w+)?\.(?:hs-scripts|hs-analytics|hsforms)\.(?:com|net)"], cookie=[r"hubspotutk", r"__hstc"])
T("Mailchimp", "Marketing", script=[r"chimpstatic\.com"], html=[r"list-manage\.com/subscribe"])
T("Google AdSense", "Advertising", script=[r"pagead2\.googlesyndication\.com"])
T("reCAPTCHA", "Captcha", script=[r"(?:google\.com|recaptcha\.net)/recaptcha/"])
T("hCaptcha", "Captcha", script=[r"hcaptcha\.com/1/api\.js"])
T("Stripe", "Payment", script=[r"js\.stripe\.com"])
T("PayPal", "Payment", script=[r"paypal\.com/sdk|paypalobjects\.com"])
T("Mercado Pago", "Payment", script=[r"sdk\.mercadopago\.com|mlstatic\.com/.*mercadopago"])
T("PagSeguro", "Payment", script=[r"pagseguro\.uol\.com\.br"])
T("Zendesk", "Customer support", script=[r"static\.zdassets\.com"])
T("Intercom", "Customer support", script=[r"widget\.intercom\.io"], js=[r"widget\.intercom\.io"])
T("Tawk.to", "Customer support", js=[r"embed\.tawk\.to"], script=[r"embed\.tawk\.to"])
T("JivoChat", "Customer support", script=[r"code\.jivosite\.com"])
T("VLibras", "Accessibility", script=[r"vlibras\.gov\.br"])
T("OneTrust", "Cookie consent", script=[r"cdn\.cookielaw\.org|otSDKStub"], cookie=[r"OptanonConsent"])
T("Cookiebot", "Cookie consent", script=[r"consent\.cookiebot\.com"])
T("Google Maps", "Maps", script=[r"maps\.google(?:apis)?\.com/maps"], html=[r"<iframe[^>]+google\.com/maps/embed"])
T("YouTube embed", "Media player", html=[r"<iframe[^>]+youtube(?:-nocookie)?\.com/embed"])
T("Vimeo embed", "Media player", html=[r"<iframe[^>]+player\.vimeo\.com"])
T("Firebase", "Backend service", script=[r"gstatic\.com/firebasejs/([\d.]+)"], npm=["firebase", "@firebase/app"],
  js=[r"[\"'][\w\-]+\.firebaseapp\.com[\"']"])
T("Supabase", "Backend service", js=[r"https://[a-z]{20}\.supabase\.co"], npm=["@supabase/supabase-js"])
T("Auth0", "Authentication", script=[r"cdn\.auth0\.com"], js=[r"[\"'`][\w\-]+\.(?:us\.|eu\.)?auth0\.com"])
T("Algolia", "Search", script=[r"algoliasearch"], npm=["algoliasearch"])
T("Service Worker", "Web platform", js=[r"navigator\.serviceWorker\.register\("])

# ---------------------------------------------------------------- TCP services (--ports)
T("OpenSSH", "Network service", banner=[r"^SSH-[\d.]+-OpenSSH_(?:for_Windows_)?([\w.]+)"])
T("Dropbear SSH", "Network service", banner=[r"^SSH-[\d.]+-dropbear_?([\w.]+)?"])
T("vsftpd", "Network service", banner=[rf"^220.*vsFTPd {V}"])
T("ProFTPD", "Network service", banner=[rf"^220.*ProFTPD ?{V}?"])
T("Pure-FTPd", "Network service", banner=[r"^220[\s\S]*Pure-FTPd"])
T("FileZilla Server", "Network service", banner=[rf"^220.*FileZilla Server(?: version)? ?{V}?"])
T("Microsoft FTP", "Network service", implies=["Windows Server"], banner=[r"^220.*Microsoft FTP Service"])
T("Postfix", "Mail server", banner=[r"^220.*Postfix"])
T("Exim", "Mail server", banner=[rf"^220.*Exim {V}"])
T("Sendmail", "Mail server", banner=[r"^220.*Sendmail (\d[\d.]+)"])
T("Microsoft Exchange", "Mail server", implies=["Windows Server"], banner=[r"^220.*Microsoft ESMTP"])
T("Dovecot", "Mail server", banner=[r"Dovecot"])
T("Redis", "Database", banner=[r"-(?:DENIED Redis|NOAUTH)"])
