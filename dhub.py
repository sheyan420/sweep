import base64, io, json, os, re, sys, tarfile, time, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "docker_cand.tsv")
SEEN_LAYER = os.path.join(HERE, "layers.seen")
USER = os.environ.get("DOCKER_USER", "")
PAT = os.environ.get("DOCKER_PAT", "")
UA = "keyhunt/1.0"
MAXL = 50 * 1024 * 1024

PATS = [("hex0x", r"\b0x[0-9a-fA-F]{64}\b"),
        ("hexkey", r"\b[0-9a-fA-F]{64}\b"),
        ("wif", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
        ("pem", r"-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----")]
GATE = re.compile(r"(?i)\b(COPY|ADD)\b.*(\.|env|config|secret)|\bARG\s+\w+=")
INTEREST = re.compile(r"(?i)(^|/)(\.env[^/]*|\.npmrc|\.pypirc|credentials|config\.json|secrets?\.(json|ya?ml)|[^/]+\.(pem|key|p12|pfx|tfstate))$")

def req(url, hdrs=None, tok=None, method="GET"):
    h = {"User-Agent": UA}
    if tok:
        h["Authorization"] = "Bearer " + tok
    if hdrs:
        h.update(hdrs)
    r = urllib.request.Request(url, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=45) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read() if e.fp else b""

def auth_realm(hdrs):
    w = hdrs.get("www-authenticate", "")
    if "Bearer" not in w:
        return None
    d = dict(re.findall(r'(\w+)="([^"]*)"', w))
    if "realm" not in d:
        return None
    q = {"service": d.get("service", ""), "scope": d.get("scope", "")}
    return d["realm"] + "?" + urllib.parse.urlencode({k: v for k, v in q.items() if v})

def token(realm):
    h = {}
    if USER and PAT:
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (USER, PAT)).encode()).decode()
    s, _, b = req(realm, h)
    if s != 200:
        return None
    try:
        j = json.loads(b)
    except Exception:
        return None
    return j.get("token") or j.get("access_token")

def host_of(ref):
    head, _, rest = ref.partition("/")
    if "." in head or ":" in head:
        return head, rest
    return "registry-1.docker.io", ("library/" + ref if "/" not in ref else ref)

def walk(blob, out):
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except Exception:
        return
    for m in tf:
        if not m.isfile() or m.size > 4 * 1024 * 1024:
            continue
        if not INTEREST.search(m.name):
            continue
        try:
            txt = tf.extractfile(m).read().decode("utf-8", "replace")
        except Exception:
            continue
        for t, p in PATS:
            for v in re.findall(p, txt):
                out.append((t, v, m.name))

def scan(ref, dry=False):
    host, repo = host_of(ref)
    base = "https://" + host
    t = None
    acc = "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json"
    tag = "latest"
    s, h, b = req(base + "/v2/" + repo + "/manifests/" + tag, {"Accept": acc})
    if s == 401:
        r = auth_realm(h)
        if not r:
            print("no realm", ref); return []
        t = token(r)
        if not t:
            print("no token", ref); return []
        s, h, b = req(base + "/v2/" + repo + "/manifests/" + tag, {"Accept": acc}, t)
    if s == 404:
        s2, _, tb = req(base + "/v2/" + repo + "/tags/list", tok=t)
        if s2 == 200:
            try:
                tl = json.loads(tb).get("tags") or []
            except Exception:
                tl = []
            if tl:
                tag = tl[-1]
                s, h, b = req(base + "/v2/" + repo + "/manifests/" + tag, {"Accept": acc}, t)
    if s == 429:
        print("RATELIMIT", ref, h.get("ratelimit-remaining", "?"), flush=True)
        time.sleep(5)
        return []
    if s != 200:
        print("manifest", s, ref); return []
    m = json.loads(b)
    if "manifests" in m:
        pick = next((x for x in m["manifests"]
                     if x.get("platform", {}).get("architecture") == "amd64"), m["manifests"][0])
        s, h, b = req(base + "/v2/" + repo + "/manifests/" + pick["digest"], {"Accept": acc}, t)
        if s != 200:
            print("submanifest", s, ref); return []
        m = json.loads(b)
    out = []
    cfgd = m.get("config", {}).get("digest")
    hist = []
    if cfgd:
        s, _, cb = req(base + "/v2/" + repo + "/blobs/" + cfgd, tok=t)
        if s == 200:
            try:
                hist = [x.get("created_by", "") for x in json.loads(cb).get("history", [])]
            except Exception:
                hist = []
            for line in hist:
                for tp, p in PATS:
                    for v in re.findall(p, line):
                        out.append((tp, v, "history"))
    gated = any(GATE.search(x) for x in hist)
    print("%-46s hist=%d gate=%s" % (ref[:46], len(hist), gated), flush=True)
    if dry or not gated:
        return out
    seen = set()
    if os.path.exists(SEEN_LAYER):
        seen = set(open(SEEN_LAYER).read().split())
    for l in m.get("layers", []):
        d = l.get("digest", "")
        if not d or d in seen or l.get("size", 0) > MAXL:
            continue
        s, _, lb = req(base + "/v2/" + repo + "/blobs/" + d, tok=t)
        if s != 200:
            continue
        seen.add(d)
        walk(lb, out)
        time.sleep(0.05)
    with open(SEEN_LAYER, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(seen)))
    return out

def main():
    refs = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry" in sys.argv
    if "--file" in sys.argv:
        refs = [r.split(chr(9))[0] + "/" + r.split(chr(9))[1] for r in open(sys.argv[sys.argv.index("--file") + 1], encoding="utf-8") if chr(9) in r]
    if not refs and os.path.exists(os.path.join(HERE, "imgrefs.tsv")):
        refs = [r.split("\t")[0] + "/" + r.split("\t")[1]
                for r in open(os.path.join(HERE, "imgrefs.tsv"), encoding="utf-8") if "\t" in r]
    total = 0
    for ref in refs:
        try:
            got = scan(ref.strip(), dry)
        except SystemExit:
            print("stopping on ratelimit"); break
        except Exception as e:
            print("ERR", ref, repr(e)[:80]); continue
        total += len(got)
        if got:
            with open(OUT, "a", encoding="utf-8", newline="\n") as f:
                for t, v, where in got:
                    f.write("%s\t%s\t%s\t%s\n" % (t, v, ref, where))
    print("TOTAL %d" % total)

main()