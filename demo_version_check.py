# Demo logika IDENTIK dengan phpcheck.js OpenAI, pakai stdlib saja (bukan tool node-nya).
import sys, re, urllib.request
VULN_THROUGH = {"8.5":11,"8.4":26,"8.3":35,"8.2":34}  # patched = +1 patch di atasnya
def status(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v or "")
    if not m: return "unknown"
    cut = VULN_THROUGH.get(f"{int(m[1])}.{int(m[2])}")
    if cut is None: return "unknown-branch"
    return "VULNERABLE" if int(m[3]) <= cut else "OK"
def check(url):
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            srv = r.headers.get("Server","") ; pb = r.headers.get("X-Powered-By","")
    except Exception as e:
        print(f"{url}: unreachable ({type(e).__name__})"); return
    banner = f"{srv} {pb}"
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", banner, re.I)
    ver = m.group(1) if m else ""
    print(f"{url}\n  Server: {srv or '-'}\n  X-Powered-By: {pb or '-'}")
    print(f"  PHP version terdeteksi: {ver or '(tidak terekspos)'}  ->  CVE-2026-109618/619: {status(ver)}")
check(sys.argv[1] if len(sys.argv)>1 else "https://example.com")
print("\n--- uji fungsi versi (tanpa jaringan) ---")
for v in ["8.3.12","8.3.36","8.2.34","8.2.35","8.1.30","7.4.33",""]:
    print(f"  PHP {v or '(kosong)':<8} -> {status(v)}")
