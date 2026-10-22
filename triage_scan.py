#!/usr/bin/env python3
"""
triage_scan.py - Defensive web triage for an OWNED domain portfolio.

Tujuan: menyapu daftar domain MILIK SENDIRI untuk:
  1) Fingerprint teknologi (server, PHP, generator/CMS) - inventaris aset.
  2) Deteksi indikasi KOMPROMI yang sudah ada (web shell terpasang) -
     hanya GET read-only ke path indikator + pencocokan signature.
  3) Menandai endpoint UPLOAD yang terekspos untuk ditinjau manual.

Yang TIDAK dilakukan script ini (disengaja):
  - Tidak meng-upload file apa pun.
  - Tidak mengeksekusi/membuat shell.
  - Tidak mengeksploitasi apa pun. Semua request read-only (GET/HEAD).

Output: CSV ringkas + ringkasan di layar. Gunakan HANYA pada aset yang
Anda miliki / punya izin tertulis untuk diperiksa.

Pemakaian:
    python triage_scan.py domains.txt
    python triage_scan.py domains.txt --shell-check --out hasil.csv --concurrency 20

Format domains.txt: satu domain/URL per baris. Baris kosong & yang diawali '#' diabaikan.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    sys.exit("Butuh paket 'httpx'. Install: pip install httpx")


# --- Signature compromise-detection (read-only). Bukan daftar lengkap,
#     hanya indikator umum untuk sweep awal. Temuan = perlu investigasi,
#     bukan kesimpulan final. ---
SHELL_PATHS = [
    "shell.php", "c99.php", "r57.php", "wso.php", "b374k.php",
    "alfa.php", "indoxploit.php", "adminer.php", "up.php", "upload.php",
    "cmd.php", "gel4y.php", "mini.php", "0byt3m1n1.php", "x.php",
]
SHELL_SIGNATURES = [
    re.compile(p, re.I) for p in [
        r"b374k", r"c99shell", r"r57shell", r"wso\s*shell", r"indoxploit",
        r"alfa\s*team", r"gel4y", r"<title>[^<]*shell[^<]*</title>",
        r"eval\s*\(\s*(base64_decode|gzinflate)", r"IndoXploit",
    ]
]

# Path upload/panel yang umum - hanya ditandai untuk tinjauan manual.
REVIEW_PATHS = [
    "upload/", "uploads/", "files/", "fileupload/", "wp-admin/",
    "administrator/", "admin/", "phpmyadmin/", "adminer.php",
    "wp-content/uploads/", "server-status",
]

GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I
)

# Ambil versi PHP dari header (X-Powered-By: PHP/8.3.12 / Server: ... PHP/8.3.12)
PHP_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I)

# CVE-2026-109618 / CVE-2026-109619 (PHP2Shell, rilis 2026-10-21).
# Versi minimal yang sudah di-patch per branch. <= di bawah ini = RENTAN.
# 8.1 ke bawah = EOL (hanya backport terbatas 7.4/8.0/8.1) -> anggap rentan.
PHP2SHELL_PATCHED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}


def php2shell_status(ver: tuple[int, int, int] | None) -> str:
    """Kembalikan status terhadap CVE-2026-109618/619 dari tuple versi PHP."""
    if ver is None:
        return "UNKNOWN (versi tak terekspos - verifikasi di host: php -v)"
    branch = (ver[0], ver[1])
    patched = PHP2SHELL_PATCHED.get(branch)
    if patched is None:
        # branch tak terdaftar: >=8.6 dianggap aman, <=8.1 EOL/rentan
        if ver >= (8, 6, 0):
            return "LIKELY_OK (branch baru, pastikan >= rilis ber-patch)"
        return f"VULNERABLE (PHP {ver[0]}.{ver[1]} EOL / <= 8.1)"
    if ver >= patched:
        return "OK (sudah di atas versi patched)"
    return (
        f"VULNERABLE (PHP {ver[0]}.{ver[1]}.{ver[2]} < "
        f"{patched[0]}.{patched[1]}.{patched[2]})"
    )


@dataclass
class Result:
    domain: str
    reachable: bool = False
    final_url: str = ""
    status: int = 0
    server: str = ""
    powered_by: str = ""
    php_detected: bool = False
    php_version: str = ""
    php2shell_cve: str = ""
    generator: str = ""
    shell_hits: list[str] = field(default_factory=list)
    review_hits: list[str] = field(default_factory=list)
    error: str = ""


def normalize(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not line.startswith(("http://", "https://")):
        line = "https://" + line
    return line.rstrip("/")


async def fingerprint(client: httpx.AsyncClient, base: str, r: Result) -> None:
    try:
        resp = await client.get(base + "/", follow_redirects=True)
    except Exception as e:
        # coba http kalau https gagal
        if base.startswith("https://"):
            try:
                resp = await client.get(
                    "http://" + base[len("https://"):] + "/",
                    follow_redirects=True,
                )
            except Exception as e2:
                r.error = f"{type(e2).__name__}: {e2}"
                return
        else:
            r.error = f"{type(e).__name__}: {e}"
            return

    r.reachable = True
    r.final_url = str(resp.url)
    r.status = resp.status_code
    r.server = resp.headers.get("server", "")
    r.powered_by = resp.headers.get("x-powered-by", "")
    body = resp.text if resp.headers.get("content-type", "").startswith("text") else ""
    r.php_detected = (
        "php" in r.powered_by.lower()
        or "phpsessid" in resp.headers.get("set-cookie", "").lower()
        or ".php" in r.final_url.lower()
    )

    # Ekstrak versi PHP dari header untuk cek CVE-2026-109618/619.
    vm = PHP_VERSION_RE.search(r.powered_by) or PHP_VERSION_RE.search(r.server)
    ver = None
    if vm:
        ver = (int(vm.group(1)), int(vm.group(2)), int(vm.group(3)))
        r.php_version = f"{ver[0]}.{ver[1]}.{ver[2]}"
    # Status CVE hanya bermakna kalau ini memang server PHP.
    if r.php_detected or ver is not None:
        r.php2shell_cve = php2shell_status(ver)

    m = GENERATOR_RE.search(body)
    if m:
        r.generator = m.group(1).strip()[:120]


async def probe_paths(
    client: httpx.AsyncClient, base: str, r: Result, shell_check: bool
) -> None:
    # Review paths: cek keberadaan (status < 400) untuk tinjauan manual.
    for p in REVIEW_PATHS:
        try:
            resp = await client.get(f"{base}/{p}", follow_redirects=False)
            if resp.status_code < 400 or resp.status_code in (401, 403):
                r.review_hits.append(f"{p}({resp.status_code})")
        except Exception:
            pass

    if not shell_check:
        return

    # Compromise sweep: cek indikator web shell (read-only GET + signature).
    for p in SHELL_PATHS:
        try:
            resp = await client.get(f"{base}/{p}", follow_redirects=False)
            if resp.status_code == 200:
                text = resp.text[:20000]
                if any(sig.search(text) for sig in SHELL_SIGNATURES) or p in SHELL_PATHS:
                    # status 200 pada path shell = sangat mencurigakan
                    tag = f"{p}({resp.status_code})"
                    if any(sig.search(text) for sig in SHELL_SIGNATURES):
                        tag += "+SIG"
                    r.shell_hits.append(tag)
        except Exception:
            pass


async def scan_one(
    sem: asyncio.Semaphore, client: httpx.AsyncClient, domain: str, shell_check: bool
) -> Result:
    r = Result(domain=domain)
    async with sem:
        await fingerprint(client, domain, r)
        if r.reachable:
            await probe_paths(client, domain, r, shell_check)
    return r


async def run(domains: list[str], concurrency: int, timeout: float, shell_check: bool):
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    headers = {"User-Agent": "internal-triage-scan/1.0 (authorized asset review)"}
    async with httpx.AsyncClient(
        timeout=timeout, limits=limits, headers=headers, verify=False
    ) as client:
        tasks = [scan_one(sem, client, d, shell_check) for d in domains]
        results = []
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            flag = ""
            if res.shell_hits:
                flag = "  [!!] SHELL: " + ", ".join(res.shell_hits)
            elif res.php2shell_cve.startswith("VULNERABLE"):
                flag = f"  [CVE] {res.php2shell_cve}"
            elif not res.reachable:
                flag = f"  (unreachable: {res.error})"
            print(f"[{res.status or '---'}] {res.domain}{flag}")
        return results


def write_csv(results: list[Result], path: str) -> None:
    cols = list(asdict(results[0]).keys()) if results else []
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in results:
            d = asdict(r)
            d["shell_hits"] = "; ".join(d["shell_hits"])
            d["review_hits"] = "; ".join(d["review_hits"])
            w.writerow([d[c] for c in cols])


def main() -> None:
    ap = argparse.ArgumentParser(description="Defensive triage scan for OWNED domains.")
    ap.add_argument("domains_file", help="File txt berisi daftar domain milik sendiri.")
    ap.add_argument("--out", default="triage_results.csv", help="File CSV output.")
    ap.add_argument("--concurrency", type=int, default=15)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument(
        "--shell-check",
        action="store_true",
        help="Aktifkan sweep indikator web shell (compromise detection).",
    )
    args = ap.parse_args()

    with open(args.domains_file, encoding="utf-8") as f:
        domains = [d for d in (normalize(l) for l in f) if d]
    domains = sorted(set(domains))
    if not domains:
        sys.exit("Tidak ada domain valid di file.")

    print(f"# Triase {len(domains)} domain | mulai {datetime.now(timezone.utc).isoformat()}")
    print(f"# shell-check: {'ON' if args.shell_check else 'off'} | concurrency: {args.concurrency}\n")

    results = asyncio.run(run(domains, args.concurrency, args.timeout, args.shell_check))
    write_csv(results, args.out)

    reachable = [r for r in results if r.reachable]
    shells = [r for r in results if r.shell_hits]
    cve_vuln = [r for r in results if r.php2shell_cve.startswith("VULNERABLE")]
    cve_unknown = [r for r in results if r.php2shell_cve.startswith("UNKNOWN")]
    print("\n" + "=" * 50)
    print(f"Total        : {len(results)}")
    print(f"Reachable    : {len(reachable)}")
    print(f"PHP terdeteksi: {sum(1 for r in reachable if r.php_detected)}")
    print(f"[!!] Indikasi shell: {len(shells)}")
    for r in shells:
        print(f"     - {r.domain}: {', '.join(r.shell_hits)}")
    print(f"[CVE] PHP2Shell (CVE-2026-109618/619) RENTAN: {len(cve_vuln)}")
    for r in cve_vuln:
        print(f"     - {r.domain}: PHP {r.php_version} -> {r.php2shell_cve}")
    print(f"[CVE] versi PHP tak terdeteksi (perlu cek di host): {len(cve_unknown)}")
    print(f"\nDetail lengkap -> {args.out}")
    if shells:
        print("\nPENTING: temuan shell = INDIKASI, perlu verifikasi manual &")
        print("prosedur incident response, bukan kesimpulan otomatis.")
    if cve_unknown:
        print("\nCatatan CVE: banyak server menyembunyikan versi PHP (expose_php=Off).")
        print("Status pasti CVE-2026-109618/619 dicek di host: `php -v` atau versi paket.")


if __name__ == "__main__":
    main()
