#!/usr/bin/env node
/*
 * run_bulk.js - jalankan phpcheck.js OpenAI pada BANYAK domain dari file .txt,
 * simpan hasil ke .csv, dan tampilkan ke layar.
 *
 * Hanya memakai Node built-in (child_process). Tidak mengubah tool OpenAI;
 * ia memanggil phpcheck.js --json per domain lalu mengumpulkan hasilnya.
 *
 * Pakai (cmd/PowerShell):
 *   node run_bulk.js domains.txt
 *   node run_bulk.js domains.txt --out hasil.csv --concurrency 10 --timeout 10
 *   node run_bulk.js domains.txt --tool "C:\path\ke\phpcheck.js"
 *
 * domains.txt: satu domain/URL per baris; baris kosong & diawali '#' diabaikan.
 * Gunakan HANYA pada aset milik sendiri / yang Anda punya izin memeriksanya.
 */
'use strict'
const fs = require('node:fs')
const path = require('node:path')
const { execFile } = require('node:child_process')

function parseCli(argv) {
  const o = {
    file: null,
    out: 'php2shell_results.csv',
    concurrency: 10,
    timeout: 10,
    // default: phpcheck.js yang berada SATU FOLDER dengan script ini.
    // Memakai __dirname -> folder bisa dipindah ke mana pun, tetap jalan.
    tool: path.join(__dirname, 'phpcheck.js'),
  }
  const a = argv.slice(2)
  for (let i = 0; i < a.length; i++) {
    const t = a[i]
    if (t === '--out') o.out = a[++i]
    else if (t === '--concurrency') o.concurrency = Number(a[++i])
    else if (t === '--timeout') o.timeout = Number(a[++i])
    else if (t === '--tool') o.tool = a[++i]
    else if (!o.file) o.file = t
  }
  return o
}

function normalize(line) {
  line = line.trim()
  if (!line || line.startsWith('#')) return null
  if (!/^https?:\/\//i.test(line)) line = 'https://' + line
  return line.replace(/\/+$/, '')
}

function csvCell(v) {
  v = v == null ? '' : String(v)
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v
}

// Panggil phpcheck.js untuk satu URL; selalu resolve (tidak reject),
// baca JSON dari stdout apa pun exit code-nya.
function runOne(nodeBin, tool, url, timeout) {
  return new Promise((resolve) => {
    execFile(
      nodeBin,
      [tool, url, '--json', '--timeout', String(timeout)],
      { timeout: (timeout + 8) * 1000, windowsHide: true },
      (err, stdout, stderr) => {
        const out = (stdout || '').trim()
        try {
          const r = JSON.parse(out)
          return resolve({
            patch_status: r.patch_status,
            php_version: r.php_version,
            reason: r.reason,
            exit_code: r.exit_code,
          })
        } catch (_) {
          resolve({
            patch_status: 'error',
            php_version: null,
            reason: ((stderr || '') + (err ? ' ' + err.message : '')).trim() || 'no output',
            exit_code: err && typeof err.code === 'number' ? err.code : -1,
          })
        }
      }
    )
  })
}

async function pool(items, size, worker) {
  const results = new Array(items.length)
  let idx = 0
  const n = Math.max(1, Math.min(size, items.length))
  await Promise.all(
    Array.from({ length: n }, async () => {
      while (true) {
        const i = idx++
        if (i >= items.length) break
        results[i] = await worker(items[i], i)
      }
    })
  )
  return results
}

async function main() {
  const o = parseCli(process.argv)
  if (!o.file) {
    console.error('Usage: node run_bulk.js domains.txt [--out hasil.csv] [--concurrency 10] [--timeout 10] [--tool PATH]')
    process.exit(2)
  }
  if (!fs.existsSync(o.tool)) {
    console.error('Tool phpcheck.js tidak ditemukan di: ' + o.tool + '\nGunakan --tool untuk menunjuk lokasinya.')
    process.exit(2)
  }
  const domains = [...new Set(
    fs.readFileSync(o.file, 'utf8').split(/\r?\n/).map(normalize).filter(Boolean)
  )]
  if (!domains.length) {
    console.error('Tidak ada domain valid di ' + o.file)
    process.exit(2)
  }

  console.log(`# phpcheck bulk | ${domains.length} domain | concurrency ${o.concurrency} | timeout ${o.timeout}s`)
  console.log('# status: OK=aman  VULNERABLE=rentan  UNKNOWN=versi tak terbaca  ERROR=gagal konek\n')

  const label = { ok: '[OK]        ', vulnerable: '[VULNERABLE]', unknown: '[UNKNOWN]   ', error: '[ERROR]     ' }
  const counts = { ok: 0, vulnerable: 0, unknown: 0, error: 0 }
  const nodeBin = process.execPath

  let done = 0
  const rows = await pool(domains, o.concurrency, async (url) => {
    const r = await runOne(nodeBin, o.tool, url, o.timeout)
    const st = r.patch_status in counts ? r.patch_status : 'error'
    counts[st]++
    done++
    const ver = r.php_version ? ` PHP ${r.php_version}` : ''
    console.log(`${label[st] || '[?]         '} ${url}${ver}  (${done}/${domains.length})`)
    return { domain: url, ...r }
  })

  // Tulis CSV
  const header = ['domain', 'patch_status', 'php_version', 'reason', 'exit_code']
  const lines = [header.join(',')]
  for (const r of rows) {
    lines.push([r.domain, r.patch_status, r.php_version, r.reason, r.exit_code].map(csvCell).join(','))
  }
  fs.writeFileSync(o.out, lines.join('\n') + '\n', 'utf8')

  console.log('\n' + '='.repeat(48))
  console.log(`Total        : ${domains.length}`)
  console.log(`VULNERABLE   : ${counts.vulnerable}`)
  console.log(`OK           : ${counts.ok}`)
  console.log(`UNKNOWN      : ${counts.unknown}  (versi disembunyikan -> cek di host: php -v)`)
  console.log(`ERROR        : ${counts.error}`)
  console.log(`\nCSV tersimpan -> ${path.resolve(o.out)}`)
  if (counts.vulnerable) {
    console.log('\nDomain RENTAN:')
    for (const r of rows) if (r.patch_status === 'vulnerable') console.log(`  - ${r.domain} (PHP ${r.php_version})`)
    console.log('\nTindakan: update ke rilis ber-patch (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).')
  }
}

main()
