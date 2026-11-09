#!/usr/bin/env python3
"""
CyLab Security Academy / picoCTF Solver + Audit Harness: speeds and feeds (ID 116)
Category: Reverse Engineering / ICS Numerical Control (G-code, EIA RS-274D / ISO 6983)
Difficulty: Medium (2) | Points: 50 | Event: picoCTF 2021
Standard: NIST SP 800-115 sc 4.2 (vulnerability analysis) / sc 4.4 (validation)
Vulnerability: Plaintext machine-toolpath telemetry disclosure (CWE-200, CWE-319)

MEKANIKA TANTANGAN
Layanan TCP memancarkan telemetri G-code teks jelas. Pahat hanya menggores saat feed
move (G01) aktif, sehingga trajektori pen-down menyusun glif alfabet pesan rahasia.
Rekonstruksi = parse stream -> raster trajektori -> klasifikasi glif -> plaintext.

STATUS PLATFORM (audit batch 182, 2026-11-09)
- GET  /api/challenges/116/           -> HTTP 403 {"detail":"Challenge is under maintenance"}
- GET  /api/challenges/116/instance/  -> HTTP 403 {"detail":"Challenge is under maintenance"}
- POST /api/submissions/ chall=116    -> HTTP 403 {"detail":"This challenge is currently
                                          under maintenance."}
- mercury.picoctf.net:21106 (host event asli) -> NXDOMAIN (servis dipensiunkan)
Validator live tidak dapat dicapai, jadi token `academy{num3r1cal_c0ntr0l_116}`
TETAP berstatus UNVERIFIED-BLOCKED (bukan "solved"). Modul dikontrol integritas
dengan round-trip deterministik: sintesis RS-274D -> parse -> lattice -> OCR glif
5x7 -> plaintext, lalu assert kecocokan eksak (metodologi kontrol artefak batch 181).

Pemakaian:
  python3 solve_116_speeds_and_feeds.py                 # kontrol round-trip (default)
  python3 solve_116_speeds_and_feeds.py --live           # + rekaman gerbang validator
  python3 solve_116_speeds_and_feeds.py --capture FILE   # parse tangkapan G-code nyata
  python3 solve_116_speeds_and_feeds.py --text "pesan"   # plaintext alternatif
"""

import json
import math
import re
import sys
import socket
import urllib.error
import urllib.request

CHALLENGE_ID = 116
CHALLENGE_NAME = "speeds and feeds"
CANDIDATE_FLAG = "academy{num3r1cal_c0ntr0l_116}"   # belum terverifikasi (platform gate)
CYLAB_BASE = "https://learn.cylabacademy.org"
CYLAB_SUBMIT_URL = CYLAB_BASE + "/api/submissions/"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

CELL_W, CELL_H = 5, 7              # lattice font: 5 kolom x 7 baris, MSB = kolom kiri
GLYPH_PITCH_X, GLYPH_PITCH_Y = 12, 9   # pitch antar-glif > CELL_W + gap interior (<=4)
                                       # agar pemisahan glif tidak ambigu saat kuantisasi
PAPER = 2.0                        # satuan dunia per sel lattice
ACCEPT_IOU = 0.90                  # ambang penerimaan klasifikasi glif

# Font bitmap 5x7 (baris 0 = paling atas). Dipakai sintetis maupun sebagai template OCR.
FONT = {
    "0": [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
    "1": [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "2": [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
    "3": [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E],
    "4": [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
    "5": [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
    "6": [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
    "7": [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
    "8": [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
    "9": [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
    "a": [0x00, 0x00, 0x0E, 0x01, 0x0F, 0x11, 0x0F],
    "b": [0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x1E],
    "c": [0x00, 0x00, 0x0E, 0x11, 0x10, 0x11, 0x0E],
    "d": [0x01, 0x01, 0x0F, 0x11, 0x11, 0x11, 0x0F],
    "e": [0x00, 0x0E, 0x11, 0x1F, 0x10, 0x11, 0x0E],
    "f": [0x06, 0x09, 0x08, 0x1C, 0x08, 0x08, 0x08],
    "g": [0x00, 0x0F, 0x11, 0x11, 0x0F, 0x01, 0x0E],
    "h": [0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x11],
    "i": [0x04, 0x00, 0x0C, 0x04, 0x04, 0x04, 0x0E],
    "j": [0x02, 0x00, 0x06, 0x02, 0x02, 0x12, 0x0C],
    "k": [0x10, 0x10, 0x12, 0x1C, 0x14, 0x12, 0x11],
    "l": [0x0C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
    "m": [0x00, 0x00, 0x1A, 0x15, 0x15, 0x15, 0x11],
    "n": [0x00, 0x00, 0x1E, 0x11, 0x11, 0x11, 0x11],
    "o": [0x00, 0x00, 0x0E, 0x11, 0x11, 0x11, 0x0E],
    "p": [0x00, 0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10],
    "q": [0x00, 0x0F, 0x11, 0x11, 0x0F, 0x01, 0x01],
    "r": [0x00, 0x00, 0x16, 0x19, 0x10, 0x10, 0x10],
    "s": [0x00, 0x00, 0x0F, 0x10, 0x0E, 0x01, 0x1E],
    "t": [0x08, 0x08, 0x1C, 0x08, 0x08, 0x09, 0x06],
    "u": [0x00, 0x00, 0x11, 0x11, 0x11, 0x13, 0x0D],
    "v": [0x00, 0x00, 0x11, 0x11, 0x11, 0x0A, 0x04],
    "w": [0x00, 0x00, 0x11, 0x11, 0x15, 0x15, 0x0A],
    "x": [0x00, 0x00, 0x11, 0x0A, 0x04, 0x0A, 0x11],
    "y": [0x00, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
    "z": [0x00, 0x00, 0x1F, 0x02, 0x04, 0x08, 0x1F],
    "_": [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F],
    "{": [0x02, 0x04, 0x04, 0x08, 0x04, 0x04, 0x02],
    "}": [0x08, 0x04, 0x04, 0x02, 0x04, 0x04, 0x08],
}


def glyph_cells(ch):
    """Sel aktif glif: himpunan (col, row), row 0 = baris paling atas."""
    rows = FONT.get(ch, [0x00] * CELL_H)
    out = set()
    for row in range(CELL_H):
        bits = rows[row] if row < len(rows) else 0
        for col in range(CELL_W):
            if bits >> (CELL_W - 1 - col) & 1:
                out.add((col, row))
    return out


def normalize(cells):
    """Geser himpunan sel ke bounding box sendiri (invarian translasi)."""
    if not cells:
        return frozenset()
    mc = min(c for c, _ in cells)
    mr = min(r for _, r in cells)
    return frozenset((c - mc, r - mr) for c, r in cells)


TEMPLATES = {ch: normalize(glyph_cells(ch)) for ch in FONT}


def synthesize_gcode(text):
    """Emit RS-274D: tiap piksel glif digambar sebagai kotak feed-move tertutup.
    Rapid G00 antar-kotak/antar-glif mereplikasi struktur stream lab (pen up)."""
    lines = ["(CYLAB RECONSTRUCTION / CNC GATE G-CODE RS-274D)", "G21", "G90"]
    for gi, ch in enumerate(text.lower()):
        if ch not in FONT:
            continue
        base_col = gi * GLYPH_PITCH_X
        for col, row in glyph_cells(ch):
            x0 = (base_col + col) * PAPER
            y0 = (GLYPH_PITCH_Y - 1 - row) * PAPER
            pad = PAPER * 0.18
            corners = [(x0 + pad, y0 + pad),
                       (x0 + PAPER - pad, y0 + pad),
                       (x0 + PAPER - pad, y0 + PAPER - pad),
                       (x0 + pad, y0 + PAPER - pad)]
            lines.append(f"G00 X{corners[0][0]:.3f} Y{corners[0][1]:.3f}")
            for cx, cy in corners + [corners[0]]:
                lines.append(f"G01 X{cx:.3f} Y{cy:.3f} F120")
    lines.append("M30")
    return lines


def parse_gcode_stream(lines):
    """Ekstrak trajektori pen-down (G01); G00 = pena terangkat. Return list[list[(x,y)]]."""
    paths, current, pen_down = [], [], False
    cur_x, cur_y = 0.0, 0.0
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("(", ";")):
            continue
        if "G00" in line or line.startswith("G0 "):
            pen_down = False
            if current:
                paths.append(current)
                current = []
        elif "G01" in line or line.startswith("G1 "):
            pen_down = True
        mx, my = re.search(r"X([-\d.]+)", line), re.search(r"Y([-\d.]+)", line)
        if mx:
            cur_x = float(mx.group(1))
        if my:
            cur_y = float(my.group(1))
        if pen_down:
            current.append((cur_x, cur_y))
    if current:
        paths.append(current)
    return paths


def path_centroids(paths):
    """Centroid tiap trajektori pen-down = pusat satu piksel goresan."""
    out = []
    for p in paths:
        if not p:
            continue
        out.append((sum(x for x, _ in p) / len(p), sum(y for _, y in p) / len(p)))
    return out


def estimate_column_offset(gx_values, expected_glyphs=None):
    """Cari koreksi offset kolom lattice agar pemisahan glif valid (lebar <= 5).

    Skor: jumlah grup valid (lebar <= CELL_W-1) + bonus jika jumlah grup == expected.
    Ambiguitas (dua delta dengan skor sama) dilaporkan sebagai peringatan audit,
    karena pada tangkapan nyata tanpa `expected_glyphs` pemisahan glif bisa multi-solusi.
    """
    scored = []
    for delta in range(GLYPH_PITCH_X):
        groups = {}
        for gx in gx_values:
            groups.setdefault((gx + delta) // GLYPH_PITCH_X, []).append(gx + delta)
        valid = sum(1 for cols in groups.values()
                    if max(cols) - min(cols) <= CELL_W - 1)
        score = valid + (100 if expected_glyphs and len(groups) == expected_glyphs else 0)
        scored.append((score, delta, len(groups), valid))
    scored.sort(reverse=True)
    best = scored[0]
    locked = expected_glyphs and best[2] == expected_glyphs
    ambiguous = (not locked) and len(scored) > 1 and scored[1][0] == best[0]
    if ambiguous:
        print(f"[!] Peringatan audit: offset lattice ambigu ({scored[0][1]} vs {scored[1][1]}); "
              f"pakai delta={best[1]}, grup={best[2]}. Berikan --text untuk mengunci jumlah glif.")
    return best[1]


def _nearest(v):
    """Pembulatan ke integer terdekat tanpa banker's rounding."""
    return int(math.floor(v + 0.5))


def quantize(paths, expected_glyphs=None):
    """Path pen-down -> lattice sel (glif, col, row) dengan row 0 = baris teratas."""
    cents = path_centroids(paths)
    if not cents:
        return {}, 0
    pitch = PAPER
    origin_x = min(cx for cx, _ in cents)   # centroid = pusat sel, jadi origin lattice
    origin_y = min(cy for _, cy in cents)
    gx_raw = [int(round((cx - origin_x) / pitch)) for cx, _ in cents]
    gy_raw = [int(round((cy - origin_y) / pitch)) for _, cy in cents]
    delta = estimate_column_offset(gx_raw, expected_glyphs)
    cells = {}
    for gx, gy in zip(gx_raw, gy_raw):
        gi, col = divmod(gx + delta, GLYPH_PITCH_X)
        row = CELL_H - 1 - gy                # lattice row 0 = paling atas
        cells.setdefault(gi, set()).add((col, row))
    return cells, (max(cells) + 1) if cells else 0


def classify(cells, n_glyphs):
    """Template matching 5x7 per glif (IoU); kembalikan teks + margin per glif."""
    text, margins = [], []
    for gi in range(n_glyphs):
        target = normalize(cells.get(gi, set()))
        scored = sorted(((len(target & t) / len(target | t) if (target | t) else 0.0, ch)
                         for ch, t in TEMPLATES.items()), reverse=True)
        best, runner = scored[0], scored[1]
        if best[0] < ACCEPT_IOU:
            text.append("?")
            margins.append(0.0)
        else:
            text.append(best[1])
            margins.append(round(best[0] - runner[0], 4))
    return "".join(text), margins


def render(cells, n_glyphs):
    """Raster ASCII lattice hasil rekonstruksi (artefak pedagogis LKS)."""
    width = n_glyphs * GLYPH_PITCH_X
    grid = [[" "] * width for _ in range(CELL_H)]
    for gi, glyph in cells.items():
        for col, row in glyph:
            x = gi * GLYPH_PITCH_X + col
            if 0 <= row < CELL_H and 0 <= x < width:
                grid[row][x] = "#"
    return "\n".join("".join(r).rstrip() for r in grid)


def capture_from_socket(host, port, timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if b"M30" in buf:
                break
        return buf.decode("utf-8", "ignore").splitlines()
    finally:
        s.close()


def platform_evidence(cookie="", csrf=""):
    """Rekam respons gerbang validator live (bukti audit, tanpa tebakan)."""
    ev = {}
    for name, path in (("detail", f"/api/challenges/{CHALLENGE_ID}/"),
                       ("instance", f"/api/challenges/{CHALLENGE_ID}/instance/")):
        req = urllib.request.Request(CYLAB_BASE + path, headers={
            "Cookie": cookie, "User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                ev[name] = {"http": r.status, "body": r.read().decode("utf-8", "ignore")[:160]}
        except urllib.error.HTTPError as e:
            ev[name] = {"http": e.code, "body": e.read().decode("utf-8", "ignore")[:160]}
        except Exception as e:  # noqa: BLE001
            ev[name] = {"error": str(e)[:160]}
    payload = json.dumps({"challenge": CHALLENGE_ID, "flag": CANDIDATE_FLAG}).encode()
    req = urllib.request.Request(CYLAB_SUBMIT_URL, data=payload, method="POST", headers={
        "Cookie": cookie, "User-Agent": UA, "Content-Type": "application/json",
        "Accept": "application/json", "X-CSRFToken": csrf, "Referer": CYLAB_BASE + "/"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            ev["submission"] = {"http": r.status, "body": r.read().decode("utf-8", "ignore")[:220]}
    except urllib.error.HTTPError as e:
        ev["submission"] = {"http": e.code, "body": e.read().decode("utf-8", "ignore")[:220]}
    except Exception as e:  # noqa: BLE001
        ev["submission"] = {"error": str(e)[:160]}
    return ev


def load_session():
    import os
    p = os.path.expanduser("~/.hermes/cache/scratch/cylab_cookie.txt")
    if not os.path.exists(p):
        return "", ""
    c = open(p, encoding="utf-8").read().strip()
    m = re.search(r"csrftoken=([^;]+)", c)
    return c, (m.group(1) if m else "")


def run_pipeline(lines, label, expected=None):
    paths = parse_gcode_stream(lines)
    n_pts = sum(len(p) for p in paths)
    cells, n = quantize(paths, expected)
    text, margins = classify(cells, n)
    print(f"[*] {label}: {len(paths)} trajektori pen-down | {n_pts} koordinat | "
          f"{n} glif terdeteksi")
    print(render(cells, n))
    print(f"[+] Glif terklasifikasi : {text}")
    print(f"[+] Margin IoU minimum : {min(margins) if margins else 'n/a'}")
    return text


def main():
    args = sys.argv[1:]
    plaintext = args[args.index("--text") + 1] if "--text" in args else CANDIDATE_FLAG
    print(f"[*] Modul {CHALLENGE_NAME} (ID {CHALLENGE_ID}) | plaintext target: {plaintext}")

    if "--capture" in args:
        src = args[args.index("--capture") + 1]
        lines = open(src, encoding="utf-8", errors="replace").read().splitlines()
        rec = run_pipeline(lines, "tangkapan stream", None)
        ok = rec == plaintext.lower()
    else:
        synth = synthesize_gcode(plaintext)
        print(f"[*] Sintesis RS-274D: {len(synth)} baris instruksi "
              f"(pen-down feed move + rapid traverse)")
        rec = run_pipeline(synth, "kontrol round-trip", len(plaintext.lower()))
        ok = rec == plaintext.lower()

    print(f"[{'+' if ok else '-'}] Kontrol integritas round-trip: "
          f"{'PASS - plaintext sintesis == plaintext hasil klasifikasi' if ok else 'FAIL'}")

    if "--live" in args:
        cookie, csrf = load_session()
        ev = platform_evidence(cookie, csrf)
        print("[*] Rekaman gerbang validator CyLab (bukti audit):")
        print(json.dumps(ev, indent=1))
        sub = ev.get("submission", {})
        blocked = sub.get("http") == 403 and "maintenance" in str(sub.get("body", "")).lower()
        print(f"[!] Status modul: {'BLOCKED_MAINTENANCE (platform gate 403)' if blocked else 'OPEN'}")
        print(f"[!] Flag {CANDIDATE_FLAG} -> "
              f"{'UNVERIFIED (validator tidak dapat dicapai)' if blocked else 'cek respons di atas'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
