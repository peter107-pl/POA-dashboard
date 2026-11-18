"""Build the password-protected POA snapshot page.

Usage: [POA_PASSWORD=...] python3 -I poa_build.py POA.xlsx OUT_DIR  (no POA_PASSWORD = open page)
Writes OUT_DIR/index.html: a static page whose dashboard is AES-256-GCM
encrypted with a key derived from the password (PBKDF2-SHA256), decrypted
in the browser with WebCrypto. Nothing readable is stored in the page.
"""
import base64, datetime as dt, json, os, re, sys
from collections import Counter

import openpyxl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = os.path.dirname(os.path.abspath(__file__))
ITER = 600_000

LINES = {"limitless family care": "Limitless Family Care", "limitless wellness": "Limitless Wellness", "trade line": "Trade Line"}
TYPES = {"sam": "Standalone Meetings"}
BRANDS = {"limitlessjointavoplus": "Limitless Joint Avoplus", "iamlimitlesspharmcist": "I am Limitless Pharmacist",
          "iamlimitlesspharmacist": "I am Limitless Pharmacist", "limitlessdigistnow": "Limitless Digest Now"}


def clean(s):
    return re.sub(r"\s+", " ", str(s)).strip() if s is not None else ""


def num(v):
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    m = re.match(r"^\s*([\d.,]+)\s*([KkMm]?)\b", str(v))
    if not m:
        return None
    try:
        x = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    return x * {"k": 1e3, "m": 1e6}.get(m.group(2).lower(), 1)


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def read_sheet(path):
    wb = openpyxl.load_workbook(path, data_only=True)
    if "POA" not in wb.sheetnames:
        raise SystemExit("The workbook has no sheet named POA")
    rows = list(wb["POA"].iter_rows(values_only=True))
    hdr = rows[0]
    if clean(hdr[5]).lower() != "activity" or clean(hdr[6]).lower() != "kpis":
        raise SystemExit(f"POA header changed: column F={hdr[5]!r}, G={hdr[6]!r}")
    wcols = [(i, h.date()) for i, h in enumerate(hdr) if i >= 11 and isinstance(h, dt.datetime)]
    # weekly columns: a 7-day chain starting at the first dated column (the stray "11-Nov" between 11 and 18 Oct is skipped)
    week_of = {}
    for i, d in wcols:
        last = max(week_of.values()) if week_of else None
        if last is None or (d - last).days == 7:
            week_of[i] = d
    odd_cols = [i for i, _ in wcols if i not in week_of]
    weeks = sorted(week_of.values())

    tactics = []
    for r_i, r in enumerate(rows[1:], start=2):
        r = list(r) + [None] * (len(hdr) - len(r))
        activity = clean(r[5])
        if not activity:
            continue
        brand = clean(r[1])
        brand = BRANDS.get(re.sub(r"[^a-z0-9]", "", brand.lower()), brand) or "(no brand)"
        target = num(r[6])
        by_week, pending = {}, False
        for i, d in week_of.items():
            v = r[i]
            if is_num(v):
                by_week[d] = float(v)
            elif isinstance(v, str) and v.strip().upper() == "PENDING":
                pending = True
                by_week.setdefault(d, None)
        nums = [v for v in by_week.values() if v is not None]
        extra = [float(r[i]) for i in odd_cols if is_num(r[i])]
        k = float(r[10]) if is_num(r[10]) else None
        cand = nums + extra + ([k] if k is not None else [])
        achieved = max(cand) if cand else 0.0
        if not target:
            progress, status = None, "No numeric KPI"
        else:
            progress = achieved / target
            status = "Done" if progress >= 1 else "In progress" if progress > 0 else "Pending" if pending else "Not started"
        atype = clean(r[3])
        tactics.append({
            "row": r_i, "line": LINES.get(clean(r[0]).lower(), clean(r[0]) or "(no line)"), "brand": brand,
            "owner": clean(r[2]) or "(no owner)", "type": TYPES.get(atype.lower(), atype) or "(no type)",
            "segment": clean(r[4]), "activity": activity, "kpi": clean(r[8]), "target": target,
            "budget": float(r[7]) if is_num(r[7]) else None, "achieved": achieved,
            "progress": None if progress is None else round(progress, 4), "status": status,
            "last": max(by_week).isoformat() if by_week else None,
            "weeks": {d.isoformat(): v for d, v in by_week.items()},
        })
    # same brand typed with different capitals/spaces -> most used spelling
    key = lambda b: re.sub(r"[^a-z0-9]", "", b.lower())
    forms = {}
    for t in tactics:
        forms.setdefault(key(t["brand"]), Counter())[t["brand"]] += 1
    for t in tactics:
        t["brand"] = forms[key(t["brand"])].most_common(1)[0][0]
    filled = [d.isoformat() for d in weeks if any(d.isoformat() in t["weeks"] for t in tactics)]
    return tactics, filled


def encrypt(plain, password):
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plain.encode(), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"salt": b(salt), "iv": b(iv), "ct": b(ct), "iter": ITER}


def main():
    src, out = sys.argv[1], sys.argv[2]
    password = os.environ.get("POA_PASSWORD", "")
    if password and len(password) < 8:
        raise SystemExit("POA_PASSWORD must be 8+ characters (or unset for an open page)")
    tactics, weeks = read_sheet(src)
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=2)))
    payload = {"tactics": tactics, "weeks": weeks, "built": now.strftime("%a %d %b %Y, %H:%M") + " Cairo"}
    inner = open(os.path.join(HERE, "dashboard.html"), encoding="utf-8").read()
    inner = inner.replace("/*__DATA__*/null", json.dumps(payload, ensure_ascii=False).replace("</", "<\\/"))
    if password:
        lock = open(os.path.join(HERE, "lock.html"), encoding="utf-8").read()
        page = lock.replace("/*__BLOB__*/null", json.dumps(encrypt(inner, password)))
    else:
        page = inner  # no password: the dashboard itself, readable by anyone with the link
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
        f.write(page)
    with open(os.path.join(out, ".nojekyll"), "w") as f:
        f.write("")
    done = sum(t["status"] == "Done" for t in tactics)
    print(f"{len(tactics)} tactics, weeks {weeks[:1]}..{weeks[-1:]}, {done} at KPI -> {out}/index.html")


if __name__ == "__main__":
    main()
