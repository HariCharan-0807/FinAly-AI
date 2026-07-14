"""
FinAly AI — Bank Statement Parser
===================================
Supports : CSV  — HDFC, SBI, ICICI, Axis, Kotak + Generic auto-detect
           PDF  — via pdfplumber table extraction (same bank profiles)

Security  : Files are processed ENTIRELY IN MEMORY.
            Nothing is written to disk.
            Caller is responsible for not persisting file_bytes.
"""

import csv
import hashlib
import io
import re
from datetime import datetime
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
#  Auto-Categorisation Engine
# ══════════════════════════════════════════════════════════════════════════════

CATEGORY_RULES: list[tuple[list[str], str]] = [
    # ── Food & Dining ──────────────────────────────────────────────────────
    (["swiggy", "zomato", "dunzo", "blinkit", "bigbasket", "grofers",
      "zepto", "instamart", "restaurant", "cafe", "diner", "eatery",
      "food", "kitchen", "pizza", "burger", "kfc", "mcdonald", "domino",
      "starbucks", "subway", "biryani", "dhaba", "tiffin", "canteen",
      "dine", "meal", "lunch", "dinner", "breakfast", "snack",
      "haldiram", "barbeque", "fassos", "wow momo", "chaayos",
      "amul", "nandos", "the good bowl"], "Food"),

    # ── Transport & Travel ────────────────────────────────────────────────
    (["uber", "ola ", "rapido", "auto ", "taxi", "cab ", "metro",
      "railway", "irctc", "dmrc", "bmtc", "best bus", "bus ", "petrol",
      "fuel", "diesel", "fastag", "toll", "makemytrip", "goibibo",
      "redbus", "yatra", "easemytrip", "indigo", "spicejet", "airindia",
      "vistara", "akasa", "parking", "namma metro", "ola electric",
      "bounce", "yulu", "vogo", "bp fuel", "indian oil", "hpcl", "bpcl"], "Transport"),

    # ── Entertainment ─────────────────────────────────────────────────────
    (["netflix", "hotstar", "disneyplus", "spotify", "amazon prime",
      "youtube premium", "zee5", "sonyliv", "jiocinema", "altbalaji",
      "mxplayer", "bookmyshow", "pvr ", "inox ", "cinepolis",
      "steam ", "playstation", "xbox ", "epic games", "gaming",
      "play store", "app store", "nintendo", "twitch"], "Entertainment"),

    # ── Shopping ──────────────────────────────────────────────────────────
    (["amazon", "flipkart", "myntra", "meesho", "ajio ", "nykaa",
      "shopsy", "snapdeal", "tatacliq", "reliance digital",
      "croma ", "vijay sales", "jiomart", "lenskart", "boat ",
      "shopping", "mall ", "retail", "bazaar", "emporium",
      "big bazaar", "dmart", "reliance fresh", "more supermarket",
      "lifestyle", "max fashion", "westside", "pantaloons", "h&m"], "Shopping"),

    # ── Rent & Housing ────────────────────────────────────────────────────
    (["rent", "maintenance", "society fee", "housing", "property",
      "apartment", "flat ", "pg ", "hostel ", "lease", "landlord",
      "deposit", "advance rent", "house rent", "nobroker", "magicbricks",
      "99acres", "nestaway", "stanza living", "common facilities"], "Rent"),

    # ── Utilities ─────────────────────────────────────────────────────────
    (["bescom", "electricity", "tata power", "adani electric", "msedcl",
      "bses", "tneb", "pspcl", "wesco", "water board", "bwssb", "cwds",
      "gas ", "lpg", "hp gas", "bharat gas", "indane", "mahanagar gas",
      "airtel", "jio ", "vodafone", "vi ", "bsnl", "broadband",
      "internet", "wifi", "act fibernet", "hathway", "tikona",
      "utility", "bill pay", "bbmp", "pmc", "nmmc"], "Utilities"),

    # ── Healthcare ────────────────────────────────────────────────────────
    (["apollo", "medplus", "fortis", "manipal", "narayana", "aiims",
      "max hospital", "columbia asia", "care hospital", "yashoda",
      "hospital", "clinic", "doctor", "physician", "surgeon",
      "pharmacy", "chemist", "medicine", "health", "medical",
      "diagnostic", "lab ", "pathology", "lic ", "star health",
      "max bupa", "niva bupa", "hdfc ergo", "icici lombard health",
      "1mg", "netmeds", "pharmeasy", "tata 1mg", "healthkart"], "Healthcare"),

    # ── Education ─────────────────────────────────────────────────────────
    (["school", "college", "university", "fees", "tuition", "iit",
      "nit ", "iim ", "coursera", "udemy", "upgrad", "byju",
      "unacademy", "vedantu", "toppr", "physicswallah", "pw ",
      "simplilearn", "edx", "khan academy", "education", "exam",
      "certification", "library", "books", "stationery"], "Education"),

    # ── Income signals ─ check LAST to avoid false positives ──────────────
    (["salary", "payroll", "stipend", "paycheck",
      "neft cr", "imps cr", "rtgs cr", "upi cr", "credit by",
      "dividend", "interest cr", "credit interest", "int. cr",
      "refund", "cashback", "reversal", "inward remittance",
      "tds refund", "it refund", "income tax refund"], "Income"),
]

VALID_CATEGORIES = {
    "Food", "Rent", "Transport", "Utilities", "Healthcare",
    "Entertainment", "Shopping", "Education", "Income", "Other",
}


def auto_categorise(description: str, transaction_type: str) -> tuple[str, str]:
    """
    Returns (category, confidence).
    confidence: 'high' | 'medium' | 'low'
    """
    if transaction_type == "Income":
        return "Income", "high"
    desc_lower = description.lower()
    for keywords, category in CATEGORY_RULES:
        if category == "Income":
            continue
        for kw in keywords:
            if kw in desc_lower:
                return category, "high"
    return "Other", "low"


# ══════════════════════════════════════════════════════════════════════════════
#  Dedup Hash
# ══════════════════════════════════════════════════════════════════════════════

def dedup_hash(date: datetime, amount: float, description: str) -> str:
    """
    SHA-256 of normalised (date, amount, description).
    Used to detect duplicate imports across re-uploads of the same statement.
    """
    raw = f"{date.strftime('%Y-%m-%d')}|{amount:.2f}|{description.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

DATE_FORMATS = [
    "%d/%m/%Y", "%d-%m-%Y", "%d %b %Y", "%d-%b-%Y",
    "%d/%m/%y", "%d-%m-%y", "%Y-%m-%d", "%m/%d/%Y",
    "%d %B %Y", "%b %d, %Y", "%d.%m.%Y", "%d.%m.%y",
    "%d %b %y", "%d-%B-%Y",
]


def _parse_date(s: str) -> Optional[datetime]:
    s = s.strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _clean_amount(s: str) -> Optional[float]:
    """Strip ₹, $, commas, spaces and parse as float."""
    if not s or not s.strip():
        return None
    cleaned = re.sub(r"[₹$,\s\u20b9]", "", s.strip())
    try:
        v = float(cleaned)
        return v if v > 0 else None
    except ValueError:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  Bank Profiles — column name mappings for each bank
# ══════════════════════════════════════════════════════════════════════════════

BANK_PROFILES: dict[str, dict] = {
    "hdfc": {
        "signals": ["narration", "withdrawal amt", "deposit amt", "closing balance"],
        "date":   ["date"],
        "debit":  ["withdrawal amt.", "withdrawal amt", "debit"],
        "credit": ["deposit amt.", "deposit amt", "credit"],
        "desc":   ["narration", "description", "particulars"],
    },
    "sbi": {
        "signals": ["txn date", "ref no./cheque no.", "debit", "credit"],
        "date":   ["txn date", "transaction date", "date"],
        "debit":  ["debit"],
        "credit": ["credit"],
        "desc":   ["description", "narration", "particulars"],
    },
    "icici": {
        "signals": ["transaction remarks", "withdrawal amount (inr", "deposit amount (inr"],
        "date":   ["transaction date", "value date", "date"],
        "debit":  ["withdrawal amount (inr )", "withdrawal amount(inr)", "debit"],
        "credit": ["deposit amount (inr )", "deposit amount(inr)", "credit"],
        "desc":   ["transaction remarks", "narration", "description"],
    },
    "axis": {
        "signals": ["tran date", "particulars", "chq/ref no"],
        "date":   ["tran date", "transaction date", "date"],
        "debit":  ["debit", "withdrawal"],
        "credit": ["credit", "deposit"],
        "desc":   ["particulars", "narration", "description"],
    },
    "kotak": {
        "signals": ["transaction date", "debit amount", "credit amount"],
        "date":   ["transaction date", "date"],
        "debit":  ["debit amount", "debit"],
        "credit": ["credit amount", "credit"],
        "desc":   ["description", "narration", "particulars"],
    },
    "yes": {
        "signals": ["transaction date", "narration", "withdrawal", "deposit"],
        "date":   ["transaction date", "date"],
        "debit":  ["withdrawal", "debit"],
        "credit": ["deposit", "credit"],
        "desc":   ["narration", "description"],
    },
    "pnb": {
        "signals": ["value date", "debit", "credit", "narration"],
        "date":   ["value date", "date"],
        "debit":  ["debit"],
        "credit": ["credit"],
        "desc":   ["narration", "description", "particulars"],
    },
}


def _detect_bank(headers: list[str]) -> str:
    hl = [h.lower().strip() for h in headers]
    best, best_score = "generic", 0
    for bank, profile in BANK_PROFILES.items():
        score = sum(1 for sig in profile["signals"] if any(sig in h for h in hl))
        if score > best_score:
            best, best_score = bank, score
    return best if best_score >= 2 else "generic"


def _find_col(headers_lower: list[str], candidates: list[str]) -> Optional[int]:
    for candidate in candidates:
        for i, h in enumerate(headers_lower):
            if candidate in h:
                return i
    return None


def _resolve_cols(headers: list[str], bank: str) -> tuple:
    """Return (date_col, debit_col, credit_col, desc_col) indices."""
    hl = [h.lower() for h in headers]
    profile = BANK_PROFILES.get(bank)
    if profile:
        return (
            _find_col(hl, profile["date"]),
            _find_col(hl, profile["debit"]),
            _find_col(hl, profile["credit"]),
            _find_col(hl, profile["desc"]),
        )
    # Generic fallback
    return (
        _find_col(hl, ["date", "txn date", "transaction date", "value date"]),
        _find_col(hl, ["debit", "withdrawal", "dr", "amount dr", "debit amount"]),
        _find_col(hl, ["credit", "deposit", "cr", "amount cr", "credit amount"]),
        _find_col(hl, ["narration", "description", "particulars", "remarks", "details"]),
    )


def _build_row(date: datetime, desc: str, amount: float, txn_type: str) -> dict:
    cat, conf = auto_categorise(desc, txn_type)
    return {
        "date":             date.isoformat(),
        "description":      desc[:255],
        "amount":           round(amount, 2),
        "transaction_type": txn_type,
        "category":         cat,
        "confidence":       conf,
        "import_hash":      dedup_hash(date, amount, desc),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  CSV Parser
# ══════════════════════════════════════════════════════════════════════════════

def parse_csv(file_bytes: bytes, bank_hint: str = "auto") -> dict:
    """
    Parse a bank CSV statement.
    Returns: {"bank": str, "source": "bank_csv", "rows": list[dict], "errors": list[str]}
    """
    errors: list[str] = []
    rows:   list[dict] = []

    # Decode — UTF-8 BOM → latin-1 fallback
    try:
        text = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = file_bytes.decode("latin-1")
        except Exception as e:
            return {"bank": "unknown", "source": "bank_csv", "rows": [], "errors": [f"Decode failed: {e}"]}

    # Detect delimiter
    sample = text[:2048]
    delim = "," if sample.count(",") >= sample.count(";") else ";"

    try:
        reader   = csv.reader(io.StringIO(text), delimiter=delim)
        all_rows = list(reader)
    except Exception as e:
        return {"bank": "unknown", "source": "bank_csv", "rows": [], "errors": [f"CSV read failed: {e}"]}

    if not all_rows:
        return {"bank": "unknown", "source": "bank_csv", "rows": [], "errors": ["CSV file is empty."]}

    # Find header row: first row with ≥ 3 non-empty cells
    header_idx, headers = 0, []
    for i, row in enumerate(all_rows):
        non_empty = [c.strip() for c in row if c.strip()]
        if len(non_empty) >= 3:
            header_idx = i
            headers    = [c.strip() for c in row]
            break

    if not headers:
        return {"bank": "unknown", "source": "bank_csv", "rows": [], "errors": ["No header row found."]}

    bank = bank_hint if bank_hint not in ("auto", "") else _detect_bank(headers)
    date_col, debit_col, cred_col, desc_col = _resolve_cols(headers, bank)

    if date_col is None or (debit_col is None and cred_col is None):
        errors.append(
            "Could not identify date / amount columns. "
            "Try selecting your bank manually."
        )

    for line_no, row in enumerate(all_rows[header_idx + 1:], start=header_idx + 2):
        if not any(c.strip() for c in row):
            continue

        max_needed = max(x for x in [date_col, debit_col, cred_col, desc_col] if x is not None)
        if len(row) <= max_needed:
            errors.append(f"Line {line_no}: too few columns, skipped.")
            continue

        date = _parse_date(row[date_col]) if date_col is not None else None
        if not date:
            continue  # silently skip non-data rows (summaries, notes)

        desc   = row[desc_col].strip()  if desc_col  is not None else ""
        debit  = _clean_amount(row[debit_col])  if debit_col is not None else None
        credit = _clean_amount(row[cred_col])   if cred_col  is not None else None

        if debit and debit > 0:
            rows.append(_build_row(date, desc, debit,  "Expense"))
        elif credit and credit > 0:
            rows.append(_build_row(date, desc, credit, "Income"))
        # else: no usable amount → skip

    return {"bank": bank, "source": "bank_csv", "rows": rows, "errors": errors}


# ══════════════════════════════════════════════════════════════════════════════
#  PDF Parser
# ══════════════════════════════════════════════════════════════════════════════

def parse_pdf(file_bytes: bytes, bank_hint: str = "auto") -> dict:
    """
    Parse a bank PDF statement via pdfplumber table extraction.
    Returns: {"bank": str, "source": "bank_pdf", "rows": list[dict], "errors": list[str]}
    """
    errors: list[str] = []
    rows:   list[dict] = []

    try:
        import pdfplumber  # type: ignore
    except ImportError:
        return {
            "bank": "unknown", "source": "bank_pdf", "rows": [],
            "errors": ["pdfplumber not installed. Run: pip install pdfplumber"]
        }

    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            all_tables: list = []
            for page in pdf.pages:
                tables = page.extract_tables()
                if tables:
                    all_tables.extend(tables)
    except Exception as e:
        return {"bank": "unknown", "source": "bank_pdf", "rows": [],
                "errors": [f"Could not open PDF: {e}. Make sure the file is a valid, non-encrypted bank statement."]}

    if not all_tables:
        return {
            "bank": "unknown", "source": "bank_pdf", "rows": [],
            "errors": [
                "No transaction tables found in the PDF. "
                "Please make sure you're uploading a bank statement (not a passbook image scan). "
                "If the PDF is image-based, download the e-statement in text format from your bank."
            ],
        }

    # Pick largest table
    best_table = max(all_tables, key=len)
    if len(best_table) < 2:
        errors.append("PDF table has too few rows.")
        return {"bank": "unknown", "source": "bank_pdf", "rows": [], "errors": errors}

    # Find header row
    headers, data_start = [], 0
    for i, row in enumerate(best_table):
        cells = [str(c or "").strip() for c in row]
        non_empty = [c for c in cells if c]
        if len(non_empty) >= 3:
            headers    = cells
            data_start = i + 1
            break

    bank = bank_hint if bank_hint not in ("auto", "") else _detect_bank(headers)
    date_col, debit_col, cred_col, desc_col = _resolve_cols(headers, bank)

    for line_no, row in enumerate(best_table[data_start:], start=data_start + 1):
        cells = [str(c or "").strip() for c in row]
        if not any(cells):
            continue

        date = _parse_date(cells[date_col]) if date_col is not None and date_col < len(cells) else None
        if not date:
            continue

        desc   = cells[desc_col]  if desc_col  is not None and desc_col  < len(cells) else ""
        debit  = _clean_amount(cells[debit_col])  if debit_col is not None and debit_col < len(cells) else None
        credit = _clean_amount(cells[cred_col])   if cred_col  is not None and cred_col  < len(cells) else None

        if debit and debit > 0:
            rows.append(_build_row(date, desc, debit,  "Expense"))
        elif credit and credit > 0:
            rows.append(_build_row(date, desc, credit, "Income"))

    return {"bank": bank, "source": "bank_pdf", "rows": rows, "errors": errors}


# ══════════════════════════════════════════════════════════════════════════════
#  Public Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def parse_statement(file_bytes: bytes, filename: str, bank_hint: str = "auto") -> dict:
    """
    Dispatch to the correct parser using magic-byte detection.
    Never writes to disk — processes file_bytes entirely in memory.

    Raises ValueError for unsupported or invalid file types.
    """
    if len(file_bytes) < 8:
        raise ValueError("File is too small to be a valid bank statement.")

    magic = file_bytes[:4]

    # PDF: starts with %PDF
    if magic == b"%PDF":
        return parse_pdf(file_bytes, bank_hint)

    # CSV / text: try to decode
    for enc in ("utf-8-sig", "latin-1"):
        try:
            sample = file_bytes[:2048].decode(enc)
            # Must look like text with field separators
            if any(ch in sample for ch in (",", "\t", ";")):
                return parse_csv(file_bytes, bank_hint)
        except UnicodeDecodeError:
            continue

    raise ValueError(
        "Unsupported file format. Please upload a CSV or PDF bank statement. "
        "Images, Excel (.xls/.xlsx), and encrypted PDFs are not supported."
    )
