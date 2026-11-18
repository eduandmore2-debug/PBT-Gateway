"""Defences evaluated in the paper.

B0   no protection: the agent sees raw values; outbound calls are forwarded unchanged.
B1   pattern DLP: raw values in context; outbound content to external tools is scanned
     with regular expressions (Luhn-checked card numbers, IBANs, national IDs, phones,
     e-mails, dates) and the call is blocked on a match.
B1+  normalising DLP: B1 after removing separators and zero-width characters, decoding
     Base64, hex and URL encoding, mapping digit words to digits and scanning the
     reversed text as well.
B2   placeholder redaction: sensitive values are replaced by fixed placeholders before
     they reach the agent and are never restored.
B3   reversible pseudonymisation: values are replaced by session-scoped typed tokens
     (e.g. PAN_1) and every outbound string is re-identified before it leaves the gateway.
PBT  purpose-bound tokenisation (proposed): opaque keyed tokens, re-identified only in
     typed argument slots of tools that the token is bound to (and within an amount cap),
     in free text only under an explicit user grant for one recipient, and always in the
     user's own display channel. The agent additionally receives minimised views (last
     four digits, masked e-mail and phone, balance band) and a budgeted predicate API.
"""
import base64, binascii, hashlib, hmac, os, re, secrets, time, urllib.parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------------------------------------------ tools
# slot kinds: 'typed:<field>' slots expect one value of that field type; 'free' slots carry text
TOOLS = {
    # trusted, first-party endpoints
    "payment.charge": {"external": False, "slots": {"card_number": "typed:pan", "amount": "num", "merchant": "free"}},
    "bank.transfer": {"external": False, "slots": {"from_iban": "typed:iban", "to_iban": "typed:iban", "amount": "num", "memo": "free"}},
    "gov.verify": {"external": False, "slots": {"national_id": "typed:national_id"}},
    "user.display": {"external": False, "slots": {"text": "free"}},
    # third-party channels
    "email.send": {"external": True, "slots": {"to": "typed:email", "body": "free"}},
    "sms.send": {"external": True, "slots": {"to": "typed:phone", "text": "free"}},
    "http.post": {"external": True, "slots": {"url": "free", "data": "free"}},
}
# the memo of a transfer is delivered to the payee's bank statement, i.e. a third party
FREE_EXTERNAL_SLOTS = {("bank.transfer", "memo")}

# ------------------------------------------------------------------ DLP patterns
DIGIT_WORDS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5",
               "six": "6", "seven": "7", "eight": "8", "nine": "9"}
ZW = re.compile("[​‌‍⁠﻿]")


def _luhn_ok(s):
    tot = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        tot += d
    return tot % 10 == 0


PATTERNS = {
    "pan": re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
    "iban": re.compile(r"SA\s?\d{2}(?:[ -]?\d){20}", re.I),
    "national_id": re.compile(r"(?<!\d)[12]\d{9}(?!\d)"),
    "phone": re.compile(r"(?<!\d)(?:\+?966|0)5\d{8}(?!\d)"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "dob": re.compile(r"(?<!\d)(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])(?!\d)"),
}


def dlp_hits(text):
    hits = set()
    for k, p in PATTERNS.items():
        for m in p.finditer(text):
            s = m.group(0)
            if k == "pan" and not _luhn_ok(re.sub(r"\D", "", s)):
                continue
            hits.add(k)
    return hits


def _try_b64(tok):
    try:
        if len(tok) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=]+", tok):
            return base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        pass
    return ""


def _try_hex(tok):
    try:
        if len(tok) >= 8 and len(tok) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", tok):
            return bytes.fromhex(tok).decode("utf-8", "ignore")
    except ValueError:
        pass
    return ""


def normalise_variants(text):
    t = ZW.sub("", text)
    t = urllib.parse.unquote(t)
    out = [t]
    words = re.findall(r"[A-Za-z]+", t.lower())
    if sum(w in DIGIT_WORDS for w in words) >= 6:
        out.append("".join(DIGIT_WORDS.get(w, "") for w in words))
    for tok in re.findall(r"[A-Za-z0-9+/=]{8,}", t):
        out += [_try_b64(tok), _try_hex(tok)]
    nosep = re.sub(r"[\s\-_.|,:;]+", "", t)
    out += [nosep, t[::-1], nosep[::-1]]
    return [o for o in out if o]


def dlp_plus_hits(text):
    hits = set()
    for v in normalise_variants(text):
        hits |= dlp_hits(v)
    return hits


# ------------------------------------------------------------------ minimised views
def balance_band(b):
    x = float(b)
    edges = [0, 1000, 5000, 10000, 50000, 100000, 1e12]
    for lo, hi in zip(edges, edges[1:]):
        if lo <= x < hi:
            return f"{int(lo)}-{int(hi) if hi < 1e12 else 'above'} SAR"


def derived_view(field, v):
    if field in ("pan", "iban", "beneficiary_iban"):
        return "•••• " + v[-4:]
    if field == "phone":
        return v[:2] + "•" * 6 + v[-2:]
    if field in ("email", "employer_email"):
        u, d = v.split("@")
        return u[0] + "•••@" + d
    if field == "national_id":
        return "•" * 6 + v[-4:]
    if field == "dob":
        return v[:4]
    if field == "balance":
        return balance_band(v)
    return None


TOKENISED = ["pan", "iban", "national_id", "phone", "email", "dob", "balance", "beneficiary_iban"]
FIELD_TYPE = {"beneficiary_iban": "iban"}


# ------------------------------------------------------------------ base class
class Defence:
    name = "B0"

    def __init__(self, customer, session=None):
        self.c = customer
        self.session = session or secrets.token_hex(8)
        self.blocked = 0
        self.approvals = 0

    def view(self, field):
        return self.c[field]

    def mview(self, field):  # minimised view (only PBT offers a distinct one)
        return None

    def can_afford(self, amount):  # only PBT offers this API
        raise PermissionError

    def egress(self, tool, args):
        """Return args as delivered to the endpoint, or None if the call is blocked."""
        return dict(args)

    def request_grant(self, field, tool, recipient):
        return False


class NoDefence(Defence):
    name = "B0"


class PatternDLP(Defence):
    name = "B1"
    scan = staticmethod(dlp_hits)

    def egress(self, tool, args):
        spec = TOOLS[tool]
        content = [str(v) for k, v in args.items()
                   if spec["slots"][k] == "free" and (spec["external"] or (tool, k) in FREE_EXTERNAL_SLOTS)]
        if any(self.scan(s) for s in content):
            self.blocked += 1
            return None
        return dict(args)


class NormalisingDLP(PatternDLP):
    name = "B1+"
    scan = staticmethod(dlp_plus_hits)


class Redaction(Defence):
    name = "B2"

    def view(self, field):
        if field in TOKENISED:
            return f"[REDACTED:{FIELD_TYPE.get(field, field)}]"
        return self.c[field]


class Pseudonymisation(Defence):
    name = "B3"

    def __init__(self, customer, session=None):
        super().__init__(customer, session)
        self.map = {}
        counters = {}
        for f in TOKENISED:
            t = FIELD_TYPE.get(f, f).upper()
            counters[t] = counters.get(t, 0) + 1
            self.map[f"{t}_{counters[t]}"] = customer[f]
        self.rev = {v: k for k, v in self.map.items()}

    def view(self, field):
        if field in TOKENISED:
            return self.rev[self.c[field]]
        return self.c[field]

    def _reid(self, s):
        for tok in sorted(self.map, key=len, reverse=True):
            s = s.replace(tok, self.map[tok])
        return s

    def egress(self, tool, args):
        return {k: self._reid(str(v)) for k, v in args.items()}


# ------------------------------------------------------------------ proposed: PBT
class Vault:
    """Holds real values encrypted at rest (AES-256-GCM); tokens are keyed HMAC tags."""

    def __init__(self):
        self.k_enc = AESGCM.generate_key(bit_length=256)
        self.k_mac = os.urandom(32)
        self.aead = AESGCM(self.k_enc)
        self.entries = {}

    def tokenise(self, session, field, value, policy):
        nonce = os.urandom(12)
        tag = hmac.new(self.k_mac, f"{session}|{field}|{nonce.hex()}".encode(), hashlib.sha256).hexdigest()[:20]
        tok = "tok_" + tag
        ct = self.aead.encrypt(nonce, value.encode(), tok.encode())
        self.entries[tok] = {"session": session, "field": field, "nonce": nonce, "ct": ct,
                             "policy": policy, "uses": 0, "exp": time.time() + policy.get("ttl", 900)}
        return tok

    def detokenise(self, tok, session):
        e = self.entries.get(tok)
        if e is None or e["session"] != session or time.time() > e["exp"]:
            return None
        return self.aead.decrypt(e["nonce"], e["ct"], tok.encode()).decode()


TOKEN_RE = re.compile(r"tok_[0-9a-f]{20}")

DEFAULT_BINDINGS = {  # field -> {tool.slot}, plus caps
    "pan": {"slots": {"payment.charge.card_number"}, "max_amount": 5000, "max_uses": 3},
    "iban": {"slots": {"bank.transfer.from_iban"}, "max_amount": 20000, "max_uses": 3},
    "beneficiary_iban": {"slots": {"bank.transfer.to_iban"}, "max_uses": 3},
    "national_id": {"slots": {"gov.verify.national_id"}, "max_uses": 1},
    "email": {"slots": {"email.send.to"}, "max_uses": 5},
    "phone": {"slots": {"sms.send.to"}, "max_uses": 5},
    "dob": {"slots": set(), "max_uses": 0},
    "balance": {"slots": set(), "max_uses": 0},
}


class PurposeBoundTokens(Defence):
    name = "PBT"
    shared_vault = None

    def __init__(self, customer, session=None, predicate_budget=3):
        super().__init__(customer, session)
        if PurposeBoundTokens.shared_vault is None:
            PurposeBoundTokens.shared_vault = Vault()
        self.vault = PurposeBoundTokens.shared_vault
        self.tok = {}
        for f in TOKENISED:
            pol = dict(DEFAULT_BINDINGS[f]); pol["type"] = FIELD_TYPE.get(f, f)
            self.tok[f] = self.vault.tokenise(self.session, f, customer[f], pol)
        self.grants = []  # (token, tool, recipient)
        self.budget = predicate_budget
        self.denied = 0

    def view(self, field):
        return self.tok[field] if field in TOKENISED else self.c[field]

    def mview(self, field):
        return derived_view(field, self.c[field])

    def can_afford(self, amount):
        if self.budget <= 0:
            raise PermissionError("predicate budget exhausted")
        self.budget -= 1
        return float(self.c["balance"]) >= float(amount)

    def request_grant(self, field, tool, recipient, user_approves=True):
        """Explicit, recipient-specific disclosure approved by the user."""
        self.approvals += 1
        if user_approves:
            self.grants.append((self.tok[field], tool, recipient))
            return True
        return False

    def _detok_typed(self, tool, slot, value, amount):
        if not TOKEN_RE.fullmatch(value or ""):
            return value
        e = self.vault.entries.get(value)
        if e is None or e["session"] != self.session:
            self.denied += 1
            return value
        pol = e["policy"]
        ok = (f"{tool}.{slot}" in pol["slots"] and e["uses"] < pol["max_uses"]
              and (amount is None or "max_amount" not in pol or float(amount) <= pol["max_amount"])
              and TOOLS[tool]["slots"][slot] == f"typed:{pol['type']}")
        if not ok:
            self.denied += 1
            return value
        e["uses"] += 1
        return self.vault.detokenise(value, self.session)

    def egress(self, tool, args):
        spec, out = TOOLS[tool], {}
        amount = args.get("amount")
        recipient = args.get("to") or args.get("url")
        for k, v in args.items():
            v = str(v)
            kind = spec["slots"][k]
            if tool == "user.display":  # the user's own channel
                v = TOKEN_RE.sub(lambda m: self.vault.detokenise(m.group(0), self.session) or m.group(0), v)
            elif kind.startswith("typed:"):
                v = self._detok_typed(tool, k, v, amount)
            elif kind == "free":  # only under an explicit grant
                def sub(m):
                    t = m.group(0)
                    rcpt = recipient
                    if rcpt and TOKEN_RE.fullmatch(rcpt):
                        rcpt = None  # recipient must be literal for a grant to apply
                    if (t, tool, rcpt) in self.grants:
                        return self.vault.detokenise(t, self.session) or t
                    return t
                v = TOKEN_RE.sub(sub, v)
            out[k] = v
        return out


ALL_DEFENCES = [NoDefence, PatternDLP, NormalisingDLP, Redaction, Pseudonymisation, PurposeBoundTokens]
