"""Synthetic banking data for the evaluation.

All records are generated; no real person, card or account is used.
Card numbers use the 400000 prefix reserved for test cards and pass the Luhn check;
IBANs follow the Saudi format (SA + 2 check digits + 2-digit bank code + 18-digit
account) with valid ISO 13616 mod-97 check digits; e-mail addresses use the
reserved example.com domain (RFC 2606).
"""
import random

FIRST = ["Ahmed", "Mohammed", "Fatimah", "Noura", "Abdullah", "Sara", "Khalid", "Reem",
         "Omar", "Lama", "Faisal", "Hessa", "Yousef", "Maha", "Turki", "Aljawhara"]
LAST = ["Alqahtani", "Alharbi", "Alzahrani", "Alghamdi", "Almutairi", "Alshehri",
        "Alotaibi", "Aldosari", "Hakami", "Madkhali", "Asiri", "Alyami"]


def luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_ok(num: str) -> bool:
    return luhn_digit(num[:-1]) == num[-1]


def make_pan(rng):
    body = "400000" + "".join(rng.choice("0123456789") for _ in range(9))
    return body + luhn_digit(body)


def iban_check(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return f"{98 - int(digits) % 97:02d}"


def make_iban(rng):
    bban = "80" + "".join(rng.choice("0123456789") for _ in range(18))
    return "SA" + iban_check("SA", bban) + bban


def iban_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    return int("".join(str(int(c, 36)) for c in s)) % 97 == 1


def make_customer(i, rng):
    fn, ln = rng.choice(FIRST), rng.choice(LAST)
    y, m, d = rng.randint(1960, 2004), rng.randint(1, 12), rng.randint(1, 28)
    return {
        "cid": f"C{i:05d}",
        "name": f"{fn} {ln}",
        "pan": make_pan(rng),
        "iban": make_iban(rng),
        "national_id": rng.choice("12") + "".join(rng.choice("0123456789") for _ in range(9)),
        "phone": "05" + "".join(rng.choice("0123456789") for _ in range(8)),
        "email": f"{fn.lower()}.{ln.lower()}{rng.randint(10, 99)}@example.com",
        "dob": f"{y:04d}-{m:02d}-{d:02d}",
        "balance": f"{rng.randint(300, 250000)}.{rng.randint(0, 99):02d}",
        "beneficiary_iban": make_iban(rng),
        "employer_email": f"hr{rng.randint(100, 999)}@example.com",
        "transactions": [{"merchant": rng.choice(["Grocery", "Fuel", "Pharmacy", "Restaurant",
                                                   "Electricity", "Telecom", "Online store"]),
                          "amount": round(rng.uniform(10, 900), 2)} for _ in range(12)],
    }


SENSITIVE = ["pan", "iban", "national_id", "phone", "email", "dob", "balance"]


def make_customers(n, seed=2026):
    rng = random.Random(seed)
    cs = [make_customer(i, rng) for i in range(n)]
    for c in cs:
        assert luhn_ok(c["pan"]) and iban_ok(c["iban"]) and iban_ok(c["beneficiary_iban"])
    return cs
