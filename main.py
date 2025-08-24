import argparse
import time
from Crypto.Util.number import bytes_to_long
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
import math
import itertools
import base64
import typing

import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, ValidationError, field_validator, Field


class JWK(BaseModel):
    kty: str
    kid: str = ""
    alg: str = ""
    use: str = ""
    n: str
    e: str
    x5c: list[str] = Field(default_factory=list)
    x5t: str = ""
    x5t_S256: str = Field(alias="x5t#S256", default="")

    @field_validator("kty")
    def must_be_rsa(cls, v):
        if v.lower() != "rsa":
            raise ValueError("Only RSA keys are supported")
        return v


def fetch_and_validate_jwks(url: str) -> List[Dict[str, Any]]:
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    if (
        not isinstance(data, dict)
        or "keys" not in data
        or not isinstance(data["keys"], list)
    ):
        raise ValueError("Response must be a dict with a 'keys' list")
    validated = []
    for jwk_dict in data["keys"]:
        try:
            key = JWK(**jwk_dict)
        except ValidationError as e:
            print(f"✖ Validation error: {e}, skipping...\n")
            continue
        validated.append(key.model_dump())
    return validated


KEYS_FILE = Path("keys.json")


def load_store() -> Dict[str, List[Dict[str, Any]]]:
    if not KEYS_FILE.exists():
        sys.exit("✖ keys.json not found or is not a file.")
    try:
        content = json.loads(KEYS_FILE.read_text())
        if not isinstance(content, dict):
            raise ValueError
        return content
    except Exception:
        sys.exit("✖ keys.json is invalid or not a dict.")


def save_store(store: Dict[str, List[Dict[str, Any]]]) -> None:
    KEYS_FILE.write_text(json.dumps(store, indent=2))


def cmd_add(url: str) -> None:
    jwks = fetch_and_validate_jwks(url)
    store = load_store()
    existing = store.get(url, [])
    seen = {(k["kid"], k["n"], k["e"]) for k in existing}
    new = [k for k in jwks if (k["kid"], k["n"], k["e"]) not in seen]
    if new:
        store.setdefault(url, []).extend(new)
        save_store(store)
        print(f"✔ Added {len(new)} new key(s) under {url}")
    else:
        print("ℹ No new keys to add.")


def cmd_refresh() -> None:
    store = load_store()
    updated = 0
    for url in list(store.keys()):
        try:
            jwks = fetch_and_validate_jwks(url)
        except Exception as e:
            print(f"⚠ Failed fetching {url}: {e}")
            continue
        existing = store[url]
        seen = {(k["kid"], k["n"], k["e"]) for k in existing}
        new = [k for k in jwks if (k["kid"], k["n"], k["e"]) not in seen]
        if new:
            store[url].extend(new)
            updated += len(new)
            print(f"➕ {len(new)} new key(s) from {url}")
    if updated:
        save_store(store)
        print(f"✔ Refreshed and added {updated} total new key(s).")
    else:
        print("ℹ No new keys found on refresh.")


def decode_modulus(n_b64: str) -> int:
    padding = "=" * (-len(n_b64) % 4)
    b = base64.urlsafe_b64decode(n_b64 + padding)
    return bytes_to_long(b)


def cmd_factorize() -> None:
    store = load_store()
    # Gather all (url, kid, int_n)
    items: List[Tuple[str, str, int]] = []
    for url, keys in store.items():
        for k in keys:
            int_n = decode_modulus(k["n"])
            items.append((url, k["kid"], int_n))

    # Check all combinations for gcd > 1
    found = False
    for (u1, kid1, n1), (u2, kid2, n2) in itertools.combinations(items, 2):
        g = math.gcd(n1, n2)
        if g not in (1, n1, n2):
            found = True
            print(f"🔓 Common factor found!")
            print(f" - URL1: {u1}, kid1: {kid1}")
            print(f" - URL2: {u2}, kid2: {kid2}")
            print(f" - gcd: {g}\n")
    if not found:
        print("ℹ No common factors found among stored moduli.")


def cmd_factor_db():
    store = load_store()
    for url, keys in store.items():
        for k in keys:
            n_int = decode_modulus(k["n"])
            time.sleep(2)
            resp = requests.get(f"https://factordb.com/index.php?query={n_int}")
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            # Locate the first <table> after "Result:"
            table = soup.find("b", string="Result:").find_parent("table")
            rows = table.find_all("tr")
            # Extract status from first data row
            status_cell = rows[2].find_all("td")[0]
            status = status_cell.get_text(strip=True)
            # Extract the right side of the equality row
            number_cell = rows[2].find_all("td")[2]
            parts = number_cell.get_text(separator=" ", strip=True).split("=")
            lhs = parts[0].strip()
            rhs = parts[1].strip()
            if "*" in status:
                print(
                    f"➕ New number added to factordb ! (from {url} | kid={k['kid']}\n"
                )
                status = status.split("*")[0]
            if status in ("FF", "CF"):
                # factors known
                factors = rhs.split("·")
                print(f"✅ {url} | kid={k['kid']}")
                print(f"  n = {lhs}")
                print(f"  factors = {factors}\n")
            else:
                # composite unknown
                print(f"❓ {url} | kid={k['kid']}")
                print(f"  n = {lhs}")
                print("  factors not known\n")


def main():
    parser = argparse.ArgumentParser(description="Manage JWKS sets in keys.json")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--add", metavar="URL", help="Fetch & add JWKs from URL")
    group.add_argument(
        "-r", "--refresh", action="store_true", help="Refresh all stored JWKS"
    )
    group.add_argument(
        "-f", "--factorize", action="store_true", help="Factorize RSA moduli via GCD"
    )
    group.add_argument(
        "-d", "--factor-db", action="store_true", help="Query FactorDB for each modulus"
    )
    args = parser.parse_args()

    try:
        if args.add:
            cmd_add(args.add)
        elif args.refresh:
            cmd_refresh()
        elif args.factorize:
            cmd_factorize()
        elif args.factor_db:
            cmd_factor_db()
    except ValidationError as ve:
        sys.exit(f"✖ Validation error: {ve}")
    except requests.HTTPError as he:
        sys.exit(f"✖ HTTP error: {he}")
    except Exception as e:
        sys.exit(f"✖ Error: {e}")


if __name__ == "__main__":
    main()
