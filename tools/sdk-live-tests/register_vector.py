#!/usr/bin/env python3
"""Registers the account of an sdk-internal test vector on a vaultwarden server, as a client would.

Usage: register_vector.py <vector.json> <server-url>

A V1 vector is registered with the flat `keys` object, a V2 one with `accountKeys` and the user key
id. Prints the account's email and password on two lines, for the caller to log in with.

Exits with SKIP, and the reason on stderr, for a vector the live tests can't use.
"""

import json
import sys
import urllib.error
import urllib.request

SKIP = 3
MIN_PBKDF2_ITERATIONS = 100_000


def skip_reason(vector):
    if not any("masterPasswordUnlock" in m for m in vector["unlockMethods"]):
        return "it has no master password, which the live tests log in with"
    pbkdf2 = vector["account"]["kdf"].get("pBKDF2")
    if pbkdf2 is not None and pbkdf2["iterations"] < MIN_PBKDF2_ITERATIONS:
        return f"registration requires at least {MIN_PBKDF2_ITERATIONS} PBKDF2 iterations (upstream 600000)"
    return None


def kdf_of(account):
    kind, params = next(iter(account["kdf"].items()))
    if kind == "pBKDF2":
        return {"kdfType": 0, "iterations": params["iterations"]}
    return {
        "kdfType": 1,
        "iterations": params["iterations"],
        "memory": params["memory"],
        "parallelism": params["parallelism"],
    }


def register_body(vector):
    account = vector["account"]
    raw = vector["rawCryptographicState"]
    version, state = next(iter(account["accountCryptographicState"].items()))
    kdf = kdf_of(account)
    unlock = next(m["masterPasswordUnlock"] for m in vector["unlockMethods"] if "masterPasswordUnlock" in m)
    mp_unlock = unlock["master_password_unlock"]

    body = {
        "email": account["email"],
        "name": vector["name"],
        "masterPasswordHint": None,
        "masterPasswordAuthentication": {
            "kdf": kdf,
            "salt": mp_unlock["salt"],
            "masterPasswordAuthenticationHash": vector["masterPasswordAuthenticationHash"],
        },
        "masterPasswordUnlock": {
            "kdf": kdf,
            "salt": mp_unlock["salt"],
            "masterKeyWrappedUserKey": mp_unlock["masterKeyWrappedUserKey"],
        },
    }

    if version == "V2":
        body["masterPasswordUnlock"]["containedKeyId"] = raw["userKeyId"]
        body["accountKeys"] = {
            "userKeyEncryptedAccountPrivateKey": state["private_key"],
            "accountPublicKey": raw["publicKey"],
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": state["private_key"],
                "publicKey": raw["publicKey"],
                "signedPublicKey": state["signed_public_key"],
            },
            "signatureKeyPair": {
                "signatureAlgorithm": "ed25519",
                "wrappedSigningKey": state["signing_key"],
                "verifyingKey": raw["verifyingKey"],
            },
            "securityState": {
                "securityState": state["security_state"],
                "securityVersion": account["securityVersion"],
            },
        }
    else:
        body["keys"] = {"encryptedPrivateKey": state["private_key"], "publicKey": raw["publicKey"]}

    return body, unlock["password"]


def main():
    with open(sys.argv[1]) as f:
        vector = json.load(f)
    server = sys.argv[2].rstrip("/")

    reason = skip_reason(vector)
    if reason is not None:
        print(f"Skipped: {reason}", file=sys.stderr)
        sys.exit(SKIP)

    body, password = register_body(vector)
    request = urllib.request.Request(
        f"{server}/identity/accounts/register",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request):
            pass
    except urllib.error.HTTPError as e:
        sys.exit(f"Registering {body['email']} failed: {e.code} {e.read().decode()}")

    print(body["email"])
    print(password)


if __name__ == "__main__":
    main()
