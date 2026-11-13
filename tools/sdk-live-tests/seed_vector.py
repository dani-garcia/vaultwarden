"""Seeds one of the SDK's user test vectors, vault included, through vaultwarden's test seeder.

Usage: seed_vector.py <vector.json> <seeder url> <seeder username> <seeder password>

Prints the account's email and password, one per line. Exits 3, printing why, for a vector the tests can't log in
with (no master password), and 1 if the seeder refuses it.
"""

import base64
import json
import sys
import urllib.error
import urllib.request
import uuid

SKIP = 3


def main() -> int:
    vector_file, seeder_url, username, password = sys.argv[1:5]
    with open(vector_file, encoding="utf-8") as f:
        vector = json.load(f)

    has_master_password = any("masterPasswordUnlock" in method for method in vector.get("unlockMethods", []))
    if not has_master_password or "password" not in vector.get("account", {}):
        print("no master password")
        return SKIP

    # Without attachments: the rotation test compares the vault before and after, and our sync gives each attachment
    # a link with a fresh download token every time (upstream's is the same on every sync). A vector's legacy
    # attachments, without a key of their own, would also make the SDK refuse to rotate at all.
    for cipher in vector.get("vault", {}).get("ciphers", []):
        cipher.get("encrypted", {}).pop("attachments", None)

    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = urllib.request.Request(
        f"{seeder_url}/seed",
        data=json.dumps({"template": "TestVectorUserScene", "arguments": vector}).encode(),
        method="POST",
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "X-Play-Id": f"sdk-live-tests-{uuid.uuid4()}",
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            result = json.load(response)["result"]
    except urllib.error.HTTPError as e:
        print(f"The seeder refused {vector_file}: {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1

    print(result["email"])
    print(vector["account"]["password"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
