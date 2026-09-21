# Bois Vert — Facturation

Challenge web **hard**, conçu pour tenir sur un plan gratuit Railway : un seul processus Node, moins de 80 Mo de RAM, aucune base, **aucune sortie réseau**, et **aucune exécution de commande**.

---

## Énoncé (à publier aux joueurs)

> Le service de facturation de Bois Vert a survécu à la saisie. Les enquêteurs ont récupéré un compte client, rien de plus. La pièce principale du dossier est dans les documents internes, et ce compte n'y donne pas accès.
>
> Accès : `client` / `Ch3ne33cm!`
>
> L'instance est partagée : son état est remis à zéro toutes les 10 minutes.
>
> Format : `MOTFFA{...}`

---

## Chaîne de résolution

### Maillon 1 — confusion d'algorithme sur le JWT

Le site signe ses sessions en RS256 et publie ses clés sur `/.well-known/jwks.json`, avec deux `kid` : `bv-2024` (actif) et `bv-2023` (retiré du service, réponse `401` si on l'utilise). Chaque entrée pointe vers le PEM correspondant, servi sur `/.well-known/keys/<kid>.pem`.

La vérification est maison et lit l'algorithme dans l'en-tête du jeton sans le contraindre à celui de la clé :

```js
if (header.alg === 'RS256')      ok = crypto.verify('sha256', corps, key.pem, sig);
else if (header.alg === 'HS256') ok = hmac(key.pem, corps) === sig;
```

Le joueur reforge donc son jeton en HS256 en utilisant **les octets exacts du PEM** comme secret HMAC, et passe de `role: client` à `role: compta`. Le PEM étant téléchargeable tel quel, il n'y a aucune ambiguïté sur les sauts de ligne — c'est volontaire : le piège est conceptuel, pas typographique.

### Maillon 2 — SSRF vers la boucle locale

Le rôle `compta` débloque `/compta/facture?logo=<url>`, qui récupère le logo côté serveur. Le filtre se contente de chercher deux chaînes dans l'URL :

```js
const INTERDITS = ['localhost', '127.0.0.1'];
if (INTERDITS.some((mot) => cible.includes(mot))) return res.status(400)...
```

Une API interne écoute sur `127.0.0.1:9100`, dans le même processus. Contournements qui fonctionnent, vérifiés : `127.1`, `0.0.0.0`, `2130706433`, `0x7f.1`. (`[::1]` échoue, l'API n'écoute qu'en IPv4 — c'est un faux positif utile, le joueur voit un `502` et non un `400`, donc il sait qu'il a franchi le filtre.)

Quand le contenu récupéré n'est pas une image, la réponse renvoie un aperçu de 800 caractères « pour le diagnostic » : c'est le canal de lecture qui rend la SSRF exploitable.

**Point important pour l'hébergement** : cette SSRF ne vise que l'intérieur du processus. Elle fonctionne même sans egress, et un joueur ne peut pas s'en servir pour scanner Internet depuis le compte d'hébergement.

### Maillon 3 — pollution de prototype vers contournement d'autorisation

L'API interne expose une route historique qui accepte du JSON dans la query string et le fusionne sans filtrer les clés :

```
GET /internal/preferences?data={"__proto__":{"isAdmin":true}}
```

Le document interne construit son contexte de droits à partir d'un objet vide :

```js
const contexte = {};
if (!contexte.isAdmin) return res.status(403)...
```

Après pollution, `contexte.isAdmin` est hérité d'`Object.prototype` et vaut `true`. `GET /internal/documents/preuve` rend alors le flag, lu depuis la variable d'environnement `FLAG`.

---

## Les leurres

| Leurre | Réflexe visé | Signal de fermeture |
|---|---|---|
| `/compta/apercu?url=` | la « vraie » SSRF, trouvée en premier dans l'espace compta | résout l'hôte avant de sortir et renvoie `adresse privee refusee` avec l'IP résolue |
| `/api/v1/pdf?template=` | sent le SSTI | `501`, aucun moteur de rendu branché |
| `kid: bv-2023` dans le JWKS | forger avec la mauvaise clé | `401 cle retiree du service` |

Pas de faux flag.

---

## Déploiement sur Railway

```bash
npm i -g @railway/cli
railway login
railway init
railway variables set FLAG='MOTFFA{...}'
railway up
```

Railway détecte le `Dockerfile` et injecte `PORT`, que l'application lit. Le port interne 9100 n'est jamais exposé publiquement : il n'écoute que sur la boucle locale.

**À vérifier avant d'ouvrir l'épreuve** : le nombre de réplicas doit rester à **1**. La pollution de prototype est un état en mémoire dans le processus ; avec deux instances, un joueur pollue l'une et lit le document sur l'autre, et le challenge devient aléatoire. Le plan gratuit est déjà limité à un réplica, mais la vérification coûte dix secondes.

Consommation observée : environ 60 Mo de RAM au repos, largement sous les 512 Mo du plan gratuit, et le coût d'une soirée de quelques heures reste de l'ordre de quelques centimes en facturation à la seconde.

Le processus supprime lui-même les clés polluées toutes les 10 minutes — pas de cron, pas d'accès root nécessaire. Annoncez-le dans l'énoncé pour éviter les incompréhensions entre joueurs.

---

## Vérification

```bash
pip install requests
python3 solve.py https://<votre-app>.up.railway.app
```

Sortie attendue :

```
[+] connecte en tant que client
[+] cle active : bv-2024 (l'autre est retiree du service)
[+] cle publique recuperee (451 octets)
[+] role compta obtenu
[+] API interne : {"service":"facturation", ...
[+] pollution : {"ok":true, ...
[+] FLAG : MOTFFA{...}
```

---

## Échelle d'indices

1. *La vérification du jeton ne contraint pas l'algorithme à celui de la clé.*
2. *Le filtre d'URL compare des chaînes de caractères, pas des adresses.*
3. *L'API interne fusionne vos préférences sans filtrer les clés, et le contrôle de droits part d'un objet vide.*

---

## À changer avant publication

Les clés RSA du dossier `keys/` sont fournies pour que le dépôt tourne tel quel. Régénérez-les :

```bash
cd keys
openssl genrsa -out bv-2024.key 2048 && openssl rsa -in bv-2024.key -pubout -out bv-2024.pem
openssl genrsa -out bv-2023.key 2048 && openssl rsa -in bv-2023.key -pubout -out bv-2023.pem
```

Changez aussi le mot de passe du compte `client` dans `COMPTES`, et définissez `FLAG` en variable d'environnement plutôt que dans le code.

---

## Notes de conception

Le point de blocage attendu est le maillon 1 : beaucoup de joueurs connaissent la confusion d'algorithme en théorie mais ne pensent pas à récupérer le PEM exact. Le maillon 2 se trouve vite une fois le rôle obtenu, parce que le message d'erreur affiche la liste des chaînes interdites — c'est un cadeau délibéré, la difficulté est ailleurs.

Pour durcir : retirez le champ `pem` du JWKS et forcez la reconstruction du PEM depuis `n` et `e` (attention, le moindre écart d'encodage rend alors le challenge injuste). Pour adoucir : ajoutez un en-tête `X-Auth-Impl: custom-jwt-v2` qui signale que la vérification n'est pas celle d'une bibliothèque.
