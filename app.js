'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const express = require('express');

const PORT = process.env.PORT || 3000;
const INTERNAL_PORT = 9100;
const FLAG = process.env.FLAG || 'MOTFFA{flag_de_developpement_a_remplacer}';

// ---------------------------------------------------------------------------
// Cles de signature. bv-2024 est active, bv-2023 a ete retiree du service.
// Les deux sont publiees : c'est la rotation normale d'un JWKS.
// ---------------------------------------------------------------------------
const KEY_DIR = path.join(__dirname, 'keys');
const KEYS = {
  'bv-2024': {
    kid: 'bv-2024',
    actif: true,
    pem: fs.readFileSync(path.join(KEY_DIR, 'bv-2024.pem'), 'utf8'),
    priv: fs.readFileSync(path.join(KEY_DIR, 'bv-2024.key'), 'utf8')
  },
  'bv-2023': {
    kid: 'bv-2023',
    actif: false,
    pem: fs.readFileSync(path.join(KEY_DIR, 'bv-2023.pem'), 'utf8'),
    priv: fs.readFileSync(path.join(KEY_DIR, 'bv-2023.key'), 'utf8')
  }
};

const COMPTES = { client: 'Ch3ne33cm!' };

// Preferences du service : c'est l'objet que l'API interne fusionne.
const preferences = { devise: 'EUR', format: 'A4', tva: 20 };

// ------------------------------------------------------------------ Outils
const b64url = (buf) => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function signerRS256(payload, key) {
  const header = { alg: 'RS256', typ: 'JWT', kid: key.kid };
  const corps = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign('sha256', Buffer.from(corps), key.priv);
  return `${corps}.${b64url(sig)}`;
}

// ---------------------------------------------------------------------------
// Verification maison. Le kid choisit la cle, et l'algorithme est lu dans
// l'en-tete du jeton — sans etre contraint a celui de la cle.
// ---------------------------------------------------------------------------
function verifierJeton(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;

  let header;
  try {
    header = JSON.parse(unb64url(parts[0]).toString('utf8'));
  } catch (e) {
    return null;
  }

  const key = KEYS[header.kid];
  if (!key) return null;
  if (!key.actif) return { erreur: 'cle retiree du service' };

  const corps = `${parts[0]}.${parts[1]}`;
  const sig = unb64url(parts[2]);
  let ok = false;

  if (header.alg === 'RS256') {
    ok = crypto.verify('sha256', Buffer.from(corps), key.pem, sig);
  } else if (header.alg === 'HS256') {
    const attendu = crypto.createHmac('sha256', key.pem).update(corps).digest();
    ok = sig.length === attendu.length && crypto.timingSafeEqual(sig, attendu);
  } else {
    return { erreur: 'algorithme non supporte' };
  }

  if (!ok) return null;
  try {
    return { claims: JSON.parse(unb64url(parts[1]).toString('utf8')) };
  } catch (e) {
    return null;
  }
}

function lireCookies(req) {
  const out = {};
  for (const morceau of String(req.headers.cookie || '').split(';')) {
    const i = morceau.indexOf('=');
    if (i > 0) out[morceau.slice(0, i).trim()] = decodeURIComponent(morceau.slice(i + 1).trim());
  }
  return out;
}

function session(req, res, next) {
  const r = verifierJeton(lireCookies(req)['bv.jwt']);
  req.utilisateur = r && r.claims ? r.claims : null;
  req.jetonErreur = r && r.erreur ? r.erreur : null;
  next();
}

const page = (titre, corps) => `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(titre)} — Bois Vert Facturation</title>
<link rel="stylesheet" href="/style.css"></head><body>
<header class="bandeau"><a class="marque" href="/">Bois&nbsp;Vert</a>
<nav><a href="/">Accueil</a><a href="/espace">Espace</a><a href="/login">Connexion</a></nav></header>
<main class="page">${corps}</main>
<footer class="pied">Service facturation — Bois Vert, Hauts-de-France</footer>
</body></html>`;

// ===========================================================================
//  Application publique
// ===========================================================================
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session);

app.get('/', (req, res) => {
  res.type('html').send(page('Accueil', `
    <h1>Service de facturation</h1>
    <p>Espace réservé aux clients et au service comptabilité de Bois Vert.</p>
    <ul class="liste">
      <li>Consultation des factures : rôle <code>client</code></li>
      <li>Génération et export des factures : rôle <code>compta</code></li>
      <li>Documents internes : réservés à l'administration</li>
    </ul>
    <p class="note">Les jetons de session sont signés. Les clés publiques sont
    exposées sur <a href="/.well-known/jwks.json">/.well-known/jwks.json</a>.</p>`));
});

app.route('/login')
  .get((req, res) => res.type('html').send(page('Connexion', `
    <h1>Connexion</h1>
    <form method="post" action="/login" class="formulaire">
      <label for="u">Identifiant</label><input id="u" name="identifiant" required>
      <label for="p">Mot de passe</label><input id="p" name="motdepasse" type="password" required>
      <button type="submit">Se connecter</button>
    </form>`)))
  .post((req, res) => {
    const { identifiant, motdepasse } = req.body;
    if (COMPTES[identifiant] !== motdepasse) {
      return res.status(401).type('html').send(page('Connexion', '<h1>Connexion</h1><p class="erreur">Identifiants incorrects.</p>'));
    }
    const jeton = signerRS256({
      sub: identifiant,
      role: 'client',
      iat: Math.floor(Date.now() / 1000)
    }, KEYS['bv-2024']);
    res.setHeader('Set-Cookie', `bv.jwt=${jeton}; Path=/; HttpOnly; SameSite=Lax`);
    res.redirect('/espace');
  });

app.get('/espace', (req, res) => {
  if (!req.utilisateur) {
    return res.status(401).type('html').send(page('Espace', `<h1>Espace</h1>
      <p class="erreur">${esc(req.jetonErreur || 'session absente ou invalide')}</p>
      <p><a href="/login">Se connecter</a></p>`));
  }
  const u = req.utilisateur;
  const bloc = u.role === 'compta'
    ? `<p>Génération de factures : <code>/compta/facture?logo=&lt;url&gt;</code></p>
       <p>Aperçu d'une image externe : <code>/compta/apercu?url=&lt;url&gt;</code></p>`
    : '<p class="note">La génération de factures est réservée au service comptabilité.</p>';
  res.type('html').send(page('Espace', `
    <h1>Bonjour ${esc(u.sub)}</h1>
    <p>Rôle : <code>${esc(u.role)}</code></p>
    <ul class="liste"><li>Facture BV-2024-001 — 3 stères de chêne — 249,00 €</li>
    <li>Facture BV-2024-002 — 2 stères de charme — 152,00 €</li></ul>
    ${bloc}`));
});

// ------------------------------------------------------------------- JWKS
function jwk(key) {
  const k = crypto.createPublicKey(key.pem).export({ format: 'jwk' });
  return { kty: k.kty, n: k.n, e: k.e, alg: 'RS256', use: 'sig', kid: key.kid,
           statut: key.actif ? 'actif' : 'retire' };
}
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: Object.values(KEYS).map(jwk) });
});
// ------------------------------------------------------- Generation facture
// Le logo est recupere cote serveur. Le filtre compare la chaine de l'URL.
const INTERDITS = ['localhost', '127.0.0.1'];

app.get('/compta/facture', (req, res) => {
  if (!req.utilisateur || req.utilisateur.role !== 'compta') {
    return res.status(403).json({ error: 'role compta requis' });
  }
  const cible = String(req.query.logo || '');
  if (!cible) return res.status(400).json({ error: 'parametre logo manquant' });
  if (INTERDITS.some((mot) => cible.includes(mot))) {
    return res.status(400).json({ error: 'hote interdit' });
  }

  let u;
  try {
    u = new URL(cible);
  } catch (e) {
    return res.status(400).json({ error: 'url invalide' });
  }
  if (u.protocol !== 'http:') return res.status(400).json({ error: 'seul http est supporte' });

  const requete = http.get(cible, { timeout: 4000 }, (r) => {
    const morceaux = [];
    r.on('data', (d) => { if (morceaux.length < 64) morceaux.push(d); });
    r.on('end', () => {
      const corps = Buffer.concat(morceaux);
      const type = String(r.headers['content-type'] || '');
      if (type.startsWith('image/')) {
        return res.json({ ok: true, logo: { type, octets: corps.length } });
      }
      // Le contenu n'est pas une image : on renvoie un apercu pour le diagnostic.
      res.status(415).json({
        error: 'contenu non reconnu comme image',
        statut: r.statusCode,
        type: type || null,
        apercu: corps.toString('utf8').slice(0, 800)
      });
    });
  });
  requete.on('timeout', () => { requete.destroy(); });
  requete.on('error', (e) => res.status(502).json({ error: 'recuperation impossible', detail: e.code || e.message }));
});

// Leurre : meme idee, mais la validation resout l'hote et rejette le prive.
app.get('/compta/apercu', async (req, res) => {
  if (!req.utilisateur || req.utilisateur.role !== 'compta') {
    return res.status(403).json({ error: 'role compta requis' });
  }
  let u;
  try {
    u = new URL(String(req.query.url || ''));
  } catch (e) {
    return res.status(400).json({ error: 'url invalide' });
  }
  let adresses;
  try {
    adresses = net.isIP(u.hostname) ? [{ address: u.hostname }] : await dns.lookup(u.hostname, { all: true });
  } catch (e) {
    return res.status(502).json({ error: 'resolution impossible' });
  }
  for (const a of adresses) {
    const ip = a.address;
    if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.|::1|f[cd])/i.test(ip) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) {
      return res.status(400).json({
        error: 'adresse privee refusee',
        resolue: ip,
        note: 'cet endpoint resout l\'hote avant de sortir'
      });
    }
  }
  res.status(502).json({ error: 'aucune sortie reseau sur cet hebergement' });
});

// Leurre : sent le SSTI, ne compile rien.
const MODELES = ['facture', 'avoir', 'relance'];
app.get('/api/v1/pdf', (req, res) => {
  const m = String(req.query.template || '');
  if (!MODELES.includes(m)) return res.status(400).json({ error: 'modele inconnu', modeles: MODELES });
  res.status(501).json({ error: 'export PDF non implemente', note: 'aucun moteur de rendu n\'est branche' });
});

app.use((req, res) => res.status(404).type('html').send(page('Introuvable', '<h1>Page introuvable</h1>')));

// ===========================================================================
//  API interne — ecoute uniquement sur la boucle locale.
// ===========================================================================
const interne = express();
interne.use(express.json());

function fusion(cible, source) {
  for (const cle in source) {
    if (typeof source[cle] === 'object' && source[cle] !== null) {
      if (!cible[cle]) cible[cle] = {};
      fusion(cible[cle], source[cle]);
    } else {
      cible[cle] = source[cle];
    }
  }
  return cible;
}

interne.get('/internal/profil', (req, res) => {
  res.json({ service: 'facturation', preferences, endpoints: [
    'GET /internal/profil',
    'GET /internal/preferences?data=<json>',
    'GET /internal/documents/preuve'
  ] });
});

// API historique : les preferences arrivent en JSON dans la query string.
interne.get('/internal/preferences', (req, res) => {
  let recu = {};
  try {
    recu = JSON.parse(String(req.query.data || '{}'));
  } catch (e) {
    return res.status(400).json({ error: 'json invalide' });
  }
  fusion(preferences, recu);
  res.json({ ok: true, preferences });
});

interne.get('/internal/documents/preuve', (req, res) => {
  const contexte = {};                       // droits par defaut : aucun
  if (!contexte.isAdmin) {
    return res.status(403).json({ error: 'document reserve a l\'administration' });
  }
  res.type('text/plain').send(FLAG + '\n');
});

// Remise a zero periodique : l'etat pollue est global au processus.
setInterval(() => {
  for (const cle of ['isAdmin', 'role', 'sub', 'devise', 'format', 'tva']) {
    delete Object.prototype[cle];
  }
}, 10 * 60 * 1000).unref();

interne.listen(INTERNAL_PORT, '127.0.0.1', () => {
  console.log(`[interne] 127.0.0.1:${INTERNAL_PORT}`);
});
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[public] 0.0.0.0:${PORT}`);
});
