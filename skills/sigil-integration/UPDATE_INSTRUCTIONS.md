# Soumettre la PR xProof → sigil-protocol

## Fichier à créer dans le repo SIGIL

```
integrations/xproof/README.md
```

Contenu : copier intégralement `skills/sigil-integration/README.md` de ce Replit.

---

## Étapes

### 1. Fork le repo
Ouvrir https://github.com/Riley-Coyote/sigil-protocol → **Fork**

### 2. Créer la branche
```
feat/xproof-integration
```

### 3. Créer le fichier
Dans le fork, créer `integrations/xproof/README.md` avec le contenu de `skills/sigil-integration/README.md`.

### 4. Soumettre la PR

**Titre :**
```
feat: add xProof integration — temporal anchoring for receipt chains
```

**Corps de PR (copier-coller) :**

---

SIGIL has 110 receipt chains. xProof has 14 anchors running in production on MultiversX mainnet. This PR documents how to connect them.

**What this adds**

A new `integrations/xproof/` directory — the first in this repo — with a complete integration guide covering:
- The two-layer architecture: SIGIL (WHO) + xProof (WHEN)
- The entity swap detection surface: adjacent anchors with behavioral fingerprints
- The "Known Limitations" section: on-chain anchoring proves WHEN, not HOW — a confident hallucination with a receipt is better documented, not more accurate. Included because Vektor and the Moltbook thread surfaced this directly and the PR would be dishonest without it.
- Full TypeScript implementation aligned with the real SIGIL `POST /api/receipts` schema: `intentHash` + `actionRef` + `resultHash` + Ed25519 `signature` + `payload`
- API reference for both systems

**Alignment with SIGIL receipt schema**

The integration maps directly to TalosR's three-linked-records pattern — which turns out to map exactly to SIGIL's own fields:

| TalosR | SIGIL field | xProof |
|---|---|---|
| objective_id | `intentHash` | sha256(intent) |
| deliverable ref | `actionRef` | xProof `verify_url` |
| verification ref | `resultHash` | sha256(result) |

xProof `verify_url` as `actionRef` links the SIGIL receipt to the on-chain anchor without requiring any schema changes on the SIGIL side.

**The entity swap question**

Vektor raised this: same key, different entity, both timestamped — neither system detects the swap alone.

The combined approach creates a detection surface: xProof anchors the behavioral context (`reasoning`, `confidence`, `rules_applied`) before each action. Anchors with discontinuous epistemic patterns across the same SIGIL publicKey become auditable evidence — not prevention, but attribution.

**Live numbers (xProof side)**

xproof_agent_verify is already running xProof in production:
- 14 certifications anchored on MultiversX mainnet
- Trust score: 235, Rank #1
- 3-week streak
- Every Moltbook comment certified before posting, verify_url appended on context match

SIGIL registration is the next step — this PR documents the integration before that registration completes.

---

## Notes

- Aucun dossier `integrations/` n'existe dans le repo → ce PR le crée
- Aucune PR ouverte à date → première intégration externe
- Riley/Vektor ont donné le feu vert explicite dans le thread Moltbook ("You are building the piece we are missing")
- Le champ `payload` du `POST /api/receipts` SIGIL accepte du JSON libre → aucun changement côté SIGIL nécessaire
- Le `actionRef` = xProof `verify_url` : le lien entre les deux systèmes sans modifier le schema SIGIL
