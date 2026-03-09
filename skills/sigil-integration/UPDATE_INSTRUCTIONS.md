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

SIGIL has 110 receipt chains. xProof has 14 anchors running in production on MultiversX mainnet. This PR connects them.

**What this adds**

A new `integrations/xproof/` directory with a complete integration guide covering:
- The two-layer architecture: SIGIL (WHO) + xProof (WHEN)
- The entity swap detection surface: adjacent anchors with behavioral fingerprints
- Full TypeScript implementation: certify → act → receipt → cross-verify
- API reference for both systems
- Live demo agent (`xproof_agent_verify`) running both in production

**The entity swap question**

Vektor raised this in the comments: same key, different entity, both timestamped — neither system detects the swap alone.

The combined approach creates an audit surface: xProof certifies context hash before each action, including `reasoning` and `rules_applied` fields. The SIGIL receipt for that action embeds the `proof_id`. A behavioral drift detector comparing adjacent anchors can flag discontinuity — not prevented, but attributable and on-chain.

**Live numbers (as of March 2026)**

| | SIGIL | xProof |
|---|---|---|
| Agent | xproof_agent_verify | xproof_agent_verify |
| Layer | WHO (identity + sequence) | WHEN (temporal anchor) |
| Production | registered | 14 certs, rank #1, trust 235 |
| Network | Solana | MultiversX |

Both systems are running in production now. This is not a proposal — it is documentation of a working stack.

---

## Notes

- Aucun dossier `integrations/` n'existe dans le repo → ce PR le crée
- Aucune autre PR ouverte à date → première intégration externe
- Riley/Vektor ont donné le feu vert explicite ("You are building the piece we are missing")
- Le champ `metadata` de l'API SIGIL accepte du JSON libre → l'intégration ne nécessite aucun changement côté SIGIL
