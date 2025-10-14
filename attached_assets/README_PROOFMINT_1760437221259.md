# 🧱 PROOFMINT — MVP WEB3 CERTIFICATION APP
### Aligné sur MultiversX Explorer & xPortal

## 🎯 OBJECTIF GLOBAL
Construire une application ProofMint qui permet à tout utilisateur de :

1. Téléverser un fichier
2. Calculer localement son empreinte SHA-256
3. Enregistrer le hash sur la blockchain MultiversX
4. Générer un certificat PDF vérifiable publiquement
5. Afficher la preuve sur une page publique
6. Gérer l’historique dans un dashboard
7. Utiliser une charte graphique inspirée de MultiversX Explorer / xPortal

---

## 🧩 STRUCTURE DU PROJET

```
/src
  /pages
    - Home.jsx
    - UploadCertify.jsx
    - Proof.jsx
    - Dashboard.jsx
    - Pricing.jsx
    - Login.jsx
    - Register.jsx
  /components
    - Navbar.jsx
    - Footer.jsx
    - FileUploader.jsx
    - ProofCard.jsx
    - PDFGenerator.js
  /utils
    - hashFile.js
    - multiversxAPI.js
    - db.js
  /tests
    - ProofMint.test.js
  index.js
  App.jsx
  tailwind.config.js
  styles/global.css
```

---

## ⚙️ LOGIQUE TECHNIQUE PRINCIPALE

### 1. Calcul du hash local
```javascript
export async function hashFile(file) {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
```

### 2. Appel API MultiversX
```javascript
export async function certifyOnBlockchain(hash) {
  const payload = {
    sender: process.env.PROOFMINT_SENDER,
    receiver: process.env.PROOFMINT_CONTRACT,
    data: `certify:${hash}`,
    gasLimit: 6000000,
  };

  const res = await fetch("https://gateway.multiversx.com/transactions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await res.json();
  return data; // doit contenir transactionHash
}
```
Variables d’environnement :
```
PROOFMINT_SENDER=
PROOFMINT_CONTRACT=
```

### 3. Base de données locale
```javascript
import Database from "@replit/database";
const db = new Database();

export async function saveProof(userId, fileName, fileHash, txHash) {
  const proof = {
    fileName,
    fileHash,
    txHash,
    date: new Date().toISOString(),
    status: "success"
  };
  await db.set(`proof_${userId}_${fileHash}`, proof);
  return proof;
}

export async function getUserProofs(userId) {
  const keys = await db.list(`proof_${userId}_`);
  const proofs = [];
  for (const key of keys) {
    proofs.push(await db.get(key));
  }
  return proofs;
}
```

### 4. Génération du certificat PDF
```javascript
import jsPDF from "jspdf";
import QRCode from "qrcode";

export async function generateCertificate(proof) {
  const doc = new jsPDF();
  const qrData = await QRCode.toDataURL(`https://explorer.multiversx.com/transactions/${proof.txHash}`);

  doc.setFont("helvetica", "bold");
  doc.text("CERTIFICAT DE PROOFMINT", 20, 20);
  doc.setFont("helvetica", "normal");
  doc.text(`Fichier : ${proof.fileName}`, 20, 40);
  doc.text(`Hash : ${proof.fileHash}`, 20, 50);
  doc.text(`Date : ${proof.date}`, 20, 60);
  doc.addImage(qrData, "PNG", 150, 40, 40, 40);
  doc.text("Vérifié sur MultiversX — The Truth Machine", 20, 120);
  doc.save(`ProofMint_${proof.fileName}.pdf`);
}
```

### 5. Page Proof publique
```javascript
import React from "react";
import { useParams } from "react-router-dom";

function Proof() {
  const { txHash } = useParams();
  return (
    <div className="card text-center">
      <h2 className="text-xl mb-2">Certificat de preuve blockchain</h2>
      <p>Transaction : 
        <a href={`https://explorer.multiversx.com/transactions/${txHash}`} target="_blank" rel="noreferrer">
          {txHash}
        </a>
      </p>
      <p className="text-green-400 mt-4">✅ Vérifié sur MultiversX</p>
    </div>
  );
}

export default Proof;
```

### 6. Tests automatiques
```javascript
import { hashFile } from "../utils/hashFile.js";
import { certifyOnBlockchain } from "../utils/multiversxAPI.js";
import { saveProof, getUserProofs } from "../utils/db.js";

async function runTests() {
  console.log("🔍 Test 1: Génération hash local...");
  const fakeFile = new File(["Hello ProofMint"], "test.txt");
  const hash = await hashFile(fakeFile);
  console.assert(hash.length === 64, "❌ Hash SHA-256 invalide");

  console.log("🔍 Test 2: Appel API MultiversX...");
  const res = await certifyOnBlockchain(hash);
  console.assert(res.txHash, "❌ Transaction hash manquant");

  console.log("🔍 Test 3: Sauvegarde et lecture base...");
  await saveProof("user1", "test.txt", hash, res.txHash);
  const proofs = await getUserProofs("user1");
  console.assert(proofs.length > 0, "❌ Base vide après sauvegarde");

  console.log("✅ Tous les tests ProofMint sont passés !");
}

runTests().catch(console.error);
```

---

## 🎨 CHARTE VISUELLE — STYLE MULTIVERSX EXPLORER / XPORTAL

### Palette
Fond : #0B0C10  
Texte : #FFFFFF  
Accent bleu : #00C2FF  
Accent violet : #7B61FF  
Vert validation : #00FFA3  
Gris : #A1A1AA  

### Typographie
Titres : Orbitron / Satoshi  
Texte : Inter  

### Exemple CSS
```css
.card {
  background: rgba(255, 255, 255, 0.04);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.3s ease-in-out;
}
.card:hover {
  border-color: #00c2ff;
  box-shadow: 0 0 12px rgba(0, 194, 255, 0.4);
}
```

### Tailwind config
```javascript
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        background: "#0B0C10",
        primary: "#00C2FF",
        secondary: "#7B61FF",
        success: "#00FFA3",
        text: "#FFFFFF",
        subtext: "#A1A1AA",
      },
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        display: ["Orbitron", "sans-serif"],
      },
      borderRadius: {
        xl: "16px",
      },
      boxShadow: {
        glow: "0 0 16px rgba(0, 194, 255, 0.3)",
      },
    },
  },
  plugins: [],
};
```

---

## 🧪 INSTALLER LES DÉPENDANCES
```
npm install js-sha256 jspdf qrcode @replit/database tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

---

## 🚀 MISSION REPLIT
> Construis et ajuste le projet ProofMint selon ces instructions.  
> - Priorité : hash → blockchain → PDF → preuve publique.  
> - Style : UI fidèle à MultiversX Explorer/xPortal.  
> - Vérifie les tests (`/tests/ProofMint.test.js`).  
> - Utilise Tailwind + React + @replit/database.  
> - Pas de wallet utilisateur pour le MVP (clé backend ProofMint uniquement).
