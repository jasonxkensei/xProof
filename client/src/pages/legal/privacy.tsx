import { Shield, ArrowLeft } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";

export default function PolitiqueConfidentialite() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <Link href="/">
            <div className="flex items-center gap-2 cursor-pointer">
              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                <Shield className="h-5 w-5 text-primary-foreground" />
              </div>
              <span className="text-xl font-bold tracking-tight">xproof</span>
            </div>
          </Link>
          <Link href="/">
            <Button variant="ghost" size="sm" data-testid="button-back-home">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Retour
            </Button>
          </Link>
        </div>
      </header>

      <main className="container py-12 max-w-3xl">
        <h1 className="text-3xl font-bold mb-8" data-testid="text-page-title">Politique de confidentialité</h1>
        
        <div className="prose prose-invert max-w-none space-y-8">
          <section>
            <h2 className="text-xl font-semibold mb-4">Introduction</h2>
            <p className="text-muted-foreground leading-relaxed">
              xproof s'engage à protéger la vie privée de ses utilisateurs. Cette politique 
              de confidentialité explique comment nous collectons, utilisons et protégeons 
              vos données personnelles conformément au Règlement Général sur la Protection 
              des Données (RGPD).
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Données collectées</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              xproof collecte uniquement les données strictement nécessaires au fonctionnement du service :
            </p>
            <ul className="space-y-3 text-muted-foreground">
              <li>
                <strong className="text-foreground">Adresse de portefeuille MultiversX :</strong> utilisée pour 
                l'authentification et l'association des certifications à votre compte.
              </li>
              <li>
                <strong className="text-foreground">Hash SHA-256 des fichiers :</strong> empreinte cryptographique 
                de vos fichiers. Le fichier original n'est jamais transmis ni stocké sur nos serveurs.
              </li>
              <li>
                <strong className="text-foreground">Métadonnées de certification :</strong> nom du fichier, 
                date de certification, nom d'auteur (si fourni).
              </li>
              <li>
                <strong className="text-foreground">Données de paiement :</strong> traitées par nos prestataires 
                de paiement (Stripe, xMoney). Nous ne stockons jamais vos données bancaires.
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Données non collectées</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              Pour garantir la confidentialité de vos créations, xproof ne collecte jamais :
            </p>
            <ul className="space-y-2 text-muted-foreground">
              <li>Le contenu de vos fichiers</li>
              <li>Vos données personnelles (nom, email, adresse) sauf si vous les fournissez volontairement</li>
              <li>Votre historique de navigation en dehors du service</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Utilisation des données</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              Vos données sont utilisées exclusivement pour :
            </p>
            <ul className="space-y-2 text-muted-foreground">
              <li>Créer et gérer vos certifications blockchain</li>
              <li>Générer les certificats PDF et pages de preuve publiques</li>
              <li>Traiter les paiements</li>
              <li>Améliorer le service (statistiques agrégées et anonymisées)</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Données blockchain (publiques)</h2>
            <p className="text-muted-foreground leading-relaxed">
              Les preuves de certification sont enregistrées sur la blockchain MultiversX, 
              un registre public et immuable. Les informations suivantes sont publiquement 
              accessibles et ne peuvent être supprimées :
            </p>
            <ul className="mt-4 space-y-2 text-muted-foreground">
              <li>Hash SHA-256 du fichier certifié</li>
              <li>Adresse du portefeuille ayant effectué la certification</li>
              <li>Date et heure de la transaction</li>
              <li>Identifiant de certification</li>
            </ul>
            <p className="text-muted-foreground leading-relaxed mt-4">
              <strong className="text-foreground">Important :</strong> Le hash cryptographique ne permet pas 
              de reconstituer le fichier original. Seul le propriétaire du fichier peut prouver 
              qu'il correspond au hash enregistré.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Conservation des données</h2>
            <ul className="space-y-3 text-muted-foreground">
              <li>
                <strong className="text-foreground">Données de compte :</strong> conservées tant que votre 
                compte est actif, puis supprimées sur demande.
              </li>
              <li>
                <strong className="text-foreground">Données blockchain :</strong> permanentes et immuables 
                par conception de la technologie blockchain.
              </li>
              <li>
                <strong className="text-foreground">Données de paiement :</strong> conservées selon les 
                obligations légales (10 ans pour les données comptables).
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Vos droits (RGPD)</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              Conformément au RGPD, vous disposez des droits suivants :
            </p>
            <ul className="space-y-2 text-muted-foreground">
              <li><strong className="text-foreground">Droit d'accès :</strong> obtenir une copie de vos données</li>
              <li><strong className="text-foreground">Droit de rectification :</strong> corriger vos données inexactes</li>
              <li><strong className="text-foreground">Droit à l'effacement :</strong> supprimer vos données (hors blockchain)</li>
              <li><strong className="text-foreground">Droit à la portabilité :</strong> recevoir vos données dans un format structuré</li>
              <li><strong className="text-foreground">Droit d'opposition :</strong> vous opposer au traitement de vos données</li>
            </ul>
            <p className="text-muted-foreground leading-relaxed mt-4">
              <strong className="text-foreground">Limitation :</strong> Les données enregistrées sur la blockchain 
              ne peuvent être modifiées ou supprimées en raison de la nature immuable de cette technologie.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Sous-traitants</h2>
            <ul className="space-y-3 text-muted-foreground">
              <li>
                <strong className="text-foreground">Replit, Inc.</strong> (hébergement) - États-Unis
              </li>
              <li>
                <strong className="text-foreground">Stripe</strong> (paiements par carte) - États-Unis
              </li>
              <li>
                <strong className="text-foreground">xMoney</strong> (paiements crypto) - Europe
              </li>
              <li>
                <strong className="text-foreground">Neon</strong> (base de données) - États-Unis
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Contact</h2>
            <p className="text-muted-foreground leading-relaxed">
              Pour exercer vos droits ou pour toute question concernant cette politique 
              de confidentialité, vous pouvez nous contacter à : <span className="italic">[Email à venir]</span>
            </p>
          </section>

          <section className="border-t pt-8">
            <p className="text-sm text-muted-foreground">
              Dernière mise à jour : {new Date().toLocaleDateString('fr-FR', { year: 'numeric', month: 'long', day: 'numeric' })}
            </p>
          </section>
        </div>
      </main>
    </div>
  );
}
