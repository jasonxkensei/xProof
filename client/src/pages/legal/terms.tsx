import { Shield, ArrowLeft } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";

export default function ConditionsUtilisation() {
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
        <h1 className="text-3xl font-bold mb-8" data-testid="text-page-title">Conditions Générales d'Utilisation</h1>
        
        <div className="prose prose-invert max-w-none space-y-8">
          <section>
            <h2 className="text-xl font-semibold mb-4">1. Objet du service</h2>
            <p className="text-muted-foreground leading-relaxed">
              xproof est un service de certification numérique qui permet d'enregistrer 
              des preuves d'existence de fichiers sur la blockchain MultiversX. Le service 
              génère une empreinte cryptographique (hash SHA-256) de vos fichiers et l'inscrit 
              de manière permanente sur la blockchain, créant ainsi une preuve horodatée et immuable.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">2. Acceptation des conditions</h2>
            <p className="text-muted-foreground leading-relaxed">
              L'utilisation du service xproof implique l'acceptation pleine et entière des 
              présentes conditions générales d'utilisation. Si vous n'acceptez pas ces conditions, 
              vous ne devez pas utiliser le service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">3. Inscription et authentification</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              L'accès au service nécessite une connexion via un portefeuille MultiversX compatible 
              (xPortal, Extension, Web Wallet). L'utilisateur est responsable de la sécurité de 
              son portefeuille et de ses clés privées.
            </p>
            <p className="text-muted-foreground leading-relaxed">
              xproof n'a jamais accès à vos clés privées et ne peut pas récupérer l'accès à 
              votre compte en cas de perte de vos identifiants de portefeuille.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">4. Description du service</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              Le service xproof comprend :
            </p>
            <ul className="space-y-2 text-muted-foreground">
              <li>La génération d'empreintes cryptographiques (hash SHA-256) de fichiers</li>
              <li>L'enregistrement de ces empreintes sur la blockchain MultiversX</li>
              <li>La génération de certificats PDF téléchargeables</li>
              <li>La création de pages de preuve publiques vérifiables</li>
              <li>L'accès à un tableau de bord pour gérer vos certifications</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">5. Tarification</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              Le service de certification est facturé à <strong className="text-foreground">0.03€ par certification</strong>, 
              payable en EGLD (la cryptomonnaie native de MultiversX) au taux de change en vigueur 
              au moment de la transaction.
            </p>
            <p className="text-muted-foreground leading-relaxed">
              Les frais de réseau blockchain (gas fees) sont inclus dans ce tarif lorsque le 
              paiement est effectué via le système de paiement intégré. En cas de transaction 
              signée directement par l'utilisateur, les frais de réseau sont à sa charge.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">6. Engagements de l'utilisateur</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              L'utilisateur s'engage à :
            </p>
            <ul className="space-y-2 text-muted-foreground">
              <li>Ne certifier que des fichiers dont il détient les droits ou l'autorisation de certifier</li>
              <li>Ne pas utiliser le service à des fins illégales ou frauduleuses</li>
              <li>Ne pas tenter de compromettre la sécurité ou le fonctionnement du service</li>
              <li>Fournir des informations exactes lors de la certification</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">7. Propriété intellectuelle</h2>
            <p className="text-muted-foreground leading-relaxed">
              xproof ne revendique aucun droit sur les fichiers que vous certifiez. La certification 
              ne transfère aucun droit de propriété intellectuelle. Elle constitue uniquement une 
              preuve que le fichier existait sous cette forme à une date donnée.
            </p>
            <p className="text-muted-foreground leading-relaxed mt-4">
              <strong className="text-foreground">Important :</strong> La certification xproof ne constitue 
              pas une preuve de propriété ou de paternité. Elle prouve uniquement l'existence 
              du fichier à une date précise.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">8. Limitation de responsabilité</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              xproof s'efforce de maintenir un service fiable et disponible, mais ne peut garantir :
            </p>
            <ul className="space-y-2 text-muted-foreground">
              <li>Une disponibilité continue et sans interruption du service</li>
              <li>L'absence d'erreurs ou de dysfonctionnements</li>
              <li>La pérennité de la blockchain MultiversX (infrastructure tierce)</li>
            </ul>
            <p className="text-muted-foreground leading-relaxed mt-4">
              En aucun cas xproof ne pourra être tenu responsable des dommages directs ou indirects, 
              pertes de données, pertes de revenus ou tout autre préjudice résultant de l'utilisation 
              ou de l'impossibilité d'utiliser le service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">9. Nature des certifications</h2>
            <p className="text-muted-foreground leading-relaxed">
              Les certifications xproof sont basées sur la technologie blockchain et constituent 
              des preuves techniques d'existence à une date donnée. Leur valeur juridique dépend 
              de la législation applicable et de l'appréciation des tribunaux compétents.
            </p>
            <p className="text-muted-foreground leading-relaxed mt-4">
              xproof recommande de consulter un professionnel du droit pour toute utilisation 
              des certifications dans un contexte juridique.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">10. Immuabilité des données blockchain</h2>
            <p className="text-muted-foreground leading-relaxed">
              Par conception, les données enregistrées sur la blockchain sont permanentes et 
              immuables. Une fois une certification effectuée, il est techniquement impossible 
              de la modifier ou de la supprimer. L'utilisateur en est informé et l'accepte 
              expressément en utilisant le service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">11. Modification des conditions</h2>
            <p className="text-muted-foreground leading-relaxed">
              xproof se réserve le droit de modifier les présentes conditions générales 
              d'utilisation à tout moment. Les utilisateurs seront informés des modifications 
              importantes. La continuation de l'utilisation du service après notification 
              vaut acceptation des nouvelles conditions.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">12. Droit applicable et juridiction</h2>
            <p className="text-muted-foreground leading-relaxed">
              Les présentes conditions sont régies par le droit français. En cas de litige, 
              et après échec de toute tentative de résolution amiable, les tribunaux français 
              seront seuls compétents.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">13. Contact</h2>
            <p className="text-muted-foreground leading-relaxed">
              Pour toute question concernant ces conditions d'utilisation, vous pouvez 
              nous contacter à : <span className="italic">[Email à venir]</span>
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
