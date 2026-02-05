import { Shield, ArrowLeft } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";

export default function MentionsLegales() {
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
        <h1 className="text-3xl font-bold mb-8" data-testid="text-page-title">Mentions légales</h1>
        
        <div className="prose prose-invert max-w-none space-y-8">
          <section>
            <h2 className="text-xl font-semibold mb-4">Éditeur du service</h2>
            <p className="text-muted-foreground leading-relaxed">
              Le service xproof est actuellement opéré par un entrepreneur individuel basé en France, 
              dans l'attente de la création d'une structure juridique adaptée.
            </p>
            <ul className="mt-4 space-y-2 text-muted-foreground">
              <li><strong className="text-foreground">Nom du service :</strong> xproof</li>
              <li><strong className="text-foreground">Pays :</strong> France</li>
              <li><strong className="text-foreground">Contact :</strong> <span className="italic">[Email à venir]</span></li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Hébergement</h2>
            <p className="text-muted-foreground leading-relaxed">
              Le service est hébergé par Replit, Inc.
            </p>
            <ul className="mt-4 space-y-2 text-muted-foreground">
              <li><strong className="text-foreground">Raison sociale :</strong> Replit, Inc.</li>
              <li><strong className="text-foreground">Adresse :</strong> 1555 Blake Street, Suite 301, Denver, CO 80202, USA</li>
              <li><strong className="text-foreground">Site web :</strong> <a href="https://replit.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">replit.com</a></li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Infrastructure blockchain</h2>
            <p className="text-muted-foreground leading-relaxed">
              xproof utilise la blockchain MultiversX pour l'enregistrement des preuves d'existence.
              Les transactions sont publiques et vérifiables sur l'explorateur MultiversX.
            </p>
            <ul className="mt-4 space-y-2 text-muted-foreground">
              <li><strong className="text-foreground">Blockchain :</strong> MultiversX (anciennement Elrond)</li>
              <li><strong className="text-foreground">Explorateur :</strong> <a href="https://explorer.multiversx.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">explorer.multiversx.com</a></li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Propriété intellectuelle</h2>
            <p className="text-muted-foreground leading-relaxed">
              L'ensemble des contenus présents sur xproof (textes, graphismes, logos, icônes, images, 
              logiciels) sont la propriété exclusive de xproof ou de ses partenaires et sont protégés 
              par les lois françaises et internationales relatives à la propriété intellectuelle.
            </p>
            <p className="text-muted-foreground leading-relaxed mt-4">
              Toute reproduction, représentation, modification, publication ou adaptation de tout ou 
              partie des éléments du site, quel que soit le moyen ou le procédé utilisé, est interdite 
              sauf autorisation écrite préalable.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Limitation de responsabilité</h2>
            <p className="text-muted-foreground leading-relaxed">
              xproof ne saurait être tenu responsable des dommages directs ou indirects résultant 
              de l'utilisation du service, notamment en cas de perte de données ou d'interruption 
              de service.
            </p>
            <p className="text-muted-foreground leading-relaxed mt-4">
              Le service de certification repose sur la blockchain MultiversX. La disponibilité 
              et la pérennité des preuves enregistrées dépendent de l'infrastructure blockchain.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-4">Droit applicable</h2>
            <p className="text-muted-foreground leading-relaxed">
              Les présentes mentions légales sont régies par le droit français. En cas de litige, 
              les tribunaux français seront seuls compétents.
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
