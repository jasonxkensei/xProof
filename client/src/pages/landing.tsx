import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  Wallet, 
  CheckCircle,
  Upload,
  ArrowRight,
  Play
} from "lucide-react";
import { WalletLoginModal } from "@/components/wallet-login-modal";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

export default function Landing() {
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  const handleConnect = () => {
    setIsLoginModalOpen(true);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            <a href="#how-it-works" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-how-it-works">
              Comment ça marche
            </a>
            <a href="#faq" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-faq">
              FAQ
            </a>
          </nav>
          <div className="flex items-center gap-3">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={handleConnect}
              data-testid="button-login"
            >
              <Wallet className="mr-2 h-4 w-4" />
              Connexion
            </Button>
            <Button 
              size="sm" 
              onClick={handleConnect}
              data-testid="button-get-started"
            >
              Commencer
            </Button>
          </div>
        </div>
      </header>
      {/* Hero Section */}
      <section className="container py-20 md:py-28">
        <div className="mx-auto max-w-5xl text-center">
          <Badge variant="secondary" className="mb-6 px-4 py-1.5">
            <Shield className="mr-2 h-3.5 w-3.5" />
            Preuve blockchain infalsifiable
          </Badge>
          
          <h1 className="mb-6 text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight leading-tight">
            Prouvez que c'est le vôtre.
            <br />
            <span className="text-primary">Pour toujours.</span>
          </h1>
          
          <p className="mx-auto mb-8 max-w-2xl text-lg md:text-xl text-muted-foreground leading-relaxed">
            Une preuve irréfutable, 
            reconnue mondialement, impossible à falsifier ou supprimer.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              className="text-base h-12 px-8" 
              onClick={handleConnect}
              data-testid="button-certify-file"
            >
              <Upload className="mr-2 h-5 w-5" />
              Certifier un fichier
            </Button>
            <Button 
              asChild 
              variant="outline" 
              size="lg" 
              className="text-base h-12 px-8"
              data-testid="button-see-demo"
            >
              <a href="#how-it-works">
                <Play className="mr-2 h-4 w-4" />
                Voir comment ça marche
              </a>
            </Button>
          </div>
          
          <p className="mt-6 text-sm text-muted-foreground">
            0.03€ par certification • Paiement crypto uniquement • Illimité
          </p>
        </div>
      </section>
      {/* How It Works */}
      <section id="how-it-works" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Comment ça marche</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                3 étapes simples
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Aucune connaissance technique requise. 
                Si vous savez envoyer un email, vous savez utiliser xproof.
              </p>
            </div>
            
            <div className="grid gap-8 md:grid-cols-3">
              <div className="relative text-center md:text-left">
                <div className="mb-6 mx-auto md:mx-0 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  1
                </div>
                <h3 className="mb-3 text-xl font-semibold">Déposez votre fichier</h3>
                <p className="text-muted-foreground">
                  Glissez n'importe quel fichier : photo, document, musique, code... 
                  Votre fichier reste privé, il n'est jamais uploadé.
                </p>
                <div className="hidden md:block absolute top-8 left-[calc(100%-20px)] w-[calc(100%-40px)]">
                  <ArrowRight className="h-6 w-6 text-muted-foreground/30" />
                </div>
              </div>

              <div className="relative text-center md:text-left">
                <div className="mb-6 mx-auto md:mx-0 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  2
                </div>
                <h3 className="mb-3 text-xl font-semibold">On calcule l'empreinte</h3>
                <p className="text-muted-foreground">
                  Une empreinte unique (hash SHA-256) est calculée localement. 
                  C'est comme l'ADN de votre fichier.
                </p>
                <div className="hidden md:block absolute top-8 left-[calc(100%-20px)] w-[calc(100%-40px)]">
                  <ArrowRight className="h-6 w-6 text-muted-foreground/30" />
                </div>
              </div>

              <div className="text-center md:text-left">
                <div className="mb-6 mx-auto md:mx-0 flex h-16 w-16 items-center justify-center rounded-full bg-primary text-2xl font-bold text-primary-foreground">
                  3
                </div>
                <h3 className="mb-3 text-xl font-semibold">Gravé dans la blockchain</h3>
                <p className="text-muted-foreground">
                  L'empreinte est enregistrée définitivement sur la blockchain. 
                  Vous recevez un certificat PDF avec QR code.
                </p>
              </div>
            </div>

            <div className="mt-12 text-center">
              <Button 
                size="lg" 
                onClick={handleConnect}
                data-testid="button-try-now"
              >
                Essayer maintenant
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </section>
      {/* Pricing */}
      <section id="pricing" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-3xl">
            <div className="mb-12 text-center">
              <Badge variant="outline" className="mb-4">Tarif simple</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Un prix unique. Sans abonnement.
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Payez uniquement ce que vous utilisez. Pas de frais cachés, pas d'engagement.
              </p>
            </div>
            
            <Card className="border-primary shadow-lg max-w-md mx-auto">
              <CardContent className="pt-8 pb-8">
                <div className="text-center mb-6">
                  <div className="mb-2">
                    <span className="text-5xl font-bold">0.03€</span>
                  </div>
                  <p className="text-muted-foreground">
                    par certification
                  </p>
                </div>
                <ul className="mb-8 space-y-3 text-sm">
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span><strong>Certifications illimitées</strong></span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Certificat PDF téléchargeable</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Page de vérification publique</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>QR code de vérification</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                    <span>Blockchain MultiversX</span>
                  </li>
                </ul>
                <Button 
                  className="w-full" 
                  size="lg"
                  onClick={handleConnect}
                  data-testid="button-start-now"
                >
                  Commencer maintenant
                </Button>
              </CardContent>
            </Card>
            
            <p className="mt-8 text-center text-sm text-muted-foreground">Paiement en $EGLD lors de la signature de la transaction.</p>
          </div>
        </div>
      </section>
      {/* FAQ */}
      <section id="faq" className="py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-3xl">
            <div className="mb-12 text-center">
              <Badge variant="outline" className="mb-4">FAQ</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Questions fréquentes
              </h2>
            </div>
            
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="item-1">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-upload">
                  Est-ce que mon fichier est uploadé sur vos serveurs ?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Non, jamais. Votre fichier reste sur votre appareil. Seule son "empreinte digitale" 
                  (un code unique de 64 caractères) est calculée localement et enregistrée sur la blockchain. 
                  Votre fichier reste 100% privé.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-2">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-blockchain">
                  Qu'est-ce que la blockchain MultiversX ?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  MultiversX est une blockchain européenne ultra-performante et écologique. 
                  Contrairement à Bitcoin, elle consomme très peu d'énergie. C'est un registre 
                  public mondial, impossible à modifier ou supprimer, parfait pour les preuves légales.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-3">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-legal">
                  Est-ce que ça a une valeur juridique ?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Oui. L'horodatage blockchain est reconnu dans de nombreuses juridictions comme 
                  preuve d'antériorité. Il prouve que votre fichier existait à une date précise, 
                  ce qui est essentiel en cas de litige sur la propriété intellectuelle.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-4">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-modify">
                  Que se passe-t-il si je modifie mon fichier ?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Le moindre changement (même un pixel) génère une empreinte complètement différente. 
                  C'est ce qui garantit l'intégrité : si quelqu'un modifie votre fichier, 
                  il ne correspondra plus au certificat original.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-5">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-verify">
                  Comment quelqu'un peut vérifier mon certificat ?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Chaque certificat contient un QR code et un lien vers une page de vérification publique. 
                  N'importe qui peut scanner le QR ou visiter le lien pour voir les détails de la certification 
                  et vérifier directement sur la blockchain.
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="item-6">
                <AccordionTrigger className="text-left" data-testid="faq-trigger-wallet">
                  Pourquoi ai-je besoin d'un portefeuille crypto ?
                </AccordionTrigger>
                <AccordionContent className="text-muted-foreground">
                  Le portefeuille (wallet) sert à vous identifier de manière sécurisée et à signer 
                  vos certifications. C'est comme une signature électronique ultra-sécurisée. 
                  Vous pouvez utiliser l'extension navigateur MultiversX DeFi Wallet ou l'app xPortal.
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </div>
      </section>
      {/* Final CTA */}
      <section className="border-t bg-primary/5 py-20 md:py-28">
        <div className="container">
          <div className="mx-auto max-w-3xl text-center">
            <h2 className="mb-4 text-3xl md:text-4xl font-bold">
              Protégez votre première création
            </h2>
            <p className="mb-8 text-lg text-muted-foreground">
              Rejoignez les créateurs qui sécurisent leur travail. 
              Seulement 0.03€ par certification.
            </p>
            <Button 
              size="lg" 
              className="text-base h-12 px-8"
              onClick={handleConnect}
              data-testid="button-final-cta"
            >
              <Shield className="mr-2 h-5 w-5" />
              Commencer maintenant
            </Button>
            <p className="mt-4 text-sm text-muted-foreground">
              Paiement crypto uniquement
            </p>
          </div>
        </div>
      </section>
      {/* Footer */}
      <footer className="border-t py-12">
        <div className="container">
          <div className="mx-auto max-w-5xl">
            <div className="grid gap-8 md:grid-cols-4 mb-12">
              <div className="md:col-span-2">
                <div className="flex items-center gap-2 mb-4">
                  <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                    <Shield className="h-5 w-5 text-primary-foreground" />
                  </div>
                  <span className="text-xl font-bold">xproof</span>
                </div>
                <p className="text-sm text-muted-foreground max-w-xs">
                  Certification blockchain pour créateurs et entreprises. 
                  Prouvez l'existence et la propriété de vos fichiers.
                </p>
              </div>
              
              <div>
                <h4 className="font-semibold mb-4">Produit</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="#how-it-works" className="hover:text-foreground transition-colors">Comment ça marche</a></li>
                  <li><a href="#faq" className="hover:text-foreground transition-colors">FAQ</a></li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-semibold mb-4">Légal</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="/legal/mentions" className="hover:text-foreground transition-colors" data-testid="link-legal-mentions">Mentions légales</a></li>
                  <li><a href="/legal/privacy" className="hover:text-foreground transition-colors" data-testid="link-legal-privacy">Politique de confidentialité</a></li>
                  <li><a href="/legal/terms" className="hover:text-foreground transition-colors" data-testid="link-legal-terms">CGU</a></li>
                </ul>
              </div>
            </div>
            
            <div className="border-t pt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
              <p className="text-sm text-muted-foreground">
                © {new Date().getFullYear()} xproof. Tous droits réservés.
              </p>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <span>Propulsé par</span>
                <a 
                  href="https://multiversx.com" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="font-medium text-primary hover:underline"
                >
                  MultiversX
                </a>
              </div>
            </div>
          </div>
        </div>
      </footer>
      <WalletLoginModal 
        open={isLoginModalOpen} 
        onOpenChange={setIsLoginModalOpen} 
      />
    </div>
  );
}
