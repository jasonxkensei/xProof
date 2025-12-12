import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  Zap, 
  Lock, 
  Globe, 
  Wallet, 
  CheckCircle,
  Upload,
  FileCheck,
  Download,
  Camera,
  Palette,
  Scale,
  Briefcase,
  Music,
  Code,
  ChevronDown,
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
        <div className="container flex h-16 items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">ProofMint</span>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            <a href="#benefits" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-benefits">
              Avantages
            </a>
            <a href="#how-it-works" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-how-it-works">
              Comment ça marche
            </a>
            <a href="#use-cases" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-use-cases">
              Cas d'usage
            </a>
            <a href="#pricing" className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" data-testid="link-nav-pricing">
              Tarifs
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
      <section className="container px-6 py-20 md:py-28">
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
            Horodatez vos créations en 30 secondes. Une preuve irréfutable, 
            reconnue mondialement, impossible à falsifier ou supprimer.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              className="text-base h-12 px-8" 
              onClick={handleConnect}
              data-testid="button-start-free"
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
            Gratuit • Sans carte bancaire • 1 certification offerte par mois
          </p>
        </div>
      </section>

      {/* Trust Bar */}
      <section className="border-y bg-muted/30 py-6">
        <div className="container px-6">
          <div className="flex flex-wrap items-center justify-center gap-6 md:gap-12 text-muted-foreground">
            <div className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-primary" />
              <span className="text-sm font-medium">Chiffrement SHA-256</span>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-primary" />
              <span className="text-sm font-medium">Valide dans 195 pays</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              <span className="text-sm font-medium">Blockchain MultiversX</span>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-primary" />
              <span className="text-sm font-medium">Certification en 30 sec</span>
            </div>
          </div>
        </div>
      </section>

      {/* Benefits Grid */}
      <section id="benefits" className="py-20 md:py-28">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Avantages</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Pourquoi choisir ProofMint ?
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Comme un cachet de La Poste, mais impossible à falsifier. 
                Comme un notaire, mais instantané et 1000× moins cher.
              </p>
            </div>
            
            <div className="grid gap-6 md:grid-cols-3">
              <Card className="hover-elevate">
                <CardContent className="pt-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                    <Zap className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold">Instantané</h3>
                  <p className="text-muted-foreground">
                    Déposez votre fichier, obtenez votre certificat en moins de 30 secondes. 
                    Pas de rendez-vous, pas d'attente.
                  </p>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="pt-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                    <Lock className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold">Inviolable</h3>
                  <p className="text-muted-foreground">
                    Gravé dans la blockchain, impossible à modifier ou supprimer. 
                    Même nous ne pouvons pas altérer votre preuve.
                  </p>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="pt-6">
                  <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                    <Globe className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="mb-2 text-xl font-semibold">Universel</h3>
                  <p className="text-muted-foreground">
                    Vérifiable par n'importe qui, n'importe où dans le monde, 
                    sans logiciel spécial. Juste un lien.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Comment ça marche</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                3 étapes simples
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Aucune connaissance technique requise. 
                Si vous savez envoyer un email, vous savez utiliser ProofMint.
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

      {/* Use Cases */}
      <section id="use-cases" className="py-20 md:py-28">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Cas d'usage</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Qui utilise ProofMint ?
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Des créateurs aux entreprises, chacun protège ce qui compte.
              </p>
            </div>
            
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Card className="hover-elevate">
                <CardContent className="flex items-start gap-4 pt-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Palette className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Designers & Artistes</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Prouvez l'antériorité de vos créations avant de les partager
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="flex items-start gap-4 pt-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Camera className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Photographes</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Protégez vos photos avant de les publier en ligne
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="flex items-start gap-4 pt-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Music className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Musiciens</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Horodatez vos compositions avant envoi aux labels
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="flex items-start gap-4 pt-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Code className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Développeurs</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Certifiez votre code source et vos innovations
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="flex items-start gap-4 pt-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Scale className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Avocats & Juristes</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Horodatez contrats et preuves avec valeur probante
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card className="hover-elevate">
                <CardContent className="flex items-start gap-4 pt-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                    <Briefcase className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Entrepreneurs</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Protégez vos idées, business plans et innovations
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="border-y bg-muted/30 py-20 md:py-28">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="mb-16 text-center">
              <Badge variant="outline" className="mb-4">Tarifs</Badge>
              <h2 className="mb-4 text-3xl md:text-4xl font-bold">
                Simple et transparent
              </h2>
              <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                Commencez gratuitement. Évoluez selon vos besoins.
              </p>
            </div>
            
            <div className="grid gap-6 md:grid-cols-3">
              <Card>
                <CardContent className="pt-6">
                  <h3 className="mb-1 text-lg font-semibold text-muted-foreground">Gratuit</h3>
                  <div className="mb-4">
                    <span className="text-4xl font-bold">0€</span>
                    <span className="text-muted-foreground">/mois</span>
                  </div>
                  <p className="text-sm text-muted-foreground mb-6">
                    Parfait pour découvrir le service
                  </p>
                  <ul className="mb-6 space-y-3 text-sm">
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>1 certification par mois</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Certificat PDF</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Page de vérification publique</span>
                    </li>
                    <li className="flex items-center gap-2 text-muted-foreground">
                      <CheckCircle className="h-4 w-4 shrink-0" />
                      <span>Filigrane ProofMint</span>
                    </li>
                  </ul>
                  <Button 
                    variant="outline" 
                    className="w-full" 
                    onClick={handleConnect}
                    data-testid="button-start-free-tier"
                  >
                    Commencer gratuitement
                  </Button>
                </CardContent>
              </Card>

              <Card className="border-primary shadow-lg relative overflow-hidden">
                <div className="absolute top-0 left-0 right-0 bg-primary text-primary-foreground text-center text-sm font-medium py-1">
                  Le plus populaire
                </div>
                <CardContent className="pt-10">
                  <h3 className="mb-1 text-lg font-semibold">Pro</h3>
                  <div className="mb-4">
                    <span className="text-4xl font-bold">9,99€</span>
                    <span className="text-muted-foreground">/mois</span>
                  </div>
                  <p className="text-sm text-muted-foreground mb-6">
                    Pour les créateurs réguliers
                  </p>
                  <ul className="mb-6 space-y-3 text-sm">
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span><strong>20</strong> certifications par mois</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Sans filigrane</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Branding personnalisé</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Support prioritaire</span>
                    </li>
                  </ul>
                  <Button 
                    className="w-full" 
                    onClick={handleConnect}
                    data-testid="button-start-pro"
                  >
                    Choisir Pro
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <h3 className="mb-1 text-lg font-semibold text-muted-foreground">Business</h3>
                  <div className="mb-4">
                    <span className="text-4xl font-bold">39€</span>
                    <span className="text-muted-foreground">/mois</span>
                  </div>
                  <p className="text-sm text-muted-foreground mb-6">
                    Pour les équipes et entreprises
                  </p>
                  <ul className="mb-6 space-y-3 text-sm">
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span><strong>200</strong> certifications par mois</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Accès API</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Logo entreprise sur certificats</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-primary shrink-0" />
                      <span>Support dédié</span>
                    </li>
                  </ul>
                  <Button 
                    variant="outline" 
                    className="w-full" 
                    onClick={handleConnect}
                    data-testid="button-start-business"
                  >
                    Choisir Business
                  </Button>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="py-20 md:py-28">
        <div className="container px-6">
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
                  Vous pouvez utiliser l'extension navigateur MultiversX DeFi Wallet (gratuite).
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="border-t bg-primary/5 py-20 md:py-28">
        <div className="container px-6">
          <div className="mx-auto max-w-3xl text-center">
            <h2 className="mb-4 text-3xl md:text-4xl font-bold">
              Protégez votre première création
            </h2>
            <p className="mb-8 text-lg text-muted-foreground">
              Rejoignez les créateurs qui sécurisent leur travail. 
              Votre première certification est gratuite.
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
              Aucune carte bancaire requise
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-12">
        <div className="container px-6">
          <div className="mx-auto max-w-5xl">
            <div className="grid gap-8 md:grid-cols-4 mb-12">
              <div className="md:col-span-2">
                <div className="flex items-center gap-2 mb-4">
                  <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                    <Shield className="h-5 w-5 text-primary-foreground" />
                  </div>
                  <span className="text-xl font-bold">ProofMint</span>
                </div>
                <p className="text-sm text-muted-foreground max-w-xs">
                  Certification blockchain pour créateurs et entreprises. 
                  Prouvez l'existence et la propriété de vos fichiers.
                </p>
              </div>
              
              <div>
                <h4 className="font-semibold mb-4">Produit</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="#benefits" className="hover:text-foreground transition-colors">Avantages</a></li>
                  <li><a href="#how-it-works" className="hover:text-foreground transition-colors">Comment ça marche</a></li>
                  <li><a href="#pricing" className="hover:text-foreground transition-colors">Tarifs</a></li>
                  <li><a href="#faq" className="hover:text-foreground transition-colors">FAQ</a></li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-semibold mb-4">Légal</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li><a href="#" className="hover:text-foreground transition-colors">Mentions légales</a></li>
                  <li><a href="#" className="hover:text-foreground transition-colors">Politique de confidentialité</a></li>
                  <li><a href="#" className="hover:text-foreground transition-colors">CGU</a></li>
                </ul>
              </div>
            </div>
            
            <div className="border-t pt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
              <p className="text-sm text-muted-foreground">
                © {new Date().getFullYear()} ProofMint. Tous droits réservés.
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
