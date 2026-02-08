import { useParams } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, ExternalLink, Download, Copy, CheckCircle, Calendar, Hash, User } from "lucide-react";
import { format } from "date-fns";
import { formatHash, copyToClipboard } from "@/lib/hashUtils";
import { useToast } from "@/hooks/use-toast";
import type { Certification } from "@shared/schema";

export default function ProofPage() {
  const { id } = useParams();
  const { toast } = useToast();

  const { data: certification, isLoading, error } = useQuery<Certification>({
    queryKey: ["/api/proof", id],
    enabled: !!id,
  });

  const handleCopy = async (text: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      toast({
        title: "Copied!",
        description: "Hash copied to clipboard",
      });
    }
  };

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <p className="text-sm text-muted-foreground">Loading proof...</p>
        </div>
      </div>
    );
  }

  if (error || !certification) {
    return (
      <div className="flex min-h-screen items-center justify-center px-6">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center py-16 text-center">
            <Shield className="mb-4 h-16 w-16 text-muted-foreground/50" />
            <h2 className="mb-2 text-2xl font-bold">Proof not found</h2>
            <p className="mb-6 text-muted-foreground">
              The certification proof you are looking for does not exist or is not public.
            </p>
            <Button asChild data-testid="button-home">
              <a href="/">Back to home</a>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isVerified = certification.blockchainStatus === "confirmed";

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </div>
          <Button asChild variant="outline" size="sm" data-testid="button-home-header">
            <a href="/">Home</a>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-4xl py-16">
        {/* Verification Badge */}
        <div className="mb-12 flex flex-col items-center text-center">
          <div className={`mb-6 flex h-24 w-24 items-center justify-center rounded-full ${
            isVerified ? "bg-chart-2/10" : "bg-muted"
          }`}>
            {isVerified ? (
              <CheckCircle className="h-12 w-12 text-chart-2" />
            ) : (
              <Shield className="h-12 w-12 text-muted-foreground" />
            )}
          </div>
          <h1 className="mb-3 text-3xl md:text-4xl font-bold tracking-tight">
            {isVerified ? "Verified on the blockchain" : "Certification in progress"}
          </h1>
          <p className="text-lg text-muted-foreground max-w-2xl">
            The authenticity of this document has been {isVerified ? "verified" : "recorded"} on the MultiversX blockchain
          </p>
        </div>

        {/* Main Proof Card */}
        <Card className="mb-8">
          <CardContent className="space-y-6 pt-6">
            {/* File Information */}
            <div>
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-xl font-semibold">File information</h2>
                {isVerified && (
                  <Badge className="bg-chart-2 hover:bg-chart-2" data-testid="badge-verified">
                    <CheckCircle className="mr-1 h-3 w-3" />
                    Verified
                  </Badge>
                )}
              </div>
              <div className="space-y-4">
                <div className="flex items-start gap-3 rounded-lg bg-muted/30 p-4">
                  <Shield className="mt-0.5 h-5 w-5 text-primary" />
                  <div className="flex-1 min-w-0">
                    <p className="mb-1 text-sm font-medium text-muted-foreground">File name</p>
                    <p className="font-semibold break-all" data-testid="text-proof-filename">
                      {certification.fileName}
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3 rounded-lg bg-muted/30 p-4">
                  <Hash className="mt-0.5 h-5 w-5 text-primary" />
                  <div className="flex-1 min-w-0">
                    <p className="mb-1 text-sm font-medium text-muted-foreground">SHA-256 hash</p>
                    <div className="flex items-center gap-2">
                      <p className="flex-1 break-all font-mono text-sm" data-testid="text-proof-hash">
                        {certification.fileHash}
                      </p>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 w-8 p-0 shrink-0"
                        onClick={() => handleCopy(certification.fileHash)}
                        data-testid="button-copy-proof-hash"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-3 rounded-lg bg-muted/30 p-4">
                  <Calendar className="mt-0.5 h-5 w-5 text-primary" />
                  <div className="flex-1">
                    <p className="mb-1 text-sm font-medium text-muted-foreground">Certification date</p>
                    <p className="font-semibold" data-testid="text-proof-date">
                      {certification.createdAt ? format(new Date(certification.createdAt), "MM/dd/yyyy 'at' HH:mm") : "Unknown date"}
                    </p>
                  </div>
                </div>

                {certification.authorName && (
                  <div className="flex items-start gap-3 rounded-lg bg-muted/30 p-4">
                    <User className="mt-0.5 h-5 w-5 text-primary" />
                    <div className="flex-1">
                      <p className="mb-1 text-sm font-medium text-muted-foreground">Certified by</p>
                      <p className="font-semibold" data-testid="text-proof-author">
                        {certification.authorName}
                      </p>
                      {certification.authorSignature && (
                        <p className="mt-1 text-sm text-muted-foreground" data-testid="text-proof-signature">
                          {certification.authorSignature}
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Blockchain Information */}
            {certification.transactionHash && (
              <div className="border-t pt-6">
                <h3 className="mb-4 text-lg font-semibold">Blockchain details</h3>
                <div className="space-y-3">
                  <div className="rounded-lg bg-muted/30 p-4">
                    <p className="mb-1 text-sm font-medium text-muted-foreground">Transaction hash</p>
                    <p className="break-all font-mono text-sm" data-testid="text-transaction-hash">
                      {certification.transactionHash}
                    </p>
                  </div>
                  {certification.transactionUrl && (
                    <Button
                      asChild
                      variant="outline"
                      className="w-full"
                      data-testid="button-view-blockchain"
                    >
                      <a href={certification.transactionUrl} target="_blank" rel="noopener noreferrer">
                        <ExternalLink className="mr-2 h-4 w-4" />
                        View on MultiversX explorer
                      </a>
                    </Button>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <Button asChild variant="default" size="lg" data-testid="button-download-certificate">
            <a href={`/api/certificates/${certification.id}.pdf`} download>
              <Download className="mr-2 h-5 w-5" />
              Download certificate
            </a>
          </Button>
          <Button asChild variant="outline" size="lg" data-testid="button-certify-yours">
            <a href="/">Certify your files</a>
          </Button>
        </div>

        {/* Trust Footer */}
        <div className="mt-16 border-t pt-8 text-center">
          <p className="text-sm text-muted-foreground">
            Powered by{" "}
            <span className="font-semibold text-primary">MultiversX</span>{" "}
            - The Truth Machine
          </p>
        </div>
      </div>
    </div>
  );
}
