import { useState, useCallback, useEffect } from "react";
import { useWalletAuth } from "@/hooks/useWalletAuth";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Shield, Upload, File, CheckCircle, Loader2, ArrowLeft, Download, ExternalLink, Wallet, AlertTriangle } from "lucide-react";
import { hashFile } from "@/lib/hashFile";
import { generateProofPDF } from "@/lib/generateProofPDF";
import { sendCertificationTransaction } from "@/lib/multiversxTransaction";
import { Link, useLocation } from "wouter";
import { WalletLoginModal } from "@/components/wallet-login-modal";

interface CertificationData {
  id?: string;
  fileName: string;
  fileHash: string;
  fileType: string;
  fileSize: number;
  authorName: string;
  txHash?: string;
  explorerUrl?: string;
}

export default function Certify() {
  const { toast } = useToast();
  const { user, isAuthenticated, isWalletConnected } = useWalletAuth();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();

  const [file, setFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string>("");
  const [authorName, setAuthorName] = useState<string>("");
  const [isHashing, setIsHashing] = useState(false);
  const [hashProgress, setHashProgress] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const [certificationResult, setCertificationResult] = useState<CertificationData | null>(null);
  const [isSigning, setIsSigning] = useState(false);
  const [signatureStep, setSignatureStep] = useState<string>("");
  const [showWalletModal, setShowWalletModal] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      setLocation("/");
    }
  }, [isAuthenticated, setLocation]);

  useEffect(() => {
    if (user?.firstName && user?.lastName) {
      setAuthorName(`${user.firstName} ${user.lastName}`);
    } else if (user?.email) {
      setAuthorName(user.email);
    } else if (user?.walletAddress) {
      setAuthorName(`${user.walletAddress.slice(0, 8)}...${user.walletAddress.slice(-6)}`);
    }
  }, [user]);

  const certifyMutation = useMutation({
    mutationFn: async (data: CertificationData) => {
      const response = await apiRequest("POST", "/api/certifications", data);
      return response.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/certifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      setCertificationResult({
        ...data,
        txHash: data.transactionHash,
        explorerUrl: data.transactionUrl,
      });
      toast({
        title: "Success!",
        description: "Your file has been certified on the blockchain",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Certification failed",
        description: error.message || "An error occurred during certification",
        variant: "destructive",
      });
    },
  });

  const handleFileSelect = async (selectedFile: File) => {
    setFile(selectedFile);
    setIsHashing(true);
    setHashProgress(0);

    try {
      const progressInterval = setInterval(() => {
        setHashProgress((prev) => Math.min(prev + 10, 90));
      }, 100);

      const hash = await hashFile(selectedFile);
      
      clearInterval(progressInterval);
      setHashProgress(100);
      setFileHash(hash);
      
      setTimeout(() => setIsHashing(false), 300);
    } catch (error) {
      toast({
        title: "Error",
        description: "Unable to compute the file fingerprint",
        variant: "destructive",
      });
      setIsHashing(false);
      setFile(null);
    }
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      handleFileSelect(droppedFile);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!file || !fileHash || !authorName) {
      toast({
        title: "Missing information",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    if (!user?.walletAddress) {
      toast({
        title: "Wallet required",
        description: "Please connect your wallet to certify files",
        variant: "destructive",
      });
      return;
    }

    setIsSigning(true);
    setSignatureStep("Creating the transaction...");

    try {
      setSignatureStep("Check your wallet to sign (enter the 2FA code if enabled)...");
      
      const txResult = await sendCertificationTransaction({
        userAddress: user.walletAddress,
        fileHash,
        fileName: file.name,
        authorName,
      });

      setSignatureStep("Recording the certification...");

      const response = await apiRequest("POST", "/api/certifications", {
        fileName: file.name,
        fileHash,
        fileType: file.type || "unknown",
        fileSize: file.size,
        authorName,
        transactionHash: txResult.txHash,
        transactionUrl: txResult.explorerUrl,
      });

      const data = await response.json();

      queryClient.invalidateQueries({ queryKey: ["/api/certifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/me"] });
      
      setCertificationResult({
        id: data.id,
        fileName: file.name,
        fileHash,
        fileType: file.type || "unknown",
        fileSize: file.size,
        authorName,
        txHash: txResult.txHash,
        explorerUrl: txResult.explorerUrl,
      });

      toast({
        title: "Success!",
        description: "Your file has been certified on the MultiversX blockchain",
      });
    } catch (error: any) {
      console.error("Certification error:", error);
      toast({
        title: "Certification failed",
        description: error.message || "An error occurred during certification",
        variant: "destructive",
      });
    } finally {
      setIsSigning(false);
      setSignatureStep("");
    }
  };

  const handleDownloadPDF = async () => {
    if (!certificationResult) return;

    if (certificationResult.id) {
      // Download professional PDF from server
      const response = await fetch(`/api/certificates/${certificationResult.id}.pdf`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${certificationResult.fileName.replace(/\.[^/.]+$/, "")}_xproof_certificate.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        toast({
          title: "PDF downloaded",
          description: "Your certificate has been saved",
        });
        return;
      }
    }

    // Fallback to client-side PDF if server fails
    if (file) {
      await generateProofPDF({
        fileName: file.name,
        fileHash: certificationResult.fileHash,
        txHash: certificationResult.txHash || "",
        explorerUrl: certificationResult.explorerUrl || "",
        authorName: certificationResult.authorName,
        certificationDate: new Date().toLocaleDateString(),
      });

      toast({
        title: "PDF downloaded",
        description: "Your certificate has been saved",
      });
    }
  };

  if (!isAuthenticated) {
    return null;
  }

  if (certificationResult) {
    return (
      <div className="min-h-screen bg-background">
        <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="container flex h-16 items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
                <Shield className="h-5 w-5 text-primary-foreground" />
              </div>
              <span className="text-xl font-bold tracking-tight">xproof</span>
            </div>
          </div>
        </header>

        <div className="container mx-auto max-w-3xl py-12">
          <div className="text-center">
            <div className="mb-6 inline-flex h-20 w-20 items-center justify-center rounded-full bg-primary/10">
              <CheckCircle className="h-10 w-10 text-primary" />
            </div>
            <h1 className="mb-4 text-3xl font-bold tracking-tight">Certification successful!</h1>
            <p className="mb-8 text-muted-foreground">
              Your file has been certified on the MultiversX blockchain
            </p>
          </div>

          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Certification details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground">File name</p>
                <p className="font-medium" data-testid="text-cert-filename">{certificationResult.fileName}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">SHA-256 hash</p>
                <p className="break-all font-mono text-sm" data-testid="text-cert-hash">
                  {certificationResult.fileHash}
                </p>
              </div>
              {certificationResult.txHash && (
                <div>
                  <p className="text-sm text-muted-foreground">Transaction hash</p>
                  <p className="break-all font-mono text-sm" data-testid="text-cert-txhash">
                    {certificationResult.txHash}
                  </p>
                </div>
              )}
              {certificationResult.explorerUrl && (
                <div>
                  <Button
                    variant="outline"
                    size="sm"
                    asChild
                    data-testid="link-explorer"
                  >
                    <a
                      href={certificationResult.explorerUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <ExternalLink className="mr-2 h-4 w-4" />
                      View on explorer
                    </a>
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="flex gap-3">
            <Button
              onClick={handleDownloadPDF}
              className="flex-1"
              data-testid="button-download-pdf"
            >
              <Download className="mr-2 h-4 w-4" />
              Download PDF certificate
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setCertificationResult(null);
                setFile(null);
                setFileHash("");
                setHashProgress(0);
              }}
              data-testid="button-certify-another"
            >
              Certify another file
            </Button>
          </div>

          <div className="mt-6 text-center">
            <Button asChild variant="ghost" size="sm" data-testid="button-back-dashboard">
              <Link href="/dashboard">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to dashboard
              </Link>
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <span className="text-xl font-bold tracking-tight">xproof</span>
          </div>
          <Button asChild variant="ghost" size="sm" data-testid="button-back-dashboard">
            <Link href="/dashboard">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to dashboard
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-3xl py-12">
        <div className="mb-8">
          <h1 className="mb-2 text-3xl font-bold tracking-tight">Certify your file</h1>
          <p className="text-muted-foreground">
            Drop any file to create an immutable proof on the blockchain
          </p>
        </div>

        {!isWalletConnected && (
          <Alert variant="destructive" className="mb-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Wallet disconnected</AlertTitle>
            <AlertDescription className="flex flex-col gap-3">
              <span>
                Your wallet session has expired. Reconnect to sign transactions.
              </span>
              <Button 
                onClick={() => setShowWalletModal(true)}
                variant="outline"
                size="sm"
                className="w-fit"
                data-testid="button-reconnect-wallet"
              >
                <Wallet className="mr-2 h-4 w-4" />
                Reconnect wallet
              </Button>
            </AlertDescription>
          </Alert>
        )}

        <WalletLoginModal 
          open={showWalletModal} 
          onOpenChange={setShowWalletModal} 
        />

        <form onSubmit={handleSubmit} className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>File selection</CardTitle>
            </CardHeader>
            <CardContent>
              {!file ? (
                <div
                  onDrop={handleDrop}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  className={`relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 transition-colors ${
                    isDragging
                      ? "border-primary bg-primary/5"
                      : "border-border hover:border-primary/50"
                  }`}
                >
                  <Upload className={`mb-4 h-12 w-12 ${isDragging ? "text-primary" : "text-muted-foreground"}`} />
                  <p className="mb-2 text-center text-sm font-medium">
                    Drop your file here or click to browse
                  </p>
                  <p className="mb-4 text-center text-xs text-muted-foreground">
                    Supported formats: Images, PDF, Documents, Audio, Video
                  </p>
                  <Input
                    type="file"
                    onChange={(e) => {
                      const selectedFile = e.target.files?.[0];
                      if (selectedFile) handleFileSelect(selectedFile);
                    }}
                    className="absolute inset-0 cursor-pointer opacity-0"
                    data-testid="input-file-upload"
                  />
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-4 rounded-lg border bg-muted/30 p-4">
                    <File className="h-10 w-10 text-primary" />
                    <div className="flex-1 min-w-0">
                      <p className="font-medium truncate" data-testid="text-selected-filename">
                        {file.name}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {(file.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                    {isHashing ? (
                      <Loader2 className="h-5 w-5 animate-spin text-primary" />
                    ) : (
                      <CheckCircle className="h-5 w-5 text-chart-2" />
                    )}
                  </div>
                  
                  {isHashing && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Computing SHA-256 hash...</span>
                        <span className="font-medium">{hashProgress}%</span>
                      </div>
                      <Progress value={hashProgress} className="h-2" />
                    </div>
                  )}

                  {fileHash && !isHashing && (
                    <div className="rounded-lg bg-muted/30 p-3">
                      <p className="mb-1 text-xs font-medium text-muted-foreground">File fingerprint</p>
                      <p className="break-all font-mono text-sm" data-testid="text-file-hash">
                        {fileHash}
                      </p>
                    </div>
                  )}

                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setFile(null);
                      setFileHash("");
                      setHashProgress(0);
                    }}
                    data-testid="button-clear-file"
                  >
                    Choose another file
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {file && fileHash && (
            <Card>
              <CardHeader>
                <CardTitle>Author information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="authorName">Your name *</Label>
                  <Input
                    id="authorName"
                    value={authorName}
                    onChange={(e) => setAuthorName(e.target.value)}
                    placeholder="Enter your name"
                    required
                    data-testid="input-author-name"
                  />
                  <p className="text-xs text-muted-foreground">
                    This name will appear on your certificate
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {file && fileHash && (
            <div className="flex justify-end gap-3">
              <Button
                type="button"
                variant="outline"
                asChild
                data-testid="button-cancel"
              >
                <Link href="/dashboard">Cancel</Link>
              </Button>
              <Button
                type="submit"
                disabled={!authorName || isSigning || !isWalletConnected}
                data-testid="button-certify-submit"
              >
                {isSigning ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {signatureStep || "Processing..."}
                  </>
                ) : !isWalletConnected ? (
                  <>
                    <AlertTriangle className="mr-2 h-4 w-4" />
                    Wallet not connected
                  </>
                ) : (
                  <>
                    <Wallet className="mr-2 h-4 w-4" />
                    Sign and certify
                  </>
                )}
              </Button>
            </div>
          )}
        </form>
      </div>
    </div>
  );
}
