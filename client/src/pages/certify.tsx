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
        title: "Certification Failed",
        description: error.message || "An error occurred while certifying your file",
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
        description: "Failed to compute file hash",
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
        title: "Missing Information",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    if (!user?.walletAddress) {
      toast({
        title: "Wallet Required",
        description: "Please connect your wallet to certify files",
        variant: "destructive",
      });
      return;
    }

    setIsSigning(true);
    setSignatureStep("Creating transaction...");

    try {
      setSignatureStep("Check your wallet to sign (enter 2FA code if enabled)...");
      
      const txResult = await sendCertificationTransaction({
        userAddress: user.walletAddress,
        fileHash,
        fileName: file.name,
        authorName,
      });

      setSignatureStep("Saving certification...");

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
        description: "Your file has been certified on the MultiversX Mainnet blockchain",
      });
    } catch (error: any) {
      console.error("Certification error:", error);
      toast({
        title: "Certification Failed",
        description: error.message || "An error occurred while certifying your file",
        variant: "destructive",
      });
    } finally {
      setIsSigning(false);
      setSignatureStep("");
    }
  };

  const handleDownloadPDF = async () => {
    if (!certificationResult || !file) return;

    await generateProofPDF({
      fileName: file.name,
      fileHash: certificationResult.fileHash,
      txHash: certificationResult.txHash || "",
      explorerUrl: certificationResult.explorerUrl || "",
      authorName: certificationResult.authorName,
      certificationDate: new Date().toLocaleDateString(),
    });

    toast({
      title: "PDF Downloaded",
      description: "Your certificate has been saved",
    });
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
              <span className="text-xl font-bold tracking-tight">ProofMint</span>
            </div>
          </div>
        </header>

        <div className="container mx-auto max-w-3xl py-12">
          <div className="text-center">
            <div className="mb-6 inline-flex h-20 w-20 items-center justify-center rounded-full bg-primary/10">
              <CheckCircle className="h-10 w-10 text-primary" />
            </div>
            <h1 className="mb-4 text-3xl font-bold tracking-tight">Certification Successful!</h1>
            <p className="mb-8 text-muted-foreground">
              Your file has been certified on the MultiversX blockchain
            </p>
          </div>

          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Certification Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground">File Name</p>
                <p className="font-medium" data-testid="text-cert-filename">{certificationResult.fileName}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">SHA-256 Hash</p>
                <p className="break-all font-mono text-sm" data-testid="text-cert-hash">
                  {certificationResult.fileHash}
                </p>
              </div>
              {certificationResult.txHash && (
                <div>
                  <p className="text-sm text-muted-foreground">Transaction Hash</p>
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
                      View on Explorer
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
              Download Certificate PDF
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
              Certify Another File
            </Button>
          </div>

          <div className="mt-6 text-center">
            <Button asChild variant="ghost" size="sm" data-testid="button-back-dashboard">
              <Link href="/dashboard">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to Dashboard
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
            <span className="text-xl font-bold tracking-tight">ProofMint</span>
          </div>
          <Button asChild variant="ghost" size="sm" data-testid="button-back-dashboard">
            <Link href="/dashboard">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-3xl py-12">
        <div className="mb-8">
          <h1 className="mb-2 text-3xl font-bold tracking-tight">Certify Your File</h1>
          <p className="text-muted-foreground">
            Upload any file to create an immutable proof of ownership on the blockchain
          </p>
        </div>

        {!isWalletConnected && (
          <Alert variant="destructive" className="mb-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Wallet Disconnected</AlertTitle>
            <AlertDescription className="flex flex-col gap-3">
              <span>
                Your wallet session has expired. You need to reconnect your wallet to sign transactions.
              </span>
              <Button 
                onClick={() => setShowWalletModal(true)}
                variant="outline"
                size="sm"
                className="w-fit"
                data-testid="button-reconnect-wallet"
              >
                <Wallet className="mr-2 h-4 w-4" />
                Reconnect Wallet
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
              <CardTitle>Upload File</CardTitle>
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
                    Supports: Images, PDFs, Documents, Audio, Video
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
                      <p className="mb-1 text-xs font-medium text-muted-foreground">File Hash</p>
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
                    Choose Different File
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {file && fileHash && (
            <Card>
              <CardHeader>
                <CardTitle>Author Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="authorName">Your Name *</Label>
                  <Input
                    id="authorName"
                    value={authorName}
                    onChange={(e) => setAuthorName(e.target.value)}
                    placeholder="Enter your name"
                    required
                    data-testid="input-author-name"
                  />
                  <p className="text-xs text-muted-foreground">
                    This will appear on your certificate
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
                    Wallet Not Connected
                  </>
                ) : (
                  <>
                    <Wallet className="mr-2 h-4 w-4" />
                    Sign & Certify on Mainnet
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
