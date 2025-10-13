import { useState, useCallback, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Shield, Upload, File, CheckCircle, Loader2, ArrowLeft } from "lucide-react";
import { computeFileHash } from "@/lib/hashUtils";
import { Link, useLocation } from "wouter";

interface CertificationData {
  fileName: string;
  fileHash: string;
  fileType: string;
  fileSize: number;
  authorName: string;
  authorSignature?: string;
}

export default function Certify() {
  const { toast } = useToast();
  const { user, isLoading: authLoading, isAuthenticated } = useAuth();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();

  const [file, setFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string>("");
  const [authorName, setAuthorName] = useState<string>("");
  const [authorSignature, setAuthorSignature] = useState<string>("");
  const [isHashing, setIsHashing] = useState(false);
  const [hashProgress, setHashProgress] = useState(0);
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, authLoading, toast]);

  useEffect(() => {
    if (user?.firstName && user?.lastName) {
      setAuthorName(`${user.firstName} ${user.lastName}`);
    } else if (user?.email) {
      setAuthorName(user.email);
    }
  }, [user]);

  const certifyMutation = useMutation({
    mutationFn: async (data: CertificationData) => {
      const response = await apiRequest("POST", "/api/certifications", data);
      return response;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/certifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      toast({
        title: "Success!",
        description: "Your file has been certified on the blockchain",
      });
      setLocation("/dashboard");
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
      // Simulate progress for better UX
      const progressInterval = setInterval(() => {
        setHashProgress((prev) => Math.min(prev + 10, 90));
      }, 100);

      const hash = await computeFileHash(selectedFile);
      
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

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!file || !fileHash || !authorName) {
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields",
        variant: "destructive",
      });
      return;
    }

    certifyMutation.mutate({
      fileName: file.name,
      fileHash,
      fileType: file.type || "unknown",
      fileSize: file.size,
      authorName,
      authorSignature: authorSignature || undefined,
    });
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

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
          <Button asChild variant="ghost" size="sm" data-testid="button-back-dashboard">
            <Link href="/dashboard">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Dashboard
            </Link>
          </Button>
        </div>
      </header>

      <div className="container mx-auto max-w-3xl px-6 py-12">
        <div className="mb-8">
          <h1 className="mb-2 text-3xl font-bold tracking-tight">Certify Your File</h1>
          <p className="text-muted-foreground">
            Upload any file to create an immutable proof of ownership on the blockchain
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* File Upload */}
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

          {/* Author Information */}
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
                </div>
                <div className="space-y-2">
                  <Label htmlFor="authorSignature">Digital Signature (Optional)</Label>
                  <Input
                    id="authorSignature"
                    value={authorSignature}
                    onChange={(e) => setAuthorSignature(e.target.value)}
                    placeholder="e.g., © 2024 Your Name"
                    data-testid="input-author-signature"
                  />
                  <p className="text-xs text-muted-foreground">
                    This will appear on your certificate
                  </p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Submit */}
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
                disabled={!authorName || certifyMutation.isPending}
                data-testid="button-certify-submit"
              >
                {certifyMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Certifying...
                  </>
                ) : (
                  <>
                    <Shield className="mr-2 h-4 w-4" />
                    Certify on Blockchain
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
