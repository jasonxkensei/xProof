import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Key, Plus, Trash2, RefreshCw, Copy, CheckCircle, AlertTriangle } from "lucide-react";
import { format } from "date-fns";

interface ApiKey {
  id: string;
  prefix: string;
  name: string;
  requestCount: number;
  lastUsedAt: string | null;
  isActive: boolean;
  createdAt: string;
}

interface KeyRevealState {
  open: boolean;
  key: string;
  title: string;
  description: string;
  warningText?: string;
}

function KeyRevealDialog({
  state,
  onClose,
}: {
  state: KeyRevealState;
  onClose: () => void;
}) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(state.key);
      setCopied(true);
      toast({ title: "Copied!", description: "API key copied to clipboard." });
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast({ title: "Copy failed", description: "Please copy the key manually.", variant: "destructive" });
    }
  };

  return (
    <Dialog open={state.open} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="sm:max-w-md" data-testid="dialog-key-reveal">
        <DialogHeader>
          <DialogTitle>{state.title}</DialogTitle>
          <DialogDescription>{state.description}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="flex items-center gap-2 rounded-md border bg-muted p-3">
            <code
              className="flex-1 break-all text-xs font-mono select-all"
              data-testid="text-api-key-value"
            >
              {state.key}
            </code>
            <Button
              size="icon"
              variant="ghost"
              onClick={handleCopy}
              data-testid="button-copy-api-key"
              className="shrink-0"
            >
              {copied ? (
                <CheckCircle className="h-4 w-4 text-chart-2" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>

          <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30 p-3 text-sm">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
            <p className="text-amber-800 dark:text-amber-300">
              {state.warningText || "This key won't be shown again. Save it somewhere secure before closing."}
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onClose} data-testid="button-close-key-reveal">
            I've saved my key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ApiKeysSection() {
  const { toast } = useToast();

  const [createOpen, setCreateOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [keyReveal, setKeyReveal] = useState<KeyRevealState>({
    open: false,
    key: "",
    title: "",
    description: "",
  });

  const { data, isLoading } = useQuery<{ keys: ApiKey[] }>({
    queryKey: ["/api/keys"],
  });

  const keys = data?.keys ?? [];

  const createMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await apiRequest("POST", "/api/keys", { name });
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
      setCreateOpen(false);
      setNewKeyName("");
      setKeyReveal({
        open: true,
        key: data.key,
        title: "API key created",
        description: `Your new API key "${data.name}" is ready. Copy it now — it won't be shown again.`,
      });
    },
    onError: (err: Error) => {
      toast({
        title: "Failed to create key",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (keyId: string) => {
      const res = await apiRequest("DELETE", `/api/keys/${keyId}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
      setDeleteTargetId(null);
      toast({ title: "Key deleted", description: "The API key has been permanently deleted." });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete key", description: err.message, variant: "destructive" });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: async (keyId: string) => {
      const res = await apiRequest("POST", `/api/keys/${keyId}/rotate`);
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/keys"] });
      setKeyReveal({
        open: true,
        key: data.key,
        title: "API key rotated",
        description: "A new key has been generated. Your previous key remains valid for 24 hours to give you time to update your agents.",
        warningText: "Copy this key now — it won't be shown again. Your old key expires in 24 hours.",
      });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to rotate key", description: err.message, variant: "destructive" });
    },
  });

  const handleCreate = () => {
    const name = newKeyName.trim();
    if (!name) return;
    createMutation.mutate(name);
  };

  const deleteTarget = keys.find((k) => k.id === deleteTargetId);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-semibold">API Keys</h2>
          <p className="text-sm text-muted-foreground">
            Use these keys to authenticate your agents via{" "}
            <code className="text-xs font-mono bg-muted px-1 py-0.5 rounded">Authorization: Bearer pm_...</code>
          </p>
        </div>
        <Button
          size="sm"
          onClick={() => setCreateOpen(true)}
          data-testid="button-create-api-key"
        >
          <Plus className="h-4 w-4 mr-2" />
          New key
        </Button>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[1, 2].map((i) => (
            <div key={i} className="h-20 rounded-lg bg-muted animate-pulse" />
          ))}
        </div>
      ) : keys.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Key className="mb-3 h-10 w-10 text-muted-foreground/50" />
            <h3 className="mb-1 font-semibold">No API keys yet</h3>
            <p className="mb-4 text-sm text-muted-foreground max-w-xs">
              Create an API key to authenticate your agents and automate certifications.
            </p>
            <Button size="sm" onClick={() => setCreateOpen(true)} data-testid="button-create-first-api-key">
              <Plus className="h-4 w-4 mr-2" />
              Create my first key
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {keys.map((apiKey) => (
            <Card key={apiKey.id} data-testid={`card-api-key-${apiKey.id}`}>
              <CardContent className="p-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-medium text-sm" data-testid={`text-key-name-${apiKey.id}`}>
                        {apiKey.name}
                      </span>
                      <Badge
                        variant={apiKey.isActive ? "default" : "secondary"}
                        className={apiKey.isActive ? "bg-chart-2 hover:bg-chart-2" : ""}
                        data-testid={`badge-key-status-${apiKey.id}`}
                      >
                        {apiKey.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                    <div className="flex flex-col gap-0.5 text-xs text-muted-foreground">
                      <span className="font-mono" data-testid={`text-key-prefix-${apiKey.id}`}>
                        {apiKey.prefix}
                      </span>
                      <span data-testid={`text-key-usage-${apiKey.id}`}>
                        {apiKey.requestCount ?? 0} request{(apiKey.requestCount ?? 0) !== 1 ? "s" : ""} ·{" "}
                        Created {format(new Date(apiKey.createdAt), "MMM d, yyyy")}
                        {apiKey.lastUsedAt
                          ? ` · Last used ${format(new Date(apiKey.lastUsedAt), "MMM d, yyyy")}`
                          : " · Never used"}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => rotateMutation.mutate(apiKey.id)}
                      disabled={rotateMutation.isPending || !apiKey.isActive}
                      data-testid={`button-rotate-key-${apiKey.id}`}
                    >
                      <RefreshCw className={`h-4 w-4 sm:mr-2 ${rotateMutation.isPending ? "animate-spin" : ""}`} />
                      <span className="hidden sm:inline">Rotate</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setDeleteTargetId(apiKey.id)}
                      disabled={deleteMutation.isPending}
                      data-testid={`button-delete-key-${apiKey.id}`}
                    >
                      <Trash2 className="h-4 w-4 sm:mr-2 text-destructive" />
                      <span className="hidden sm:inline text-destructive">Delete</span>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create key dialog */}
      <Dialog open={createOpen} onOpenChange={(open) => { if (!open) { setCreateOpen(false); setNewKeyName(""); } }}>
        <DialogContent className="sm:max-w-md" data-testid="dialog-create-api-key">
          <DialogHeader>
            <DialogTitle>Create API key</DialogTitle>
            <DialogDescription>
              Give your key a name to identify which agent or integration is using it.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="key-name">Key name</Label>
            <Input
              id="key-name"
              placeholder="e.g. My LangChain agent"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleCreate(); }}
              data-testid="input-api-key-name"
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setCreateOpen(false); setNewKeyName(""); }} data-testid="button-cancel-create-key">
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!newKeyName.trim() || createMutation.isPending}
              data-testid="button-confirm-create-key"
            >
              {createMutation.isPending ? "Creating..." : "Create key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation dialog */}
      <AlertDialog open={!!deleteTargetId} onOpenChange={(open) => { if (!open) setDeleteTargetId(null); }}>
        <AlertDialogContent data-testid="dialog-confirm-delete-key">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete API key?</AlertDialogTitle>
            <AlertDialogDescription>
              The key <strong>{deleteTarget?.name}</strong>{" "}
              (<code className="font-mono text-xs">{deleteTarget?.prefix}</code>) will be permanently
              deleted. Any agent using it will immediately lose access.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="button-cancel-delete-key">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteTargetId && deleteMutation.mutate(deleteTargetId)}
              data-testid="button-confirm-delete-key"
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete key"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Key reveal dialog */}
      <KeyRevealDialog
        state={keyReveal}
        onClose={() => setKeyReveal((s) => ({ ...s, open: false, key: "" }))}
      />
    </div>
  );
}
