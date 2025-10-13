import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Shield, ArrowLeft, Building2, Image as ImageIcon } from "lucide-react";
import { Link } from "wouter";

const brandingSchema = z.object({
  companyName: z.string().min(1, "Company name is required").max(100),
  companyLogoUrl: z.string().url("Please enter a valid URL").optional().or(z.literal("")),
});

type BrandingFormData = z.infer<typeof brandingSchema>;

export default function Settings() {
  const { toast } = useToast();
  const { user, isLoading: authLoading, isAuthenticated } = useAuth();
  const queryClient = useQueryClient();

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

  const form = useForm<BrandingFormData>({
    resolver: zodResolver(brandingSchema),
    defaultValues: {
      companyName: user?.companyName || "",
      companyLogoUrl: user?.companyLogoUrl || "",
    },
  });

  // Update form when user data loads
  useEffect(() => {
    if (user) {
      form.reset({
        companyName: user.companyName || "",
        companyLogoUrl: user.companyLogoUrl || "",
      });
    }
  }, [user, form]);

  const updateBrandingMutation = useMutation({
    mutationFn: async (data: BrandingFormData) => {
      return await apiRequest("PATCH", "/api/user/branding", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      toast({
        title: "Branding Updated",
        description: "Your custom branding has been saved successfully.",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Update Failed",
        description: error.message || "Failed to update branding settings",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: BrandingFormData) => {
    updateBrandingMutation.mutate(data);
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  const isBusinessTier = user?.subscriptionTier === "business";

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

      <div className="container mx-auto max-w-4xl px-6 py-12">
        <div className="mb-8">
          <h1 className="mb-2 text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-muted-foreground">
            Manage your account and certificate branding
          </p>
        </div>

        {/* Account Information */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Account Information</CardTitle>
            <CardDescription>Your ProofMint account details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium">Email</label>
              <p className="text-sm text-muted-foreground">{user?.email || "Not set"}</p>
            </div>
            <div>
              <label className="text-sm font-medium">Name</label>
              <p className="text-sm text-muted-foreground">
                {user?.firstName || user?.lastName
                  ? `${user?.firstName || ""} ${user?.lastName || ""}`.trim()
                  : "Not set"}
              </p>
            </div>
            <div>
              <label className="text-sm font-medium">Subscription Tier</label>
              <p className="text-sm font-medium capitalize">{user?.subscriptionTier || "free"}</p>
            </div>
          </CardContent>
        </Card>

        {/* Custom Branding (Business Tier Only) */}
        {isBusinessTier ? (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5" />
                Custom Branding
              </CardTitle>
              <CardDescription>
                Add your company branding to certificates (Business tier feature)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                  <FormField
                    control={form.control}
                    name="companyName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Company Name</FormLabel>
                        <FormControl>
                          <Input
                            placeholder="Acme Corporation"
                            {...field}
                            data-testid="input-company-name"
                          />
                        </FormControl>
                        <FormDescription>
                          This will appear on your certificates as "Certified by [Company Name]"
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="companyLogoUrl"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Company Logo URL (Optional)</FormLabel>
                        <FormControl>
                          <div className="flex gap-2">
                            <ImageIcon className="h-4 w-4 mt-3 text-muted-foreground" />
                            <Input
                              placeholder="https://example.com/logo.png"
                              {...field}
                              data-testid="input-company-logo-url"
                            />
                          </div>
                        </FormControl>
                        <FormDescription>
                          Enter a public URL to your company logo (coming soon)
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button
                    type="submit"
                    disabled={updateBrandingMutation.isPending}
                    data-testid="button-save-branding"
                  >
                    {updateBrandingMutation.isPending ? "Saving..." : "Save Branding"}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5" />
                Custom Branding
              </CardTitle>
              <CardDescription>
                Add your company branding to certificates
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="mb-4 text-sm text-muted-foreground">
                Custom branding is available on the Business tier. Upgrade to add your company name and logo to all certificates.
              </p>
              <Button asChild variant="default" data-testid="button-upgrade-for-branding">
                <Link href="/pricing">Upgrade to Business</Link>
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
