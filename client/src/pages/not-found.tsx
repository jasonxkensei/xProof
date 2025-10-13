import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Shield, Home } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-6">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center py-16 text-center">
          <Shield className="mb-4 h-16 w-16 text-muted-foreground/50" />
          <h1 className="mb-2 text-4xl font-bold">404</h1>
          <p className="mb-6 text-muted-foreground">
            The page you're looking for doesn't exist
          </p>
          <Button asChild data-testid="button-go-home">
            <a href="/">
              <Home className="mr-2 h-4 w-4" />
              Go Home
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
