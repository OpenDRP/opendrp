import { useEffect } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert, ArrowLeft } from "lucide-react";
import { APP_NAME } from "@/lib/appMeta";
import { Button } from "@/components/ui/button";

export default function NotFoundPage() {
  useEffect(() => {
    document.title = `Page not found · ${APP_NAME}`;
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-6">
      <div className="max-w-md w-full text-center space-y-6 p-8 border border-border rounded-2xl bg-card shadow-xl animate-in">
        <div className="mx-auto w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center">
          <ShieldAlert className="w-10 h-10 text-primary" />
        </div>
        <div className="space-y-2">
          <div className="text-7xl font-black tracking-tighter text-foreground/10 leading-none">404</div>
          <h1 className="text-2xl font-bold text-foreground">Page not found</h1>
          <p className="text-muted-foreground text-sm leading-relaxed">
            The page you are looking for either does not exist or has been moved.
            Check the URL or return to the dashboard.
          </p>
        </div>
        <div className="flex flex-col sm:flex-row gap-2 justify-center pt-2">
          <Button asChild>
            <Link to="/dashboard">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Go to Dashboard
            </Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/login">Sign in page</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
