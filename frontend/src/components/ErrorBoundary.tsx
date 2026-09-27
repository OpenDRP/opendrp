import { Component, type ReactNode, type ErrorInfo } from "react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
  /** Optional custom fallback. If omitted, a built-in recovery screen is shown. */
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Catches unhandled render errors anywhere in the component tree.
 * Without this, any thrown error during render will unmount everything
 * and produce a blank white screen with no message.
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Log to console so developers can see the stack trace.
    console.error("[ErrorBoundary] Caught unhandled error:", error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div className="min-h-screen flex items-center justify-center bg-background p-6">
          <div className="max-w-lg w-full text-center space-y-5 p-8 border border-destructive/30 rounded-2xl bg-card shadow-lg">
            <div className="mx-auto w-16 h-16 rounded-full bg-destructive/10 flex items-center justify-center">
              <svg className="w-8 h-8 text-destructive" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Something went wrong</h1>
              <p className="mt-1 text-sm text-muted-foreground">
                An unexpected error occurred. You can try to recover or reload the page.
              </p>
            </div>
            {
              /* Raw framework errors are a developer aid, not operator
                 information: a minified React message with a reactjs.org link
                 tells an operator nothing and leaks implementation details. */
              import.meta.env.DEV && this.state.error && (
                <pre className="text-left text-xs bg-muted/50 rounded-md p-3 overflow-auto max-h-36 text-destructive border border-destructive/20">
                  {this.state.error.message}
                </pre>
              )
            }
            <div className="flex justify-center gap-3">
              <Button type="button" variant="outline" onClick={this.handleReset}>
                Try again
              </Button>
              <Button type="button" onClick={() => (location.href = "/dashboard")}>
                Go to Dashboard
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
