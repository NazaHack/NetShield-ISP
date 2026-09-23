"use client";

import { AlertTriangle, RotateCcw } from "lucide-react";
import { useEffect, type JSX } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Error boundary for the console.
 *
 * The message is deliberately generic. A failure here usually carries an API
 * response or a connection string in its text, and this page is rendered in a
 * browser that may not belong to the operator any more.
 */
export default function ConsoleError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}): JSX.Element {
  useEffect(() => {
    // The digest correlates this page with the full server-side log entry.
    console.error("console.render_failed", error.digest);
  }, [error]);

  return (
    <main className="container flex flex-col items-center justify-center py-24">
      <Card className="max-w-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="size-5 text-severity-high" aria-hidden="true" />
            Something went wrong
          </CardTitle>
          <CardDescription>
            The console could not load this view. The server logged the details
            {error.digest ? ` under reference ${error.digest}` : ""}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button type="button" onClick={reset} variant="outline" className="gap-2">
            <RotateCcw className="size-4" aria-hidden="true" />
            Try again
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
