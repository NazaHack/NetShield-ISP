import { SearchX } from "lucide-react";
import Link from "next/link";
import type { JSX } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * Shown when a client, scan or range is not available.
 *
 * The API answers "does not exist" and "belongs to another client" identically,
 * and so does this page: distinguishing them would let one client confirm
 * another's resources exist.
 */
export default function ConsoleNotFound(): JSX.Element {
  return (
    <main className="container flex flex-col items-center justify-center py-24">
      <Card className="max-w-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SearchX className="size-5 text-muted-foreground" aria-hidden="true" />
            Not found
          </CardTitle>
          <CardDescription>
            This resource does not exist, or it is not one this session may open.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline">
            <Link href="/">Back to the console</Link>
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
