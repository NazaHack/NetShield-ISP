"use client";

import { Loader2, LogIn, ShieldCheck } from "lucide-react";
import { useActionState, type JSX } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { signIn, type ActionResult } from "@/lib/actions";

const INITIAL: ActionResult = { ok: false };

/**
 * Sign-in page.
 *
 * Credentials are posted to a server action, which exchanges them for a bearer
 * token and stores it in an `httpOnly` cookie. The token never reaches the
 * browser, so a cross-site scripting flaw here cannot steal it.
 *
 * The failure message is identical whether the address is unknown or the
 * password wrong, so this form cannot be used to discover which addresses are
 * registered.
 */
export default function LoginPage(): JSX.Element {
  const [state, formAction, isPending] = useActionState(signIn, INITIAL);

  return (
    <main className="container flex min-h-screen items-center justify-center py-16">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-primary" aria-hidden="true" />
            NetShield-ISP
          </CardTitle>
          <CardDescription>
            Sign in to the network audit console.
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form action={formAction} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                spellCheck={false}
                placeholder="you@example.com"
                required
                autoFocus
              />
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
              />
            </div>

            {state.message && !state.ok ? (
              <Alert variant="destructive">
                <AlertTitle>Could not sign in</AlertTitle>
                <AlertDescription>{state.message}</AlertDescription>
              </Alert>
            ) : null}

            <Button type="submit" disabled={isPending} className="gap-2">
              {isPending ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <LogIn className="size-4" aria-hidden="true" />
              )}
              Sign in
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
