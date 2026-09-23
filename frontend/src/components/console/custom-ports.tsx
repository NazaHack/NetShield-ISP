"use client";

import { useState, type JSX } from "react";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/**
 * Optional custom port specification.
 *
 * Collapsed by default so the common case stays a single dropdown. When opened,
 * the input is named ``port_range`` and, if filled, overrides the profile's own
 * port selection on the server. Left blank, the profile decides.
 *
 * The value is only sent when the field is shown *and* non-empty, so toggling
 * it closed does not accidentally submit a stale range.
 */
export function CustomPorts(): JSX.Element {
  const [open, setOpen] = useState(false);

  return (
    <div className="flex flex-col gap-2">
      <label className="flex items-center gap-2 text-sm text-muted-foreground">
        <input
          type="checkbox"
          checked={open}
          onChange={(event) => setOpen(event.target.checked)}
          className="size-4 rounded border-input"
        />
        Puertos personalizados
      </label>

      {open ? (
        <div className="flex flex-col gap-2">
          <Label htmlFor="port_range" className="sr-only">
            Custom ports
          </Label>
          <Input
            id="port_range"
            name="port_range"
            placeholder="22,80,443 o 1-1024"
            pattern="[0-9,\-]+"
            className="font-mono"
            autoComplete="off"
            spellCheck={false}
          />
          <p className="text-xs text-muted-foreground">
            Overrides the profile&apos;s ports. Digits, commas and hyphens, for example
            <span className="font-mono"> 22,80,443</span> or <span className="font-mono">1-65535</span>.
          </p>
        </div>
      ) : null}
    </div>
  );
}
