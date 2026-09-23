"use client";

import type { JSX } from "react";

import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SCAN_PROFILES, type ScanProfile } from "@/lib/api/types";

/**
 * Chooses how thorough a scan is, and therefore how long it takes.
 *
 * The value is submitted as a plain form field named ``profile`` inside the
 * launch form, so the server action reads it with the rest of the payload and
 * no client state has to be lifted anywhere.
 *
 * The controls are uncontrolled: a hidden input carries the selected value into
 * the form, and the visible Select updates it. This keeps the whole thing
 * inside one native form submission, which is how every other panel here works.
 */
export function ProfileSelect({
  name = "profile",
  defaultValue = "balanced",
}: {
  name?: string;
  defaultValue?: ScanProfile;
}): JSX.Element {
  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={`${name}-trigger`}>Profundidad</Label>
      <Select name={name} defaultValue={defaultValue}>
        <SelectTrigger id={`${name}-trigger`} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {SCAN_PROFILES.map((profile) => (
            <SelectItem key={profile.value} value={profile.value}>
              <span className="flex flex-col">
                <span>{profile.label}</span>
                <span className="text-xs text-muted-foreground">{profile.hint}</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
