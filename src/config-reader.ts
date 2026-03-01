import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

/**
 * Find and read an OpenClaw gateway config file.
 *
 * Search order:
 *   1. Explicit path (--config flag)
 *   2. ~/.openclaw/openclaw.json
 *   3. ./openclaw.json (current directory)
 */
export function readConfig(explicitPath?: string): { config: Record<string, unknown>; path: string } {
  const candidates = explicitPath
    ? [explicitPath]
    : [
        join(homedir(), ".openclaw", "openclaw.json"),
        join(process.cwd(), "openclaw.json"),
      ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      const raw = readFileSync(candidate, "utf-8");
      const config = JSON.parse(raw) as Record<string, unknown>;
      return { config, path: candidate };
    }
  }

  throw new Error(
    `OpenClaw config not found. Searched:\n${candidates.map((c) => `  - ${c}`).join("\n")}\n\nUse --config to specify the path.`,
  );
}
