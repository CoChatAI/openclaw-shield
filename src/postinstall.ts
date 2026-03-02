#!/usr/bin/env node

/**
 * Postinstall script — fetches advisory data from jgamblin/OpenClawCVEs
 * and caches it to ~/.openclaw-carapace/cache/ so the first `audit` run
 * has vulnerability data available immediately.
 *
 * Failures are silent — this is a best-effort warm-up.
 */

import { writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const GHSA_URL =
  "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/ghsa-advisories.json";
const CVES_URL =
  "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/cves.json";

const CACHE_DIR = join(homedir(), ".openclaw-carapace", "cache");
const GHSA_CACHE_FILE = join(CACHE_DIR, "ghsa-advisories.json");
const CVES_CACHE_FILE = join(CACHE_DIR, "cves.json");

const FETCH_TIMEOUT_MS = 5000;

async function fetchAndCache(url: string, cachePath: string): Promise<number> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    const data = JSON.parse(text);
    writeFileSync(cachePath, text, "utf-8");
    return Array.isArray(data) ? data.length : 0;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function main() {
  try {
    if (!existsSync(CACHE_DIR)) {
      mkdirSync(CACHE_DIR, { recursive: true });
    }

    const [ghsaCount, cveCount] = await Promise.all([
      fetchAndCache(GHSA_URL, GHSA_CACHE_FILE),
      fetchAndCache(CVES_URL, CVES_CACHE_FILE),
    ]);

    console.log(
      `  🦞 openclaw-carapace: cached ${ghsaCount} advisories and ${cveCount} CVEs`,
    );
  } catch {
    // Silent failure — network may not be available during install
    // The CLI will fetch on first run instead
  }
}

main();
