/**
 * Advisory Fetcher — pulls OpenClaw CVE/GHSA data from jgamblin/OpenClawCVEs
 *
 * Sources:
 *   - ghsa-advisories.json: Full advisory list with affected_versions, fixed_versions, CWEs
 *   - cves.json: Published CVEs with CVSS scores
 *
 * Transforms each advisory into a Rule with a version_compare check so the
 * evaluation engine can match against gateway.version.
 *
 * Results are cached to disk so subsequent runs don't need network access.
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Rule, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const GHSA_URL =
  "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/ghsa-advisories.json";
const CVES_URL =
  "https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/cves.json";

const CACHE_DIR = join(homedir(), ".openclaw-carapace", "cache");
const GHSA_CACHE_FILE = join(CACHE_DIR, "ghsa-advisories.json");
const CVES_CACHE_FILE = join(CACHE_DIR, "cves.json");
const CACHE_MAX_AGE_MS = 60 * 60 * 1000; // 1 hour

// ---------------------------------------------------------------------------
// Types for the upstream JSON format
// ---------------------------------------------------------------------------

interface GHSAAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  severity: string;
  title: string;
  published: string;
  html_url: string;
  packages: string[];
  affected_versions: string[];
  fixed_versions: string[];
  fixed_version: string;
  cwes: string[];
}

interface PublishedCVE {
  cve_id: string;
  severity: string;
  cvss: number;
  title: string;
  date_published: string;
  ghsa_id: string;
}

// ---------------------------------------------------------------------------
// Fetch with caching
// ---------------------------------------------------------------------------

function isCacheFresh(cachePath: string): boolean {
  if (!existsSync(cachePath)) return false;
  try {
    const { mtimeMs } = statSync(cachePath);
    return Date.now() - mtimeMs < CACHE_MAX_AGE_MS;
  } catch {
    return false;
  }
}

async function fetchJson<T>(url: string, cachePath: string): Promise<T> {
  // Try cache first
  if (isCacheFresh(cachePath)) {
    try {
      const raw = readFileSync(cachePath, "utf-8");
      return JSON.parse(raw) as T;
    } catch {
      // Cache corrupted, re-fetch
    }
  }

  // Fetch from network
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const data = (await response.json()) as T;

    // Write to cache
    try {
      if (!existsSync(CACHE_DIR)) {
        mkdirSync(CACHE_DIR, { recursive: true });
      }
      writeFileSync(cachePath, JSON.stringify(data), "utf-8");
    } catch {
      // Cache write failure is non-fatal
    }

    return data;
  } catch (fetchErr) {
    // Network failure — try stale cache as fallback
    if (existsSync(cachePath)) {
      try {
        const raw = readFileSync(cachePath, "utf-8");
        return JSON.parse(raw) as T;
      } catch {
        // Cache also broken
      }
    }
    throw fetchErr;
  }
}

// ---------------------------------------------------------------------------
// Transform advisories into Rules
// ---------------------------------------------------------------------------

function normalizeSeverity(s: string): Severity {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "info";
}

function advisoryToRule(
  advisory: GHSAAdvisory,
  cvssMap: Map<string, number>,
): Rule | null {
  const fixedVersion = advisory.fixed_version;
  if (!fixedVersion) return null; // Can't create a version check without a fix target

  const id = advisory.cve_id || advisory.ghsa_id;
  const cvss = advisory.cve_id ? (cvssMap.get(advisory.cve_id) ?? 0) : 0;

  return {
    id: id.toLowerCase(),
    type: "vulnerability",
    severity: normalizeSeverity(advisory.severity),
    title: `${id} — ${advisory.title}`,
    description: advisory.title,
    recommendation: `Update to OpenClaw v${fixedVersion} or later.`,
    config_path: "gateway.version",
    auto_fixable: false,
    cve: advisory.cve_id || undefined,
    cvss: cvss || undefined,
    cwe: advisory.cwes?.join(", ") || undefined,
    fixed_in: fixedVersion,
    references: advisory.html_url ? [advisory.html_url] : undefined,
    confidence: "high",
    tags: ["vulnerability", advisory.cve_id ? "cve" : "ghsa"],
    check: {
      type: "version_compare",
      path: "gateway.version",
      operator: "lt",
      value: fixedVersion,
    },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function fetchAdvisoryRules(): Promise<Rule[]> {
  // Fetch both data sources
  const [advisories, cves] = await Promise.all([
    fetchJson<GHSAAdvisory[]>(GHSA_URL, GHSA_CACHE_FILE),
    fetchJson<PublishedCVE[]>(CVES_URL, CVES_CACHE_FILE),
  ]);

  // Build CVSS lookup from published CVEs
  const cvssMap = new Map<string, number>();
  for (const cve of cves) {
    if (cve.cve_id && cve.cvss) {
      cvssMap.set(cve.cve_id, cve.cvss);
    }
  }

  // Transform advisories into rules
  const rules: Rule[] = [];
  const seenIds = new Set<string>();

  for (const advisory of advisories) {
    const rule = advisoryToRule(advisory, cvssMap);
    if (!rule) continue;

    // Deduplicate (some advisories have both GHSA and CVE entries)
    if (seenIds.has(rule.id)) continue;
    seenIds.add(rule.id);

    rules.push(rule);
  }

  return rules;
}

/**
 * Load advisory rules from cache only (no network). Returns empty array if
 * no cache exists. Used as a fast synchronous fallback.
 */
export function loadCachedAdvisoryRules(): Rule[] {
  if (!existsSync(GHSA_CACHE_FILE)) return [];

  try {
    const advisories = JSON.parse(
      readFileSync(GHSA_CACHE_FILE, "utf-8"),
    ) as GHSAAdvisory[];
    let cves: PublishedCVE[] = [];
    if (existsSync(CVES_CACHE_FILE)) {
      cves = JSON.parse(
        readFileSync(CVES_CACHE_FILE, "utf-8"),
      ) as PublishedCVE[];
    }

    const cvssMap = new Map<string, number>();
    for (const cve of cves) {
      if (cve.cve_id && cve.cvss) cvssMap.set(cve.cve_id, cve.cvss);
    }

    const rules: Rule[] = [];
    const seenIds = new Set<string>();
    for (const advisory of advisories) {
      const rule = advisoryToRule(advisory, cvssMap);
      if (!rule || seenIds.has(rule.id)) continue;
      seenIds.add(rule.id);
      rules.push(rule);
    }
    return rules;
  } catch {
    return [];
  }
}
