import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type {
  Rule,
  HardeningProfile,
  PatternGroup,
  PatternCatalog,
  SkillBlocklistEntry,
} from "./types.js";

// ---------------------------------------------------------------------------
// Resolve the package root (where rules/, patterns/, profiles/ live)
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = resolve(__filename, "..", "..");

function resolveDir(name: string, customDir?: string): string {
  if (customDir) return resolve(customDir);
  return join(PACKAGE_ROOT, name);
}

// ---------------------------------------------------------------------------
// YAML helpers
// ---------------------------------------------------------------------------

function loadYamlFile<T>(filePath: string): T {
  const raw = readFileSync(filePath, "utf-8");
  return parseYaml(raw) as T;
}

function loadYamlDir<T>(dirPath: string): T[] {
  if (!existsSync(dirPath)) return [];
  const results: T[] = [];
  for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
    if (
      entry.isFile() &&
      (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml"))
    ) {
      results.push(loadYamlFile<T>(join(dirPath, entry.name)));
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Rule loading
// ---------------------------------------------------------------------------

export function loadRules(rulesDir?: string): Rule[] {
  const dir = resolveDir("rules", rulesDir);
  const rules: Rule[] = [];

  for (const severity of ["critical", "high", "medium", "low"]) {
    const severityDir = join(dir, severity);
    if (!existsSync(severityDir)) continue;

    for (const rule of loadYamlDir<Rule>(severityDir)) {
      // Ensure severity from directory matches (or override)
      if (!rule.severity) {
        rule.severity = severity as Rule["severity"];
      }
      rules.push(rule);
    }
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Pattern loading
// ---------------------------------------------------------------------------

export function loadPatterns(patternsDir?: string): PatternCatalog {
  const dir = resolveDir("patterns", patternsDir);

  const dangerous = existsSync(join(dir, "dangerous.yaml"))
    ? loadYamlFile<PatternGroup>(join(dir, "dangerous.yaml"))
    : { label: "Auto-denied", description: "", patterns: [] };

  const suspicious = existsSync(join(dir, "suspicious.yaml"))
    ? loadYamlFile<PatternGroup>(join(dir, "suspicious.yaml"))
    : { label: "Flagged for review", description: "", patterns: [] };

  return { dangerous, suspicious };
}

// ---------------------------------------------------------------------------
// Profile loading
// ---------------------------------------------------------------------------

export function loadProfiles(profilesDir?: string): HardeningProfile[] {
  const dir = resolveDir("profiles", profilesDir);
  return loadYamlDir<HardeningProfile>(dir);
}

// ---------------------------------------------------------------------------
// Skill security loading
// ---------------------------------------------------------------------------

export function loadSkillRules(skillsDir?: string): Rule[] {
  const dir = skillsDir
    ? resolve(skillsDir, "static")
    : join(PACKAGE_ROOT, "skills", "static");
  if (!existsSync(dir)) return [];
  return loadYamlDir<Rule>(dir);
}

export function loadSkillBlocklist(skillsDir?: string): SkillBlocklistEntry[] {
  const dir = skillsDir
    ? resolve(skillsDir, "blocklist")
    : join(PACKAGE_ROOT, "skills", "blocklist");
  if (!existsSync(dir)) return [];
  const raw = loadYamlDir<Record<string, unknown>>(dir);
  // Normalize: indicators may be nested under check.indicators in the YAML
  return raw.map((entry) => {
    const check = entry.check as Record<string, unknown> | undefined;
    const indicators = (entry.indicators ??
      check?.indicators ??
      {}) as SkillBlocklistEntry["indicators"];
    return {
      id: entry.id as string,
      severity: entry.severity as SkillBlocklistEntry["severity"],
      title: entry.title as string,
      description: entry.description as string,
      indicators,
    };
  });
}
