/**
 * Skill Scanner — scans OpenClaw skill directories for security issues.
 *
 * Two modes:
 *  1. Static analysis: regex pattern matching on source code files
 *  2. Blocklist: check skill metadata against known-malicious indicators
 */

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, extname, basename } from "node:path";
import { createHash } from "node:crypto";
import type { Rule, Finding, SkillScanResult, SkillBlocklistEntry } from "./types.js";
import { SEVERITY_WEIGHTS } from "./types.js";

// ---------------------------------------------------------------------------
// File walker
// ---------------------------------------------------------------------------

function walkDir(dir: string, filePatterns: string[]): string[] {
  const results: string[] = [];
  const extSet = new Set(filePatterns.map((p) => p.replace("*", "")));

  function walk(current: string, depth: number) {
    if (depth > 10) return; // prevent infinite recursion
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = join(current, entry.name);
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      if (entry.isDirectory()) {
        walk(fullPath, depth + 1);
      } else if (entry.isFile()) {
        if (extSet.size === 0 || extSet.has(extname(entry.name))) {
          results.push(fullPath);
        }
      }
    }
  }

  walk(dir, 0);
  return results;
}

// ---------------------------------------------------------------------------
// Static analysis
// ---------------------------------------------------------------------------

export function scanSkillStatic(
  skillDir: string,
  rules: Rule[],
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    if (rule.check?.type !== "code_pattern") continue;

    const check = rule.check as {
      type: "code_pattern";
      patterns: string[];
      file_patterns?: string[];
    };

    const filePatterns = check.file_patterns ?? ["*.ts", "*.js", "*.py", "*.json", "*.sh"];
    const files = walkDir(skillDir, filePatterns);

    for (const filePath of files) {
      let content: string;
      try {
        content = readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      for (const pattern of check.patterns) {
        const regex = new RegExp(pattern, "gi");
        const matches = content.match(regex);
        if (matches && matches.length > 0) {
          const relPath = filePath.slice(skillDir.length + 1);
          findings.push({
            id: rule.id,
            severity: rule.severity,
            title: `${rule.title} in ${relPath}`,
            description: rule.description,
            recommendation: rule.recommendation,
            config_path: relPath,
            auto_fixable: false,
            points: SEVERITY_WEIGHTS[rule.severity] ?? 0,
            context: `${relPath}: ${matches.length} match(es) for ${pattern}`,
          });
          break; // one finding per rule per file
        }
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Blocklist check
// ---------------------------------------------------------------------------

export function checkSkillBlocklist(
  skillDir: string,
  blocklist: SkillBlocklistEntry[],
  metadata?: { author?: string; name?: string },
): { blocked: boolean; reason: string; entry?: SkillBlocklistEntry } {
  // Check author
  if (metadata?.author) {
    for (const entry of blocklist) {
      if (entry.indicators.authors?.includes(metadata.author.toLowerCase())) {
        return {
          blocked: true,
          reason: `Author '${metadata.author}' is on the blocklist: ${entry.title}`,
          entry,
        };
      }
    }
  }

  // Check skill name
  if (metadata?.name) {
    for (const entry of blocklist) {
      if (entry.indicators.skill_names?.some((n) => metadata.name!.toLowerCase().includes(n.toLowerCase()))) {
        return {
          blocked: true,
          reason: `Skill name '${metadata.name}' matches blocklist: ${entry.title}`,
          entry,
        };
      }
    }
  }

  // Check file hashes
  const files = walkDir(skillDir, []);
  for (const filePath of files) {
    let content: Buffer;
    try {
      content = readFileSync(filePath) as unknown as Buffer;
    } catch {
      continue;
    }
    const hash = createHash("sha256").update(content).digest("hex");

    for (const entry of blocklist) {
      if (entry.indicators.sha256_hashes?.includes(hash)) {
        const relPath = filePath.slice(skillDir.length + 1);
        return {
          blocked: true,
          reason: `File ${relPath} matches known-malicious hash: ${entry.title}`,
          entry,
        };
      }
    }
  }

  // Check for C2 IPs and domains in source code
  const sourceFiles = walkDir(skillDir, ["*.ts", "*.js", "*.py", "*.json", "*.sh", "*.yaml", "*.yml"]);
  for (const filePath of sourceFiles) {
    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    for (const entry of blocklist) {
      for (const ip of entry.indicators.c2_ips ?? []) {
        if (content.includes(ip)) {
          const relPath = filePath.slice(skillDir.length + 1);
          return {
            blocked: true,
            reason: `File ${relPath} contains known C2 IP ${ip}: ${entry.title}`,
            entry,
          };
        }
      }
      for (const domain of entry.indicators.domains ?? []) {
        if (content.includes(domain)) {
          const relPath = filePath.slice(skillDir.length + 1);
          return {
            blocked: true,
            reason: `File ${relPath} contacts known malicious domain ${domain}: ${entry.title}`,
            entry,
          };
        }
      }
    }
  }

  return { blocked: false, reason: "" };
}

// ---------------------------------------------------------------------------
// Full scan
// ---------------------------------------------------------------------------

export function scanSkill(
  skillDir: string,
  staticRules: Rule[],
  blocklist: SkillBlocklistEntry[],
  metadata?: { author?: string; name?: string },
): SkillScanResult {
  // 1. Check blocklist first (fast reject)
  const blockResult = checkSkillBlocklist(skillDir, blocklist, metadata);

  // 2. Static analysis
  const findings = scanSkillStatic(skillDir, staticRules);

  // 3. Count files
  const allFiles = walkDir(skillDir, []);

  return {
    skill_path: skillDir,
    findings,
    files_scanned: allFiles.length,
    blocked: blockResult.blocked,
    block_reason: blockResult.reason || undefined,
    scanned_at: new Date().toISOString(),
  };
}
