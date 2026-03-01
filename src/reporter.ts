import chalk from "chalk";
import type { AuditResult, Finding, HardeningProfile, PatternCatalog, SkillScanResult } from "./types.js";

// ---------------------------------------------------------------------------
// Severity colors
// ---------------------------------------------------------------------------

const SEV_COLOR: Record<string, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.yellow,
  medium: chalk.hex("#FFA500"),
  low: chalk.blue,
  info: chalk.gray,
};

const GRADE_COLOR: Record<string, (s: string) => string> = {
  A: chalk.green.bold,
  B: chalk.blue.bold,
  C: chalk.yellow.bold,
  D: chalk.hex("#FFA500").bold,
  F: chalk.red.bold,
};

// ---------------------------------------------------------------------------
// Text reporter
// ---------------------------------------------------------------------------

export function reportText(result: AuditResult): string {
  const lines: string[] = [];
  const gradeColor = GRADE_COLOR[result.grade] ?? chalk.white;
  lines.push("");
  lines.push(chalk.bold("  OpenClaw Shield Audit"));
  lines.push(chalk.gray(`  Config: ${result.config_path}`));
  lines.push(chalk.gray(`  Scanned: ${result.audited_at}`));
  lines.push(chalk.gray(`  Rules evaluated: ${result.rules_evaluated}`));
  lines.push("");
  lines.push(`  Score: ${gradeColor(result.grade)} ${chalk.bold(String(result.score))}/100`);

  if (result.findings.length === 0) {
    lines.push("");
    lines.push(chalk.green("  No issues found."));
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`  Findings: ${result.findings.length}`);
  if (result.total_fixable_points > 0) {
    lines.push(chalk.gray(`  Auto-fixable: +${result.total_fixable_points} pts recoverable`));
  }
  lines.push("");

  const bySev = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const group = bySev.get(f.severity) ?? [];
    group.push(f);
    bySev.set(f.severity, group);
  }

  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    const group = bySev.get(severity);
    if (!group?.length) continue;
    const color = SEV_COLOR[severity] ?? chalk.white;
    lines.push(color(`  ${severity.toUpperCase()} (${group.length})`));
    for (const f of group) {
      const pts = f.points > 0 ? chalk.gray(` [${f.points}pts]`) : "";
      const fix = f.auto_fixable ? chalk.green(" [fixable]") : "";
      lines.push(`    ${color(">")} ${f.title}${pts}${fix}`);
      lines.push(chalk.gray(`      ${f.description}`));
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON reporter
// ---------------------------------------------------------------------------

export function reportJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}

// ---------------------------------------------------------------------------
// SARIF reporter (OASIS standard for static analysis results)
// ---------------------------------------------------------------------------

const SARIF_SEV_MAP: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function reportSarif(result: AuditResult): string {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "openclaw-shield",
            informationUri: "https://github.com/cochat/openclaw-shield",
            version: "0.1.0",
            rules: result.findings.map((f) => ({
              id: f.id,
              shortDescription: { text: f.title },
              fullDescription: { text: f.description },
              helpUri: "https://github.com/cochat/openclaw-shield/blob/main/rules",
              defaultConfiguration: { level: SARIF_SEV_MAP[f.severity] ?? "note" },
              properties: { severity: f.severity, points: f.points },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: SARIF_SEV_MAP[f.severity] ?? "note",
          message: { text: `${f.title}\n\n${f.description}\n\nRecommendation: ${f.recommendation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: result.config_path },
              },
            },
          ],
          properties: { severity: f.severity, points: f.points, auto_fixable: f.auto_fixable },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

// ---------------------------------------------------------------------------
// Skill scan reporter
// ---------------------------------------------------------------------------

export function reportSkillScan(result: SkillScanResult): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold("  OpenClaw Shield Skill Scan"));
  lines.push(chalk.gray(`  Path: ${result.skill_path}`));
  lines.push(chalk.gray(`  Files scanned: ${result.files_scanned}`));
  lines.push(chalk.gray(`  Scanned: ${result.scanned_at}`));
  lines.push("");

  if (result.blocked) {
    lines.push(chalk.red.bold("  BLOCKED"));
    lines.push(chalk.red(`  ${result.block_reason}`));
    lines.push("");
  }

  if (result.findings.length === 0 && !result.blocked) {
    lines.push(chalk.green("  No issues found."));
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`  Findings: ${result.findings.length}`);
  lines.push("");

  for (const f of result.findings) {
    const color = SEV_COLOR[f.severity] ?? chalk.white;
    lines.push(`  ${color(">")} ${f.title}`);
    if (f.context) lines.push(chalk.gray(`    ${f.context}`));
  }
  lines.push("");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Profile reporter
// ---------------------------------------------------------------------------

export function reportProfiles(profiles: HardeningProfile[]): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold("  OpenClaw Shield Hardening Profiles"));
  lines.push("");
  for (const p of profiles) {
    lines.push(`  ${chalk.bold(p.name)} ${chalk.gray(`(${p.id})`)}`);
    lines.push(chalk.gray(`    ${p.description}`));
    lines.push("");
    lines.push("    Impact:");
    for (const item of p.impact) {
      lines.push(`      ${chalk.gray(">")} ${item}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Patterns reporter
// ---------------------------------------------------------------------------

export function reportPatterns(catalog: PatternCatalog): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold("  OpenClaw Shield Exec Patterns"));
  lines.push("");
  for (const [key, group] of Object.entries(catalog)) {
    const color = key === "dangerous" ? chalk.red : chalk.yellow;
    lines.push(`  ${color.bold(group.label)} (${group.patterns.length} patterns)`);
    lines.push(chalk.gray(`  ${group.description}`));
    lines.push("");
    for (const p of group.patterns) {
      lines.push(`    ${color(">")} ${chalk.gray(p.pattern)}`);
      lines.push(`      ${p.description}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Rules list reporter
// ---------------------------------------------------------------------------

export function reportRulesList(rules: { id: string; severity: string; title: string; auto_fixable: boolean }[]): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.bold(`  OpenClaw Shield Rules (${rules.length})`));
  lines.push("");
  for (const severity of ["critical", "high", "medium", "low"]) {
    const group = rules.filter((r) => r.severity === severity);
    if (!group.length) continue;
    const color = SEV_COLOR[severity] ?? chalk.white;
    lines.push(color(`  ${severity.toUpperCase()} (${group.length})`));
    for (const r of group) {
      const fix = r.auto_fixable ? chalk.green(" [fixable]") : "";
      lines.push(`    ${color(">")} ${chalk.gray(r.id)} ${r.title}${fix}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
