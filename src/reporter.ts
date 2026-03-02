import chalk from "chalk";
import type {
  AuditResult,
  Finding,
  HardeningProfile,
  PatternCatalog,
  SkillScanResult,
} from "./types.js";

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
// ASCII art & personality
// ---------------------------------------------------------------------------

const CARAPACE_BANNER = `
${chalk.red.bold("   ┌─────────────────────────────┐")}
${chalk.red.bold("   │")}  ${chalk.white.bold("🦞  O P E N C L A W")}          ${chalk.red.bold("│")}
${chalk.red.bold("   │")}  ${chalk.white.bold("    C A R A P A C E")}          ${chalk.red.bold("│")}
${chalk.red.bold("   └─────────────────────────────┘")}`;

const SKILL_BANNER = `
${chalk.red.bold("   ┌─────────────────────────────┐")}
${chalk.red.bold("   │")}  ${chalk.white.bold("🦞  S K I L L   S C A N")}     ${chalk.red.bold("│")}
${chalk.red.bold("   └─────────────────────────────┘")}`;

// Grade reactions — lobster-themed personality
const GRADE_REACTION: Record<string, string> = {
  A: "🦞 Carapace integrity: maximum. This lobster is armored.",
  B: "🦞 Pretty hard carapace. A few soft spots to patch up.",
  C: "🦞 Mid-molt. Your carapace is thin — time to harden up.",
  D: "🦞 Walking around without a carapace. Fix this.",
  F: "🦞 You're basically a shrimp right now. Critical issues need immediate attention.",
};

const CLEAN_MESSAGE =
  "🦞 Hard shell, no cracks. This gateway is locked down tight.";
const BLOCKED_MESSAGE =
  "🚨 This skill has been CLAWED. Known-malicious content detected.";

// ---------------------------------------------------------------------------
// Score bar — visual gauge
// ---------------------------------------------------------------------------

function scoreBar(score: number, width: number = 20): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;

  let barColor: (s: string) => string;
  if (score >= 90) barColor = chalk.green;
  else if (score >= 75) barColor = chalk.blue;
  else if (score >= 50) barColor = chalk.yellow;
  else if (score >= 25) barColor = chalk.hex("#FFA500");
  else barColor = chalk.red;

  const bar = barColor("█".repeat(filled)) + chalk.gray("░".repeat(empty));
  return `[${bar}]`;
}

// ---------------------------------------------------------------------------
// Divider
// ---------------------------------------------------------------------------

function divider(char: string = "─", width: number = 45): string {
  return chalk.gray("   " + char.repeat(width));
}

// ---------------------------------------------------------------------------
// Text reporter
// ---------------------------------------------------------------------------

/**
 * Count how many active vuln findings share a CWE with this config finding's
 * mitigates_cwes list.
 */
function countMitigatedCves(
  configFinding: Finding,
  vulnFindings: Finding[],
): string[] {
  if (!configFinding.mitigates_cwes?.length) return [];
  const mitigateSet = new Set(configFinding.mitigates_cwes);
  const mitigated: string[] = [];
  for (const vf of vulnFindings) {
    if (!vf.cwe) continue;
    const vulnCwes = vf.cwe.split(/,\s*/);
    if (vulnCwes.some((c) => mitigateSet.has(c.trim()))) {
      mitigated.push(vf.cve ?? vf.id);
    }
  }
  return mitigated;
}

function renderFindingsSection(
  lines: string[],
  findings: Finding[],
  vulnFindings: Finding[],
): void {
  const bySev = new Map<string, Finding[]>();
  for (const f of findings) {
    const group = bySev.get(f.severity) ?? [];
    group.push(f);
    bySev.set(f.severity, group);
  }

  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    const group = bySev.get(severity);
    if (!group?.length) continue;
    const color = SEV_COLOR[severity] ?? chalk.white;

    lines.push("");
    lines.push(
      `   ${color(`${severity.toUpperCase()}`)} ${chalk.gray(`(${group.length})`)}`,
    );
    lines.push("");

    for (const f of group) {
      const fix = f.auto_fixable ? chalk.green(" ✓ fixable") : "";
      const pts = f.points > 0 ? chalk.gray(` -${f.points}pts`) : "";
      lines.push(`   ${color("▸")} ${chalk.bold(f.title)}${pts}${fix}`);
      lines.push(chalk.gray(`     ${f.description}`));
      if (f.recommendation) {
        lines.push(`     ${chalk.cyan("→")} ${f.recommendation}`);
      }

      // CVE cross-reference for config findings
      const mitigated = countMitigatedCves(f, vulnFindings);
      if (mitigated.length > 0) {
        const cveList =
          mitigated.length <= 3
            ? mitigated.join(", ")
            : `${mitigated.slice(0, 3).join(", ")} +${mitigated.length - 3} more`;
        lines.push(
          `     ${chalk.magenta("🔗")} ${chalk.magenta(`Fixing this also mitigates ${mitigated.length} active CVE${mitigated.length === 1 ? "" : "s"} (${cveList})`)}`,
        );
      }

      lines.push("");
    }
  }
}

export function reportText(result: AuditResult): string {
  const lines: string[] = [];
  const gradeColor = GRADE_COLOR[result.grade] ?? chalk.white;

  // Banner
  lines.push(CARAPACE_BANNER);
  lines.push("");

  // Config info
  lines.push(chalk.gray(`   Config:  ${result.config_path}`));
  lines.push(chalk.gray(`   Rules:   ${result.rules_evaluated} evaluated`));
  lines.push("");
  lines.push(divider());
  lines.push("");

  // Score display — config score only
  const bar = scoreBar(result.score);
  lines.push(
    `   Config Grade ${gradeColor(result.grade)}  ${chalk.bold(String(result.score))}/100  ${bar}`,
  );
  lines.push("");

  // Grade reaction
  const reaction = GRADE_REACTION[result.grade];
  if (reaction) {
    lines.push(chalk.italic(`   ${reaction}`));
    lines.push("");
  }

  const configFindings =
    result.config_findings ??
    result.findings.filter((f) => f.rule_type !== "vulnerability");
  const vulnFindings =
    result.vuln_findings ??
    result.findings.filter((f) => f.rule_type === "vulnerability");
  const vulnSummary = result.vuln_summary;

  // ── Config findings section ──

  if (configFindings.length === 0 && vulnFindings.length === 0) {
    lines.push(`   ${CLEAN_MESSAGE}`);
    lines.push("");
    return lines.join("\n");
  }

  if (configFindings.length > 0) {
    const critCount = configFindings.filter(
      (f) => f.severity === "critical",
    ).length;
    const highCount = configFindings.filter(
      (f) => f.severity === "high",
    ).length;

    let summary = `   ${chalk.bold(String(configFindings.length))} config finding${configFindings.length === 1 ? "" : "s"}`;
    if (critCount > 0)
      summary += ` ${chalk.red.bold(`(${critCount} critical)`)}`;
    else if (highCount > 0)
      summary += ` ${chalk.yellow(`(${highCount} high)`)}`;
    lines.push(summary);

    if (result.total_fixable_points > 0) {
      lines.push(
        chalk.green(
          `   ↑ ${result.total_fixable_points} pts recoverable via auto-fix`,
        ),
      );
    }
    lines.push("");
    lines.push(divider());

    renderFindingsSection(lines, configFindings, vulnFindings);
  } else {
    lines.push(chalk.green("   No config issues found."));
    lines.push("");
  }

  // ── Vulnerability exposure section ──

  if (vulnFindings.length > 0 && vulnSummary) {
    lines.push(divider());
    lines.push("");
    lines.push(chalk.red.bold("   🐛 Vulnerability Exposure"));
    lines.push("");

    // Summary badges
    const parts: string[] = [];
    if (vulnSummary.critical > 0)
      parts.push(chalk.red.bold(`${vulnSummary.critical} critical`));
    if (vulnSummary.high > 0)
      parts.push(chalk.yellow(`${vulnSummary.high} high`));
    if (vulnSummary.medium > 0)
      parts.push(chalk.hex("#FFA500")(`${vulnSummary.medium} medium`));
    if (vulnSummary.low > 0) parts.push(chalk.blue(`${vulnSummary.low} low`));

    lines.push(
      `   ${chalk.bold(String(vulnSummary.total))} advisories affect your gateway version`,
    );
    if (parts.length > 0) {
      lines.push(`   ${parts.join("  ·  ")}`);
    }
    lines.push("");

    if (vulnSummary.recommended_version) {
      lines.push(
        `   ${chalk.cyan("→")} Update to ${chalk.bold(`v${vulnSummary.recommended_version}`)} or later to resolve all known advisories`,
      );
      lines.push("");
    }

    lines.push(
      chalk.gray(
        "   These don't affect your config grade — they require a gateway update.",
      ),
    );
    lines.push(chalk.gray("   Run with --no-vulns to hide this section."));
    lines.push("");
  }

  lines.push(divider());
  lines.push("");
  lines.push(
    chalk.gray("   Run with --format json for machine-readable output"),
  );
  lines.push(chalk.gray("   Run with --format sarif for GitHub Code Scanning"));
  lines.push("");

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

function deduplicateSarifRules(findings: Finding[]) {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    if (!seen.has(f.id)) seen.set(f.id, f);
  }
  return [...seen.values()].map((f) => ({
    id: f.id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.description },
    helpUri: "https://github.com/cochatai/openclaw-carapace/blob/main/rules",
    defaultConfiguration: { level: SARIF_SEV_MAP[f.severity] ?? "note" },
    properties: { severity: f.severity, points: f.points },
  }));
}

export function reportSarif(result: AuditResult): string {
  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "openclaw-carapace",
            informationUri: "https://github.com/cochatai/openclaw-carapace",
            version: "0.2.0",
            rules: deduplicateSarifRules(result.findings),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: SARIF_SEV_MAP[f.severity] ?? "note",
          message: {
            text: `${f.title}\n\n${f.description}\n\nRecommendation: ${f.recommendation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: result.config_path },
              },
            },
          ],
          properties: {
            severity: f.severity,
            points: f.points,
            auto_fixable: f.auto_fixable,
          },
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

  lines.push(SKILL_BANNER);
  lines.push("");
  lines.push(chalk.gray(`   Path:     ${result.skill_path}`));
  lines.push(chalk.gray(`   Files:    ${result.files_scanned} scanned`));
  lines.push("");
  lines.push(divider());
  lines.push("");

  if (result.blocked) {
    lines.push(chalk.red.bold(`   ${BLOCKED_MESSAGE}`));
    lines.push("");
    lines.push(chalk.red(`   ${result.block_reason}`));
    lines.push("");
    lines.push(divider());
    lines.push("");
  }

  if (result.findings.length === 0 && !result.blocked) {
    lines.push(`   ${CLEAN_MESSAGE}`);
    lines.push("");
    return lines.join("\n");
  }

  if (result.findings.length > 0) {
    lines.push(
      `   ${chalk.bold(String(result.findings.length))} finding${result.findings.length === 1 ? "" : "s"}`,
    );
    lines.push("");

    for (const f of result.findings) {
      const color = SEV_COLOR[f.severity] ?? chalk.white;
      lines.push(`   ${color("▸")} ${chalk.bold(f.title)}`);
      if (f.context) lines.push(chalk.gray(`     ${f.context}`));
      lines.push("");
    }

    lines.push(divider());
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
  lines.push(chalk.red.bold("   🦞 Hardening Profiles"));
  lines.push("");
  lines.push(divider());

  for (const p of profiles) {
    lines.push("");
    lines.push(`   ${chalk.bold(p.name)} ${chalk.gray(`(${p.id})`)}`);
    lines.push(chalk.gray(`   ${p.description}`));
    lines.push("");
    for (const item of p.impact) {
      lines.push(`     ${chalk.cyan("•")} ${item}`);
    }
  }
  lines.push("");
  lines.push(divider());
  lines.push("");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Patterns reporter
// ---------------------------------------------------------------------------

export function reportPatterns(catalog: PatternCatalog): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.red.bold("   🦞 Exec Firewall Patterns"));
  lines.push("");
  lines.push(divider());

  for (const [key, group] of Object.entries(catalog)) {
    const color = key === "dangerous" ? chalk.red : chalk.yellow;
    lines.push("");
    lines.push(
      `   ${color.bold(group.label)} ${chalk.gray(`(${group.patterns.length} patterns)`)}`,
    );
    lines.push(chalk.gray(`   ${group.description}`));
    lines.push("");
    for (const p of group.patterns) {
      lines.push(`     ${color("▸")} ${chalk.gray(p.pattern)}`);
      lines.push(`       ${p.description}`);
    }
  }
  lines.push("");
  lines.push(divider());
  lines.push("");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Rules list reporter
// ---------------------------------------------------------------------------

export function reportRulesList(
  rules: {
    id: string;
    severity: string;
    title: string;
    auto_fixable: boolean;
  }[],
): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(chalk.red.bold(`   🦞 Audit Rules (${rules.length})`));
  lines.push("");
  lines.push(divider());

  for (const severity of ["critical", "high", "medium", "low"]) {
    const group = rules.filter((r) => r.severity === severity);
    if (!group.length) continue;
    const color = SEV_COLOR[severity] ?? chalk.white;

    lines.push("");
    lines.push(
      `   ${color(`${severity.toUpperCase()}`)} ${chalk.gray(`(${group.length})`)}`,
    );
    lines.push("");
    for (const r of group) {
      const fix = r.auto_fixable ? chalk.green(" ✓ fixable") : "";
      lines.push(`   ${color("▸")} ${chalk.gray(r.id)} ${r.title}${fix}`);
    }
  }
  lines.push("");
  lines.push(divider());
  lines.push("");
  return lines.join("\n");
}
