import type { Finding, AuditResult, VulnSummary, Severity } from "./types.js";
import { SEVERITY_WEIGHTS } from "./types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Only misconfiguration findings (or untyped findings) affect the config grade. */
function isConfigFinding(f: Finding): boolean {
  return !f.rule_type || f.rule_type === "misconfiguration";
}

function highestVersion(versions: string[]): string | undefined {
  if (versions.length === 0) return undefined;
  return versions.sort((a, b) => {
    const pa = a.split(".").map(Number);
    const pb = b.split(".").map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const diff = (pb[i] ?? 0) - (pa[i] ?? 0);
      if (diff !== 0) return diff;
    }
    return 0;
  })[0];
}

// ---------------------------------------------------------------------------
// Config scoring — only misconfiguration findings affect the grade
// ---------------------------------------------------------------------------

export function computeScore(findings: Finding[]): number {
  const configFindings = findings.filter(isConfigFinding);
  const penalty = configFindings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0),
    0,
  );
  return Math.max(0, 100 - penalty);
}

export function computeGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "F";
}

// ---------------------------------------------------------------------------
// Vulnerability summary — informational, doesn't affect grade
// ---------------------------------------------------------------------------

function buildVulnSummary(vulnFindings: Finding[]): VulnSummary {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const fixVersions: string[] = [];

  for (const f of vulnFindings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    if (f.fixed_in) fixVersions.push(f.fixed_in);
  }

  return {
    total: vulnFindings.length,
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    recommended_version: highestVersion(fixVersions),
  };
}

// ---------------------------------------------------------------------------
// Build the full audit result
// ---------------------------------------------------------------------------

export function buildAuditResult(
  findings: Finding[],
  rulesEvaluated: number,
  configPath: string,
): AuditResult {
  const configFindings = findings.filter(isConfigFinding);
  const vulnFindings = findings.filter((f) => f.rule_type === "vulnerability");

  const score = computeScore(findings);
  const totalFixablePoints = configFindings
    .filter((f) => f.auto_fixable)
    .reduce((sum, f) => sum + f.points, 0);

  return {
    score,
    grade: computeGrade(score),
    findings,
    config_findings: configFindings,
    vuln_findings: vulnFindings,
    vuln_summary: buildVulnSummary(vulnFindings),
    total_fixable_points: totalFixablePoints,
    rules_evaluated: rulesEvaluated,
    config_path: configPath,
    audited_at: new Date().toISOString(),
  };
}
