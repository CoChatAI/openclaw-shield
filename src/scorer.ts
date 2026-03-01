import type { Finding, AuditResult } from "./types.js";
import { SEVERITY_WEIGHTS } from "./types.js";

export function computeScore(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0);
  return Math.max(0, 100 - penalty);
}

export function computeGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "F";
}

export function buildAuditResult(
  findings: Finding[],
  rulesEvaluated: number,
  configPath: string,
): AuditResult {
  const score = computeScore(findings);
  const totalFixablePoints = findings
    .filter((f) => f.auto_fixable)
    .reduce((sum, f) => sum + f.points, 0);

  return {
    score,
    grade: computeGrade(score),
    findings,
    total_fixable_points: totalFixablePoints,
    rules_evaluated: rulesEvaluated,
    config_path: configPath,
    audited_at: new Date().toISOString(),
  };
}
