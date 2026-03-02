// openclaw-carapace — Library exports for programmatic use

export {
  loadRules,
  loadPatterns,
  loadProfiles,
  loadSkillRules,
  loadSkillBlocklist,
} from "./loader.js";
export {
  fetchAdvisoryRules,
  loadCachedAdvisoryRules,
} from "./advisory-fetcher.js";
export {
  evaluateRules,
  evaluateRule,
  registerCustomCheck,
  getPath,
} from "./engine.js";
export {
  scanSkill,
  scanSkillStatic,
  checkSkillBlocklist,
} from "./skill-scanner.js";
export { readConfig } from "./config-reader.js";
export { computeScore, computeGrade, buildAuditResult } from "./scorer.js";
export {
  reportText,
  reportJson,
  reportSarif,
  reportProfiles,
  reportPatterns,
  reportRulesList,
  reportSkillScan,
} from "./reporter.js";

export type {
  Rule,
  Check,
  Finding,
  AuditResult,
  VulnSummary,
  Severity,
  HardeningProfile,
  PatternEntry,
  PatternGroup,
  PatternCatalog,
  CrossFieldCondition,
  CrossFieldOp,
} from "./types.js";
export type { CustomCheckFn } from "./engine.js";

export { SEVERITY_WEIGHTS } from "./types.js";
