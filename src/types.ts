// ---------------------------------------------------------------------------
// Rule check types — each maps to a YAML check definition
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ValueEqualsCheck {
  type: "value_equals";
  path: string;
  value: unknown;
  invert?: boolean; // default false: fires when value != expected
}

export interface ValueInSetCheck {
  type: "value_in_set";
  path: string;
  values: unknown[];
  invert?: boolean; // default false: fires when value NOT in set
}

export interface ValueNotInListCheck {
  type: "value_not_in_list";
  path: string; // path to an array in config
  value: unknown; // fires when this value is absent from the array
}

export interface TruthyCheck {
  type: "truthy";
  path: string;
  invert?: boolean; // true = "falsy" check
}

export interface KeyExistsCheck {
  type: "key_exists";
  path: string;
  invert?: boolean; // true = fires when key does NOT exist
}

export interface StringLengthCheck {
  type: "string_length";
  path: string;
  min?: number;
  max?: number;
}

export interface StringMatchCheck {
  type: "string_match";
  path: string;
  pattern: string; // regex
  invert?: boolean;
}

export type CrossFieldOp =
  | "eq"
  | "ne"
  | "in"
  | "not_in"
  | "truthy"
  | "falsy"
  | "absent"
  | "contains"
  | "not_contains";

export interface CrossFieldCondition {
  path: string;
  op: CrossFieldOp;
  value?: unknown;
}

export interface CrossFieldCheck {
  type: "cross_field";
  conditions: CrossFieldCondition[];
}

export interface IterateMapCheck {
  type: "iterate_map";
  path: string;
  skip_keys?: string[];
  entry_check: Check; // check applied to each entry value
}

export interface ScanKeysCheck {
  type: "scan_keys";
  path?: string; // path to a dict (default: root)
  pattern: string; // regex to match key names
  recursive?: boolean;
  value_truthy?: boolean; // fires for matching keys where value is truthy
}

export interface UrlCheck {
  type: "url_check";
  path: string; // path to a dict to iterate
  url_field: string; // field within each entry containing the URL
  trusted_domains: string[];
  skip_keys?: string[];
}

export interface CustomCheck {
  type: "custom";
  function: string; // name of a registered custom check function
}

// --- Version comparison (for CVE/vulnerability checks) ---
export interface VersionCompareCheck {
  type: "version_compare";
  path: string; // path to version string in config
  operator: "lt" | "le" | "eq" | "ge" | "gt";
  value: string; // version to compare against (semver)
}

// --- Code pattern scanning (for skill security) ---
export interface CodePatternCheck {
  type: "code_pattern";
  patterns: string[]; // regex patterns to search for
  file_patterns?: string[]; // glob patterns for files to scan (e.g. ["*.ts", "*.js"])
  exclude_domains?: string[]; // domains to exclude from network-related pattern matches
}

// --- Skill blocklist (for known-malicious skills) ---
export interface SkillBlocklistCheck {
  type: "skill_blocklist";
  indicators: {
    c2_ips?: string[];
    authors?: string[];
    sha256_hashes?: string[];
    skill_names?: string[];
    domains?: string[];
  };
}

export type Check =
  | ValueEqualsCheck
  | ValueInSetCheck
  | ValueNotInListCheck
  | TruthyCheck
  | KeyExistsCheck
  | StringLengthCheck
  | StringMatchCheck
  | CrossFieldCheck
  | IterateMapCheck
  | ScanKeysCheck
  | UrlCheck
  | CustomCheck
  | VersionCompareCheck
  | CodePatternCheck
  | SkillBlocklistCheck;

// ---------------------------------------------------------------------------
// Rule definition — loaded from YAML
// ---------------------------------------------------------------------------

export interface RuleFix {
  [key: string]: unknown; // config.patch payload
}

export type RuleType = "misconfiguration" | "vulnerability" | "skill_check" | "skill_blocklist";

export interface Rule {
  id: string;
  type?: RuleType; // defaults to "misconfiguration"
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  config_path: string;
  auto_fixable: boolean;
  fix?: RuleFix;
  tags?: string[];
  check: Check;
  // CVE/vulnerability metadata
  cve?: string;
  cvss?: number;
  affected_versions?: string;
  fixed_in?: string;
  // Industry standard metadata
  cwe?: string; // e.g. "CWE-250"
  references?: string[];
  confidence?: "high" | "medium" | "low";
}

// ---------------------------------------------------------------------------
// Audit result types
// ---------------------------------------------------------------------------

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  config_path: string;
  auto_fixable: boolean;
  points: number;
  /** For iterate_map / url_check: which key triggered the finding */
  context?: string;
}

export interface AuditResult {
  score: number;
  grade: string;
  findings: Finding[];
  total_fixable_points: number;
  rules_evaluated: number;
  config_path: string;
  audited_at: string; // ISO 8601
}

// ---------------------------------------------------------------------------
// Firewall patterns
// ---------------------------------------------------------------------------

export interface PatternEntry {
  pattern: string;
  description: string;
}

export interface PatternGroup {
  label: string;
  description: string;
  patterns: PatternEntry[];
}

export interface PatternCatalog {
  dangerous: PatternGroup;
  suspicious: PatternGroup;
}

// ---------------------------------------------------------------------------
// Hardening profiles
// ---------------------------------------------------------------------------

export interface HardeningProfile {
  id: string;
  name: string;
  description: string;
  impact: string[];
  patch: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

// ---------------------------------------------------------------------------
// Skill scanning
// ---------------------------------------------------------------------------

export interface SkillScanResult {
  skill_path: string;
  findings: Finding[];
  files_scanned: number;
  blocked: boolean; // true if skill matches a blocklist entry
  block_reason?: string;
  scanned_at: string; // ISO 8601
}

export interface SkillBlocklistEntry {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  indicators: {
    c2_ips?: string[];
    authors?: string[];
    sha256_hashes?: string[];
    skill_names?: string[];
    domains?: string[];
  };
}
