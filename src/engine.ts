import type {
  Rule,
  Check,
  Finding,
  CrossFieldCondition,
  CrossFieldOp,
  Severity,
  SEVERITY_WEIGHTS,
} from "./types.js";
import { SEVERITY_WEIGHTS as WEIGHTS } from "./types.js";

// ---------------------------------------------------------------------------
// Config accessor: deep get by dot-path
// ---------------------------------------------------------------------------

export function getPath(
  config: Record<string, unknown>,
  path: string,
): unknown {
  const keys = path.split(".");
  let current: unknown = config;
  for (const key of keys) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

// ---------------------------------------------------------------------------
// Check evaluators
// ---------------------------------------------------------------------------

type CheckResult = { fires: boolean; context?: string };

function isTruthy(val: unknown): boolean {
  if (val == null) return false;
  if (val === false || val === 0 || val === "") return false;
  if (Array.isArray(val) && val.length === 0) return false;
  return true;
}

function evalValueEquals(
  config: Record<string, unknown>,
  check: { path: string; value: unknown; invert?: boolean },
): CheckResult {
  const actual = getPath(config, check.path);
  const matches = actual === check.value;
  // Default (invert=false): fires when value != expected
  // invert=true: fires when value == expected
  const fires = check.invert ? matches : !matches;
  return { fires };
}

function evalValueInSet(
  config: Record<string, unknown>,
  check: { path: string; values: unknown[]; invert?: boolean },
): CheckResult {
  const actual = getPath(config, check.path);
  const inSet = check.values.includes(actual);
  const fires = check.invert ? inSet : !inSet;
  return { fires };
}

function evalValueNotInList(
  config: Record<string, unknown>,
  check: { path: string; value: unknown },
): CheckResult {
  const list = getPath(config, check.path);
  if (!Array.isArray(list)) return { fires: true }; // list doesn't exist = value not in it
  return { fires: !list.includes(check.value) };
}

function evalTruthy(
  config: Record<string, unknown>,
  check: { path: string; invert?: boolean },
): CheckResult {
  const val = getPath(config, check.path);
  const truthy = isTruthy(val);
  const fires = check.invert ? !truthy : truthy;
  return { fires };
}

function evalKeyExists(
  config: Record<string, unknown>,
  check: { path: string; invert?: boolean },
): CheckResult {
  const val = getPath(config, check.path);
  const exists = val !== undefined;
  const fires = check.invert ? !exists : exists;
  return { fires };
}

function evalStringLength(
  config: Record<string, unknown>,
  check: { path: string; min?: number; max?: number },
): CheckResult {
  const val = getPath(config, check.path);
  if (typeof val !== "string") {
    // If no string found and min is set, fire (nothing to measure = too short)
    return { fires: check.min != null };
  }
  if (check.min != null && val.length < check.min) return { fires: true };
  if (check.max != null && val.length > check.max) return { fires: true };
  return { fires: false };
}

function evalStringMatch(
  config: Record<string, unknown>,
  check: { path: string; pattern: string; invert?: boolean },
): CheckResult {
  const val = getPath(config, check.path);
  if (typeof val !== "string") return { fires: !!check.invert };
  const matches = new RegExp(check.pattern).test(val);
  const fires = check.invert ? !matches : matches;
  return { fires };
}

function evalCrossFieldCondition(
  config: Record<string, unknown>,
  cond: CrossFieldCondition,
): boolean {
  const val = getPath(config, cond.path);

  switch (cond.op) {
    case "eq":
      return val === cond.value;
    case "ne":
      return val !== cond.value;
    case "in":
      return (
        Array.isArray(cond.value) && (cond.value as unknown[]).includes(val)
      );
    case "not_in":
      return (
        !Array.isArray(cond.value) || !(cond.value as unknown[]).includes(val)
      );
    case "truthy":
      return isTruthy(val);
    case "falsy":
      return !isTruthy(val);
    case "absent":
      return val === undefined || val === null;
    case "contains":
      return Array.isArray(val) && val.includes(cond.value);
    case "not_contains":
      return !Array.isArray(val) || !val.includes(cond.value);
    default:
      return false;
  }
}

function evalCrossField(
  config: Record<string, unknown>,
  check: { conditions: CrossFieldCondition[] },
): CheckResult {
  // ALL conditions must be true for the rule to fire
  const fires = check.conditions.every((c) =>
    evalCrossFieldCondition(config, c),
  );
  return { fires };
}

function evalIterateMap(
  config: Record<string, unknown>,
  check: { path: string; skip_keys?: string[]; entry_check: Check },
): Finding[] {
  const map = getPath(config, check.path);
  if (!map || typeof map !== "object" || Array.isArray(map)) return [];

  const skipSet = new Set(check.skip_keys ?? []);
  const findings: Finding[] = [];

  for (const [key, value] of Object.entries(map as Record<string, unknown>)) {
    if (skipSet.has(key)) continue;
    if (value == null || typeof value !== "object") continue;

    // For entry_check, paths are relative to the entry value.
    // Support $root. prefix for accessing root config.
    const entryConfig = value as Record<string, unknown>;

    // Create a merged view: entry fields + $root access
    const merged = new Proxy(entryConfig, {
      get(target, prop) {
        if (typeof prop === "string" && prop.startsWith("$root.")) {
          return getPath(config, prop.slice(6));
        }
        return Reflect.get(target, prop);
      },
    });

    const result = evaluateCheck(merged, check.entry_check);
    if (result.fires) {
      findings.push({
        ...({} as Finding),
        context: key,
      });
    }
  }

  return findings;
}

function evalScanKeys(
  config: Record<string, unknown>,
  check: {
    path?: string;
    pattern: string;
    recursive?: boolean;
    value_truthy?: boolean;
  },
): CheckResult {
  const root = check.path ? getPath(config, check.path) : config;
  if (!root || typeof root !== "object") return { fires: false };

  const regex = new RegExp(check.pattern);
  const found = scanKeysRecursive(
    root as Record<string, unknown>,
    regex,
    check.recursive ?? false,
    check.value_truthy ?? true,
  );
  return { fires: found };
}

function scanKeysRecursive(
  obj: Record<string, unknown>,
  regex: RegExp,
  recursive: boolean,
  valueTruthy: boolean,
): boolean {
  for (const [key, value] of Object.entries(obj)) {
    if (regex.test(key)) {
      if (valueTruthy && isTruthy(value)) return true;
      if (!valueTruthy) return true;
    }
    if (
      recursive &&
      value &&
      typeof value === "object" &&
      !Array.isArray(value)
    ) {
      if (
        scanKeysRecursive(
          value as Record<string, unknown>,
          regex,
          true,
          valueTruthy,
        )
      )
        return true;
    }
  }
  return false;
}

function evalUrlCheck(
  config: Record<string, unknown>,
  check: {
    path: string;
    url_field: string;
    trusted_domains: string[];
    skip_keys?: string[];
  },
): Finding[] {
  const map = getPath(config, check.path);
  if (!map || typeof map !== "object" || Array.isArray(map)) return [];

  const skipSet = new Set(check.skip_keys ?? []);
  const findings: Finding[] = [];

  for (const [key, value] of Object.entries(map as Record<string, unknown>)) {
    if (skipSet.has(key)) continue;
    if (!value || typeof value !== "object") continue;

    const url = (value as Record<string, unknown>)[check.url_field];
    if (typeof url !== "string" || !url) continue;

    const urlLower = url.toLowerCase();
    const trusted = check.trusted_domains.some((domain) =>
      urlLower.includes(domain.toLowerCase()),
    );
    if (!trusted) {
      findings.push({
        ...({} as Finding),
        context: `${key} -> ${url}`,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Version comparison (for CVE checks)
// ---------------------------------------------------------------------------

function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/i, "").split(".").map(Number);
  const pb = b.replace(/^v/i, "").split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

function evalVersionCompare(
  config: Record<string, unknown>,
  check: { path: string; operator: string; value: string },
): CheckResult {
  const actual = getPath(config, check.path);
  if (typeof actual !== "string") return { fires: false };

  const cmp = compareVersions(actual, check.value);
  let fires = false;
  switch (check.operator) {
    case "lt":
      fires = cmp < 0;
      break;
    case "le":
      fires = cmp <= 0;
      break;
    case "eq":
      fires = cmp === 0;
      break;
    case "ge":
      fires = cmp >= 0;
      break;
    case "gt":
      fires = cmp > 0;
      break;
  }
  return { fires };
}

// ---------------------------------------------------------------------------
// Main check dispatcher
// ---------------------------------------------------------------------------

function evaluateCheck(
  config: Record<string, unknown>,
  check: Check,
): CheckResult {
  switch (check.type) {
    case "value_equals":
      return evalValueEquals(config, check);
    case "value_in_set":
      return evalValueInSet(config, check);
    case "value_not_in_list":
      return evalValueNotInList(config, check);
    case "truthy":
      return evalTruthy(config, check);
    case "key_exists":
      return evalKeyExists(config, check);
    case "string_length":
      return evalStringLength(config, check);
    case "string_match":
      return evalStringMatch(config, check);
    case "cross_field":
      return evalCrossField(config, check);
    case "scan_keys":
      return evalScanKeys(config, check);
    case "version_compare":
      return evalVersionCompare(config, check);
    case "custom":
      // Custom checks need a registry — skip if not registered
      return { fires: false };
    // iterate_map, url_check, code_pattern, skill_blocklist handled separately
    default:
      return { fires: false };
  }
}

// ---------------------------------------------------------------------------
// Rule evaluation — public API
// ---------------------------------------------------------------------------

export type CustomCheckFn = (config: Record<string, unknown>) => Finding[];

const customChecks = new Map<string, CustomCheckFn>();

export function registerCustomCheck(name: string, fn: CustomCheckFn): void {
  customChecks.set(name, fn);
}

/** Build the metadata fields common to all findings from a rule */
function ruleMeta(rule: Rule): Partial<Finding> {
  const meta: Partial<Finding> = {};
  if (rule.type) meta.rule_type = rule.type;
  if (rule.mitigates_cwes) meta.mitigates_cwes = rule.mitigates_cwes;
  if (rule.cwe) meta.cwe = rule.cwe;
  if (rule.cve) meta.cve = rule.cve;
  if (rule.fixed_in) meta.fixed_in = rule.fixed_in;
  return meta;
}

export function evaluateRule(
  rule: Rule,
  config: Record<string, unknown>,
): Finding[] {
  const points = WEIGHTS[rule.severity] ?? 0;
  const meta = ruleMeta(rule);

  // Multi-finding check types
  if (rule.check.type === "iterate_map") {
    const partials = evalIterateMap(config, rule.check);
    return partials.map((p) => ({
      id: rule.id,
      severity: rule.severity,
      title: p.context ? `${rule.title} (${p.context})` : rule.title,
      description: rule.description,
      recommendation: rule.recommendation,
      config_path: rule.config_path,
      auto_fixable: rule.auto_fixable,
      points,
      context: p.context,
      ...meta,
    }));
  }

  if (rule.check.type === "url_check") {
    const partials = evalUrlCheck(config, rule.check);
    return partials.map((p) => ({
      id: rule.id,
      severity: rule.severity,
      title: p.context ? `${rule.title} (${p.context})` : rule.title,
      description: rule.description,
      recommendation: rule.recommendation,
      config_path: rule.config_path,
      auto_fixable: rule.auto_fixable,
      points,
      context: p.context,
      ...meta,
    }));
  }

  if (rule.check.type === "custom") {
    const fn = customChecks.get(rule.check.function);
    if (fn) return fn(config);
    return [];
  }

  // Single-finding check types
  const result = evaluateCheck(config, rule.check);
  if (!result.fires) return [];

  return [
    {
      id: rule.id,
      severity: rule.severity,
      title: rule.title,
      description: rule.description,
      recommendation: rule.recommendation,
      config_path: rule.config_path,
      auto_fixable: rule.auto_fixable,
      points,
      context: result.context,
      ...meta,
    },
  ];
}

export function evaluateRules(
  rules: Rule[],
  config: Record<string, unknown>,
): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      findings.push(...evaluateRule(rule, config));
    } catch {
      // Don't let one broken rule abort the whole audit
    }
  }
  return findings;
}
