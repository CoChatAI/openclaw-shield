# OpenClaw Shield

**Security auditor, CVE scanner, and skill analyzer for [OpenClaw](https://openclaw.ai) gateways.**

[![npm version](https://img.shields.io/npm/v/@cochatai/openclaw-shield)](https://www.npmjs.com/package/@cochatai/openclaw-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

---

OpenClaw Shield audits your gateway configuration against 24 security rules, checks for 80+ known CVEs and advisories (updated hourly), scans third-party skills for malware, and outputs results in text, JSON, or SARIF for CI/CD integration.

Use it as a CLI tool or import it as a library.

## Features

- **Configuration Audit** -- 24 rules across critical/high/medium/low severity. Checks authentication, sandboxing, tool permissions, exec approvals, filesystem restrictions, DM policies, and more. A-F letter grade with 100-point scoring.
- **Vulnerability Scanning** -- Live advisory feed from [jgamblin/OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs) (80+ advisories, updated hourly via GitHub Actions). Compares your gateway version against known affected versions. Falls back to bundled static rules when offline.
- **Skill Scanning** -- Static analysis of skill source code for hardcoded secrets, command execution, network exfiltration, filesystem access, obfuscation, and suspicious dependencies. Blocklist of known-malicious authors and campaigns (ClawHavoc, ToxicSkills, and more).
- **CI/CD Integration** -- SARIF output for GitHub Code Scanning. Exit codes for scripting (0=clean, 1=high, 2=critical, 3=blocked skill). Hardening profiles for automated remediation.

## Installation

```bash
# Global CLI
npm install -g @cochatai/openclaw-shield

# Project dependency
npm install --save-dev @cochatai/openclaw-shield
```

Requires Node.js 18+.

## Quick Start

```bash
# Audit your gateway config (auto-discovers ~/.openclaw/openclaw.json)
openclaw-shield audit

# Specify a config file
openclaw-shield audit --config ./openclaw.json

# Output SARIF for CI
openclaw-shield audit --format sarif > results.sarif

# Scan a skill for security issues
openclaw-shield skill scan ./my-skill/ --author "some-author"

# List hardening profiles
openclaw-shield profiles list
```

## CLI Reference

### `audit`

Audit a gateway config for misconfigurations and known CVEs.

```
openclaw-shield audit [options]
```

| Option                     | Description                                    | Default       |
| -------------------------- | ---------------------------------------------- | ------------- |
| `-c, --config <path>`      | Path to `openclaw.json`                        | Auto-discover |
| `-f, --format <fmt>`       | Output: `text`, `json`, `sarif`                | `text`        |
| `-s, --min-severity <sev>` | Filter: `critical`, `high`, `medium`, `low`    | `low`         |
| `--rules-dir <path>`       | Custom rules directory                         | Built-in      |
| `--no-vulns`               | Skip CVE/vulnerability checks                  |               |
| `--offline`                | Don't fetch live advisories (use cache/static) |               |

### `skill scan`

Scan a skill directory for security issues and blocklist matches.

```
openclaw-shield skill scan <path> [options]
```

| Option               | Description                        | Default |
| -------------------- | ---------------------------------- | ------- |
| `-f, --format <fmt>` | Output: `text`, `json`             | `text`  |
| `--author <author>`  | Skill author (for blocklist check) |         |
| `--name <name>`      | Skill name (for blocklist check)   |         |

### `skill blocklist`

List known-malicious skill indicators (authors, IPs, domains, hashes).

```
openclaw-shield skill blocklist [--format text|json]
```

### `profiles list` / `profiles show <id>`

View available hardening profiles and their configuration patches.

```
openclaw-shield profiles list
openclaw-shield profiles show locked_down --format json
```

### `patterns`

List built-in exec firewall patterns (dangerous + suspicious).

```
openclaw-shield patterns [--format text|json]
```

### `rules`

List all audit rules (config + vulnerability).

```
openclaw-shield rules [--format text|json] [--offline]
```

## Exit Codes

| Code | Meaning                               |
| ---- | ------------------------------------- |
| `0`  | Clean -- no high or critical findings |
| `1`  | High severity finding detected        |
| `2`  | Critical severity finding detected    |
| `3`  | Skill matches the blocklist           |

## Scoring

Shield uses a 100-point deduction system:

| Severity | Points Deducted |
| -------- | --------------- |
| Critical | 25              |
| High     | 10              |
| Medium   | 5               |
| Low      | 2               |
| Info     | 0               |

**Grades:** A (90+), B (75-89), C (50-74), D (25-49), F (below 25)

A single critical misconfiguration drops you from A to B. Two criticals and a high finding puts you at D. The score makes risk visible at a glance.

## Sample Output

```
  OpenClaw Shield Audit
  Config: /Users/dev/.openclaw/openclaw.json
  Scanned: 2026-03-01T12:00:00.000Z
  Rules evaluated: 106

  Score: D 30/100
  Findings: 8
  Auto-fixable: +55 pts recoverable

  CRITICAL
  [critical] gateway.no_auth — Gateway authentication disabled
    No authentication is configured on the gateway.
    Fix: Set gateway.auth.mode to 'token' with a strong random token.

  [critical] sandbox.mode_off — Sandboxing disabled — exec runs on host
    Sandbox mode is 'off' and exec tools are not denied.
    Fix: Set agents.defaults.sandbox.mode to 'non-main'.  [auto-fixable]

  HIGH
  [high] firewall.inactive — Tool Firewall inactive
    tools.exec.ask is 'off' or not set.
    Fix: Set tools.exec.ask to 'on-miss'.  [auto-fixable]

  ...
```

## Config Audit Rules

24 rules organized by severity. Rules with a CWE mapping indicate which vulnerability class they mitigate.

### Critical (8 rules)

| Rule ID                      | Title                                              | CWE                                | Auto-fix |
| ---------------------------- | -------------------------------------------------- | ---------------------------------- | -------- |
| `gateway.no_auth`            | Gateway authentication disabled                    | CWE-306                            |          |
| `gateway.bind_no_auth`       | Gateway exposed without authentication             | CWE-306                            |          |
| `dm_policy_open`             | Open DM policy -- anyone can message the bot       | CWE-306, CWE-345, CWE-285, CWE-863 | Y        |
| `tools.profile_full`         | All tools unrestricted                             | CWE-78, CWE-22, CWE-918            | Y        |
| `elevated.enabled`           | Elevated mode enabled                              | CWE-78, CWE-250, CWE-269           | Y        |
| `sandbox.mode_off`           | Sandboxing disabled -- exec runs on host           | CWE-78, CWE-250                    | Y        |
| `tools.gateway_tool_enabled` | Gateway tool not denied -- agent can modify config | CWE-918, CWE-284                   | Y        |
| `dangerous_flags`            | Dangerous flag enabled                             |                                    | Y        |

### High (7 rules)

| Rule ID                           | Title                                            | CWE             | Auto-fix |
| --------------------------------- | ------------------------------------------------ | --------------- | -------- |
| `exec.host_sandbox_no_sandbox`    | exec.host='sandbox' but sandbox is off           | CWE-78, CWE-250 | Y        |
| `firewall.inactive`               | Tool Firewall inactive                           | CWE-78, CWE-284 | Y        |
| `fs.not_workspace_only`           | Filesystem tools not restricted to workspace     | CWE-22, CWE-200 | Y        |
| `exec.security_full`              | Exec runs all commands without approval          | CWE-78, CWE-77  | Y        |
| `channels.open_groups_with_tools` | Open groups with runtime tools enabled           |                 |          |
| `tools.no_loop_detection`         | Tool loop detection disabled                     |                 | Y        |
| `tools.cron_tool_enabled`         | Cron tool available -- persistent scheduled jobs |                 | Y        |

### Medium (8 rules)

| Rule ID                          | Title                                         | CWE | Auto-fix |
| -------------------------------- | --------------------------------------------- | --- | -------- |
| `config_includes_present`        | Config includes detected                      |     |          |
| `custom_provider_external`       | External model provider detected              |     |          |
| `apply_patch.not_workspace_only` | apply_patch can write outside workspace       |     | Y        |
| `browser.enabled_no_sandbox`     | Browser control enabled without sandboxing    |     | Y        |
| `auth.token_short`               | Gateway auth credential is short (< 32 chars) |     |          |
| `plugins.no_allowlist`           | Plugins without explicit allowlist            |     |          |
| `logging.redact_off`             | Log redaction disabled                        |     | Y        |
| `discovery.mdns_full`            | mDNS full mode -- broadcasting sensitive info |     | Y        |

### Low (1 rule)

| Rule ID                   | Title                          | Auto-fix |
| ------------------------- | ------------------------------ | -------- |
| `tools.web_fetch_enabled` | Web fetch/search tools enabled |          |

## Vulnerability Scanning

Shield fetches live advisory data from [jgamblin/OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs), a community-maintained repository updated hourly via GitHub Actions. This currently tracks **80+ advisories** with GHSA IDs, CVE IDs, CVSS scores, affected version ranges, and fixed versions.

Each advisory is transformed into a `version_compare` rule that fires when your `gateway.version` is below the fix version. This means Shield catches vulnerabilities automatically as they're disclosed -- no manual rule updates needed.

**Cache:** Advisory data is cached to `~/.openclaw-shield/cache/` for 1 hour. Subsequent runs within that window don't hit the network.

**Offline mode:** Use `--offline` to skip network fetches entirely. Shield will use cached data if available, then fall back to the 6 static vulnerability rules bundled in the package.

**Bundled static rules** (fallback):

- CVE-2026-25253 -- One-click RCE via WebSocket hijacking (CVSS 8.8)
- CVE-2026-25157 -- OS command injection via SSH handler (CVSS 8.1)
- CVE-2026-25475 -- Local file inclusion via MEDIA: path extraction (CVSS 6.5)
- GHSA-g55j -- Unauthenticated local RCE via WebSocket config.apply (CVSS 8.4)
- GHSA-mc68 -- Command injection in Docker execution via PATH manipulation (CVSS 8.1)
- GHSA-8jpq -- Local file disclosure via Feishu/Lark extension (CVSS 6.5)

## Hardening Profiles

Pre-built configuration patches that fix multiple findings at once.

### `locked_down`

Maximum security. Denies all runtime, filesystem, and control-plane tools. Forces sandboxing for all sessions. Suitable for messaging-only bots exposed to untrusted users.

### `coding_safe`

Balanced security for coding agents. Keeps filesystem and exec tools but restricts them to the workspace. Denies dangerous control-plane tools. Enables exec approvals and non-main session sandboxing.

### `messaging_safe`

Restricted to messaging tools only. Denies all runtime, filesystem, and automation tools. Suitable for bots that only need to converse and manage sessions.

### `dm_hardened`

Locks down all channel DM policies to `pairing` and isolates DM sessions per channel+peer. Does not change tool settings.

Use `openclaw-shield profiles show <id> --format json` to inspect the exact configuration patch each profile applies.

## Exec Firewall Patterns

Two categories of patterns for real-time command interception:

### Dangerous (auto-deny) -- 20 patterns

Blocked immediately. Includes destructive file operations (`rm -rf /`), credential theft (`cat ~/.ssh/`), remote code execution (`curl | sh`), system modification (`chmod 777`), and network recon (`nmap`).

### Suspicious (flag for review) -- 13 patterns

Routed for human approval. Includes HTTP requests (`curl`, `wget`), package installation (`pip install`, `npm install -g`), privilege escalation (`sudo`), container operations (`docker`), and environment access (`printenv`, `history`).

These patterns are safety rails for use with the CoChat tool firewall, not security boundaries -- regex-based interception can be bypassed by a determined adversary.

## Skill Scanning

### Static Analysis (6 rule categories)

| Rule                            | What it detects                                 | CWE      |
| ------------------------------- | ----------------------------------------------- | -------- |
| `skill.hardcoded_secrets`       | API keys, tokens, credentials in source code    | CWE-798  |
| `skill.command_execution`       | Shell exec, eval, subprocess, child_process     | CWE-78   |
| `skill.network_exfiltration`    | fetch, axios, http.request, WebSocket, etc.     | CWE-200  |
| `skill.filesystem_access`       | References to ~/.ssh, ~/.aws, /etc/passwd, etc. | CWE-22   |
| `skill.obfuscation`             | base64 decode, fromCharCode, hex escapes        | CWE-506  |
| `skill.suspicious_dependencies` | Typosquatted packages, postinstall scripts      | CWE-1357 |

Scans `.ts`, `.js`, `.py`, `.sh`, `.json`, `.yaml` files recursively (up to depth 10, skipping `node_modules/` and `.git/`).

### Blocklist

Known-malicious indicators sourced from published security research:

- **ClawHavoc campaign** -- 335+ malicious skills on ClawHub delivering Atomic macOS Stealer (AMOS) via base64-encoded scripts. Tracked C2 IPs, author accounts, and domains.
- **Known malicious authors** -- Aggregated from Snyk ToxicSkills study (2025), Bitdefender AI supply-chain research (2026), and community incident reports. Includes infostealer distributors, cryptominer campaigns, and backdoor authors.

The blocklist checks: author name, skill name, file SHA-256 hashes, C2 IP addresses, and known malicious domains found in source code.

```bash
# Scan with metadata for blocklist matching
openclaw-shield skill scan ./my-skill --author "some-author" --name "my-skill"

# View the full blocklist
openclaw-shield skill blocklist
```

## SARIF / CI Integration

Shield outputs [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other static analysis tools.

### GitHub Actions

```yaml
name: OpenClaw Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Audit OpenClaw config
        run: npx @cochatai/openclaw-shield audit --format sarif > openclaw-shield.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: openclaw-shield.sarif
```

## Programmatic Usage

Import Shield as a library for custom integrations:

```typescript
import {
  loadRules,
  loadProfiles,
  fetchAdvisoryRules,
  evaluateRules,
  buildAuditResult,
  readConfig,
  reportText,
  reportJson,
  reportSarif,
} from "@cochatai/openclaw-shield";

// Load config
const { config, path } = readConfig("./openclaw.json");

// Load rules (config + live advisories)
const configRules = loadRules();
const vulnRules = await fetchAdvisoryRules();
const allRules = [...configRules, ...vulnRules];

// Evaluate
const findings = evaluateRules(allRules, config);
const result = buildAuditResult(findings, allRules.length, path);

console.log(reportText(result)); // Human-readable
console.log(reportJson(result)); // JSON
console.log(reportSarif(result)); // SARIF 2.1.0
```

### Custom Check Hooks

Register custom checks for domain-specific rules:

```typescript
import {
  registerCustomCheck,
  evaluateRules,
  loadRules,
} from "@cochatai/openclaw-shield";

registerCustomCheck("my_org_policy", (config) => {
  const findings = [];
  // Your custom logic here
  if (!config.myOrg?.approvedProvider) {
    findings.push({
      id: "my_org.no_approved_provider",
      severity: "high",
      title: "Organization-approved provider not configured",
      description: "...",
      recommendation: "...",
      config_path: "myOrg.approvedProvider",
      auto_fixable: false,
      points: 10,
    });
  }
  return findings;
});
```

### Skill Scanning API

```typescript
import {
  scanSkill,
  loadSkillRules,
  loadSkillBlocklist,
  reportSkillScan,
} from "@cochatai/openclaw-shield";

const staticRules = loadSkillRules();
const blocklist = loadSkillBlocklist();

const result = scanSkill("./my-skill", staticRules, blocklist, {
  author: "some-author",
  name: "my-skill",
});

if (result.blocked) {
  console.error(`BLOCKED: ${result.block_reason}`);
  process.exit(3);
}

console.log(reportSkillScan(result));
```

## Writing Custom Rules

Rules are defined in YAML. Place them in a directory and pass `--rules-dir` to the CLI.

```yaml
id: my_custom_rule
severity: high
title: "My custom security check"
description: "Checks that my-setting is properly configured."
recommendation: "Set my-setting to 'secure'."
config_path: my.setting
auto_fixable: true
fix:
  my:
    setting: secure
tags:
  - custom
check:
  type: value_equals
  path: my.setting
  value: secure
```

### Available Check Types

| Type                | Description                                                     |
| ------------------- | --------------------------------------------------------------- |
| `value_equals`      | Fires when config value != expected (or == with `invert: true`) |
| `value_in_set`      | Fires when value not in allowed set                             |
| `value_not_in_list` | Fires when a value is absent from a config array                |
| `truthy`            | Fires when value is truthy (or falsy with `invert: true`)       |
| `key_exists`        | Fires when key exists (or doesn't with `invert: true`)          |
| `string_length`     | Fires when string length is outside `min`/`max` bounds          |
| `string_match`      | Fires when string matches (or doesn't) a regex pattern          |
| `cross_field`       | Fires when ALL conditions across multiple config paths are true |
| `iterate_map`       | Iterates a config map, applying a sub-check to each entry       |
| `scan_keys`         | Scans config keys matching a regex pattern                      |
| `url_check`         | Validates URLs in a config map against trusted domains          |
| `version_compare`   | Compares a semver string (`lt`, `le`, `eq`, `ge`, `gt`)         |
| `custom`            | Delegates to a registered TypeScript function                   |

## Contributing

Issues and pull requests are welcome at [github.com/cochatai/openclaw-shield](https://github.com/cochatai/openclaw-shield).

```bash
git clone https://github.com/cochatai/openclaw-shield.git
cd openclaw-shield
npm install
npm run build
node dist/cli.js audit --help
```

## License

[MIT](./LICENSE) -- Copyright (c) 2026 CoChat
