# OpenClaw Carapace

**Security auditor for [OpenClaw](https://openclaw.ai) gateways.**
Built by [CoChat](https://cochat.ai).

<p align="center">
  <a href="https://www.npmjs.com/package/@cochatai/openclaw-carapace"><img src="https://img.shields.io/npm/v/@cochatai/openclaw-carapace?style=for-the-badge&color=d63031&label=npm" alt="npm version"></a>
  <img src="https://img.shields.io/badge/rules-24-d63031?style=for-the-badge" alt="24 audit rules">
  <img src="https://img.shields.io/badge/CVEs-225+-8b0000?style=for-the-badge" alt="225+ advisories">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/critical-8_rules-8b0000?style=flat-square" alt="8 critical rules">
  <img src="https://img.shields.io/badge/high-7_rules-d63031?style=flat-square" alt="7 high rules">
  <img src="https://img.shields.io/badge/medium-8_rules-e17055?style=flat-square" alt="8 medium rules">
  <img src="https://img.shields.io/badge/low-1_rule-27ae60?style=flat-square" alt="1 low rule">
  <img src="https://img.shields.io/badge/skill_checks-6-8e44ad?style=flat-square" alt="6 skill checks">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square" alt="Node.js >= 18">
</p>

---

Run one command. See exactly what's wrong with your gateway and how to fix it.

```
$ openclaw-carapace audit

   ┌─────────────────────────────┐
   │  🦞  O P E N C L A W        │
   │      C A R A P A C E        │
   └─────────────────────────────┘

   Config:  /Users/dev/.openclaw/openclaw.json
   Rules:   106 evaluated

   ─────────────────────────────────────────────

   Grade D  30/100  [██████░░░░░░░░░░░░░░]

   🦞 Walking around without a shell. Fix this.

   8 findings (4 critical)
   ↑ 55 pts recoverable via auto-fix

   ─────────────────────────────────────────────

   CRITICAL (4)

   ▸ Gateway authentication disabled                      -25pts
     No authentication is configured on the gateway.
     → Set gateway.auth.mode to 'token' with a strong random token.

   ▸ Sandboxing disabled — exec runs on host              -25pts  ✓ fixable
     Sandbox mode is 'off' and exec tools are not denied.
     → Set agents.defaults.sandbox.mode to 'non-main'.

   ▸ Gateway tool not denied — agent can modify config    -25pts  ✓ fixable
     A prompt injection can undo ALL security hardening.
     → Add 'gateway' to tools.deny.

   ▸ Elevated mode enabled                                -25pts  ✓ fixable
     Elevated exec bypasses sandboxing and runs on host.
     → Set tools.elevated.enabled to false.

   HIGH (2)

   ▸ Filesystem not restricted to workspace               -10pts  ✓ fixable
     Filesystem tools can access ~/.openclaw/ and credentials.
     → Set tools.fs.workspaceOnly to true.

   ▸ Tool loop detection disabled                         -10pts  ✓ fixable
     A stuck agent can execute the same tool call repeatedly.
     → Set tools.loopDetection.enabled to true.

   MEDIUM (2)

   ▸ Auth credential is short (< 32 chars)                -5pts
     Short credentials are easier to brute-force.
     → Use a random token of at least 32 characters.

   ▸ mDNS full mode — broadcasting sensitive info         -5pts   ✓ fixable
     Broadcasts install paths and SSH availability on LAN.
     → Set discovery.mdns.mode to 'minimal' or 'off'.

   ─────────────────────────────────────────────

   Run with --format json for machine-readable output
   Run with --format sarif for GitHub Code Scanning
```

Carapace tells you what's wrong, why it matters, and exactly what to change. Most findings can be auto-fixed.

## 📦 Install

```bash
npm install -g @cochatai/openclaw-carapace
```

Requires Node.js 18+. That's it.

## 🔍 What It Checks

**Your config** -- 24 rules catch misconfigurations in authentication, sandboxing, tool permissions, exec approvals, filesystem restrictions, DM policies, and more. Each finding explains the risk and tells you the fix.

**Known vulnerabilities** -- Carapace fetches 80+ CVEs and advisories from [jgamblin/OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs) (updated hourly) and checks them against your gateway version. Works offline too.

**Third-party skills** -- Scan any skill directory for hardcoded secrets, shell execution, network exfiltration, obfuscation, and known-malicious authors.

## 🚀 Usage

```bash
# Audit your gateway (auto-discovers ~/.openclaw/openclaw.json)
openclaw-carapace audit

# Point to a specific config
openclaw-carapace audit --config ./openclaw.json

# Scan a skill before installing it
openclaw-carapace skill scan ./some-skill/ --author "skill-author"

# See what hardening profiles are available
openclaw-carapace profiles list

# Output SARIF for GitHub Code Scanning
openclaw-carapace audit --format sarif > results.sarif
```

## 📊 Scoring

Your gateway gets a score out of 100. Findings deduct points based on severity:

| Severity | Points | Example                                   |
| -------- | ------ | ----------------------------------------- |
| Critical | -25    | No authentication, sandboxing off         |
| High     | -10    | No exec approval, filesystem unrestricted |
| Medium   | -5     | Log redaction off, short auth token       |
| Low      | -2     | Web fetch enabled                         |

**Grades:** A (90+), B (75-89), C (50-74), D (25-49), F (below 25)

One critical finding drops you from A to B. The score makes risk visible at a glance.

## 🤝 Contributing

We'd love your help. Whether it's a new audit rule, a better description for an existing finding, a blocklist update, or a bug fix -- contributions of any size are welcome.

```bash
git clone https://github.com/cochatai/openclaw-carapace.git
cd openclaw-carapace
npm install
npm run build
node dist/cli.js audit --help
```

**Ways to contribute:**

- Report a security misconfiguration we're not catching -- [open an issue](https://github.com/cochatai/openclaw-carapace/issues)
- Add a new audit rule -- just create a YAML file in `rules/` (see [Writing Custom Rules](#writing-custom-rules) below)
- Report a malicious skill or author -- add to `skills/blocklist/`
- Improve finding descriptions -- clarity helps everyone
- Add tests, fix bugs, improve docs

---

# 📖 Reference

Everything below is detailed reference material. You don't need to read it to use Carapace -- the output tells you what to do. But it's here when you need it.

## ⌨️ CLI Reference

### `audit`

```
openclaw-carapace audit [options]
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

```
openclaw-carapace skill scan <path> [options]
```

| Option               | Description                        | Default |
| -------------------- | ---------------------------------- | ------- |
| `-f, --format <fmt>` | Output: `text`, `json`             | `text`  |
| `--author <author>`  | Skill author (for blocklist check) |         |
| `--name <name>`      | Skill name (for blocklist check)   |         |

### `skill blocklist`

```
openclaw-carapace skill blocklist [--format text|json]
```

### `profiles list` / `profiles show <id>`

```
openclaw-carapace profiles list
openclaw-carapace profiles show locked_down --format json
```

### `patterns`

```
openclaw-carapace patterns [--format text|json]
```

### `rules`

```
openclaw-carapace rules [--format text|json] [--offline]
```

### Exit Codes

| Code | Meaning                               |
| ---- | ------------------------------------- |
| `0`  | Clean -- no high or critical findings |
| `1`  | High severity finding detected        |
| `2`  | Critical severity finding detected    |
| `3`  | Skill matches the blocklist           |

## 🛡️ Config Audit Rules

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

| Rule ID                          | Title                                         | Auto-fix |
| -------------------------------- | --------------------------------------------- | -------- |
| `config_includes_present`        | Config includes detected                      |          |
| `custom_provider_external`       | External model provider detected              |          |
| `apply_patch.not_workspace_only` | apply_patch can write outside workspace       | Y        |
| `browser.enabled_no_sandbox`     | Browser control enabled without sandboxing    | Y        |
| `auth.token_short`               | Gateway auth credential is short (< 32 chars) |          |
| `plugins.no_allowlist`           | Plugins without explicit allowlist            |          |
| `logging.redact_off`             | Log redaction disabled                        | Y        |
| `discovery.mdns_full`            | mDNS full mode -- broadcasting sensitive info | Y        |

### Low (1 rule)

| Rule ID                   | Title                          |
| ------------------------- | ------------------------------ |
| `tools.web_fetch_enabled` | Web fetch/search tools enabled |

## 🐛 Vulnerability Scanning

Carapace fetches live advisory data from [jgamblin/OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs), a community-maintained repository updated hourly via GitHub Actions. This currently tracks **80+ advisories** with GHSA IDs, CVE IDs, CVSS scores, affected version ranges, and fixed versions.

Each advisory becomes a version check that fires when your `gateway.version` is below the fix version. Carapace catches new vulnerabilities automatically as they're disclosed.

**Postinstall fetch:** When you `npm install`, Carapace automatically fetches the latest advisory data so the first `audit` run has CVE coverage immediately.

**Cache:** Advisory data is cached to `~/.openclaw-carapace/cache/` for 1 hour. Subsequent runs within that window don't hit the network.

**Offline mode:** `--offline` skips network fetches and uses cached data. If no cache exists, Carapace will warn you and skip vulnerability checks.

## 🔒 Hardening Profiles

Pre-built configuration patches that fix multiple findings at once.

| Profile          | Description                                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `locked_down`    | Maximum security. Denies all runtime, filesystem, and control-plane tools. Forces sandboxing for all sessions. For messaging-only bots exposed to untrusted users. |
| `coding_safe`    | Balanced security for coding agents. Keeps exec and filesystem tools but restricts them to the workspace. Denies control-plane tools. Enables exec approvals.      |
| `messaging_safe` | Messaging tools only. Denies all runtime, filesystem, and automation tools.                                                                                        |
| `dm_hardened`    | Locks all channel DM policies to `pairing` and isolates sessions per channel+peer. Does not change tool settings.                                                  |

Use `openclaw-carapace profiles show <id> --format json` to see the exact config patch.

## 🧱 Exec Firewall Patterns

Two categories of patterns for real-time command interception:

**Dangerous (auto-deny, 20 patterns)** -- Destructive file ops (`rm -rf /`), credential theft (`cat ~/.ssh/`), remote code exec (`curl | sh`), system modification (`chmod 777`), network recon (`nmap`).

**Suspicious (flag for review, 13 patterns)** -- HTTP requests (`curl`, `wget`), package installation (`pip install`, `npm install -g`), privilege escalation (`sudo`), container operations (`docker`), environment access (`printenv`, `history`).

These are safety rails for the CoChat tool firewall, not security boundaries.

## 🕵️ Skill Scanning

### Static Analysis (6 rule categories)

| Rule                            | What it detects                                 | CWE      |
| ------------------------------- | ----------------------------------------------- | -------- |
| `skill.hardcoded_secrets`       | API keys, tokens, credentials in source code    | CWE-798  |
| `skill.command_execution`       | Shell exec, eval, subprocess, child_process     | CWE-78   |
| `skill.network_exfiltration`    | fetch, axios, http.request, WebSocket, etc.     | CWE-200  |
| `skill.filesystem_access`       | References to ~/.ssh, ~/.aws, /etc/passwd, etc. | CWE-22   |
| `skill.obfuscation`             | base64 decode, fromCharCode, hex escapes        | CWE-506  |
| `skill.suspicious_dependencies` | Typosquatted packages, postinstall scripts      | CWE-1357 |

### Blocklist

Known-malicious indicators from published security research:

- **ClawHavoc campaign** -- 335+ malicious skills on ClawHub delivering Atomic macOS Stealer (AMOS).
- **Known malicious authors** -- Aggregated from Snyk ToxicSkills (2025), Bitdefender AI supply-chain research (2026), and community reports.

Checks author name, skill name, file SHA-256 hashes, C2 IP addresses, and known malicious domains.

## ⚙️ SARIF / CI Integration

Carapace outputs [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub Code Scanning, VS Code SARIF Viewer, and other tools.

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
        run: npx @cochatai/openclaw-carapace audit --format sarif > openclaw-carapace.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: openclaw-carapace.sarif
```

## 💻 Programmatic Usage

```typescript
import {
  loadRules,
  fetchAdvisoryRules,
  evaluateRules,
  buildAuditResult,
  readConfig,
  reportText,
} from "@cochatai/openclaw-carapace";

const { config, path } = readConfig("./openclaw.json");

const configRules = loadRules();
const vulnRules = await fetchAdvisoryRules();
const allRules = [...configRules, ...vulnRules];

const findings = evaluateRules(allRules, config);
const result = buildAuditResult(findings, allRules.length, path);

console.log(reportText(result));
```

### Custom Check Hooks

```typescript
import { registerCustomCheck } from "@cochatai/openclaw-carapace";

registerCustomCheck("my_org_policy", (config) => {
  const findings = [];
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
} from "@cochatai/openclaw-carapace";

const result = scanSkill("./my-skill", loadSkillRules(), loadSkillBlocklist(), {
  author: "some-author",
  name: "my-skill",
});

console.log(reportSkillScan(result));
```

## ✏️ Writing Custom Rules

Rules are YAML files. Drop them in a directory, pass `--rules-dir`, and Carapace picks them up.

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

## 📄 License

[MIT](./LICENSE) -- Copyright (c) 2026 CoChat
