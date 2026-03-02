# AGENTS.md — OpenClaw Carapace

This file provides context for AI coding agents working on this repository.

## Project Overview

OpenClaw Carapace is a security auditor, CVE scanner, and skill analyzer for [OpenClaw](https://openclaw.ai) gateways. It ships as both a CLI tool and a TypeScript library, published to npm as `@cochatai/openclaw-carapace`.

The project is maintained by [CoChat](https://cochat.ai). The CoChat application (separate repo) consumes the YAML rules from this repo at runtime via GitHub raw file downloads.

## Repository Structure

```
openclaw-carapace/
├── src/                    # TypeScript source (compiled to dist/)
│   ├── cli.ts              # CLI entry point (Commander-based)
│   ├── types.ts            # All type definitions, severity weights
│   ├── engine.ts           # Rule evaluation engine (13 check types)
│   ├── loader.ts           # YAML file loader with caching
│   ├── scorer.ts           # Two-component scoring (config vs vuln)
│   ├── reporter.ts         # Text, JSON, SARIF output formatters
│   ├── advisory-fetcher.ts # Live CVE fetch from jgamblin/OpenClawCVEs
│   ├── skill-scanner.ts    # Static analysis + blocklist scanner
│   ├── config-reader.ts    # Reads ~/.openclaw/openclaw.json
│   ├── postinstall.ts      # Fetches advisory cache on npm install
│   └── index.ts            # Library exports
├── rules/                  # YAML audit rules (the core value)
│   ├── critical/           # 8 rules (25 pts each)
│   ├── high/               # 7 rules (10 pts each)
│   ├── medium/             # 8 rules (5 pts each)
│   ├── low/                # 1 rule (2 pts)
│   └── schema.yaml         # Rule schema documentation
├── patterns/               # Exec firewall pattern definitions
│   ├── dangerous.yaml      # 20 auto-deny patterns
│   └── suspicious.yaml     # 13 flag-for-review patterns
├── profiles/               # Hardening profile definitions
│   ├── locked-down.yaml
│   ├── coding-safe.yaml
│   ├── messaging-safe.yaml
│   └── dm-hardened.yaml
├── skills/                 # Skill security definitions
│   ├── static/             # 6 static analysis rule categories
│   └── blocklist/          # Known-malicious authors/campaigns
├── .github/
│   ├── ISSUE_TEMPLATE/     # 5 issue templates (new rule, blocklist, bug, etc.)
│   └── pull_request_template.md
├── dist/                   # Compiled output (not committed)
├── tests/
│   └── fixtures/           # Test config files
├── package.json
├── tsconfig.json
├── LICENSE                 # MIT
└── README.md
```

## Tech Stack

- **Language:** TypeScript (ES2022, ESM modules)
- **Build:** `tsc` (no bundler — straight TypeScript compilation)
- **Runtime:** Node.js >= 18 (uses native `fetch` in postinstall)
- **Dependencies:** `chalk` (terminal colors), `commander` (CLI), `yaml` (YAML parsing)
- **Dev:** `vitest` for testing
- **Output formats:** Text (human-readable), JSON, SARIF 2.1.0

## Build & Test

```bash
npm install
npm run build          # tsc → dist/
npm test               # vitest
node dist/cli.js audit --help
```

## Architecture

### Two-Component Scoring

The scoring system separates **config quality** from **vulnerability exposure**:

- **Config score (0-100):** Only misconfiguration findings affect the grade. Severity weights: critical=25, high=10, medium=5, low=2.
- **Grades:** A (90+), B (75-89), C (50-74), D (25-49), F (<25)
- **Vulnerability exposure:** CVE/advisory findings are displayed separately as informational. They don't affect the config grade — they require a gateway software update, not a config change.

This split lives in `scorer.ts`. The `AuditResult` type contains both `config_findings` and `vuln_findings` plus a `VulnSummary`.

### Rule Evaluation Engine

The engine (`engine.ts`) supports 13 check types for evaluating YAML rules against a gateway config:

| Check Type                       | Purpose                                    |
| -------------------------------- | ------------------------------------------ |
| `value_equals`                   | Config value must equal expected           |
| `value_in_set`                   | Config value must be in allowed set        |
| `value_not_in_list`              | Value must be present in config array      |
| `truthy` / `key_exists`          | Presence/truthiness checks                 |
| `string_length` / `string_match` | String validation                          |
| `cross_field`                    | Multiple conditions across config paths    |
| `iterate_map`                    | Check each entry in a config map           |
| `scan_keys`                      | Regex scan of config key names             |
| `url_check`                      | Validate URLs against trusted domains      |
| `version_compare`                | Semver comparison (for CVE checks)         |
| `custom`                         | Delegate to registered TypeScript function |

### Finding Metadata

When a rule fires, the resulting `Finding` carries:

- `rule_type` — `"misconfiguration"` or `"vulnerability"` (determines scoring bucket)
- `mitigates_cwes` — CWEs this config fix mitigates (for CVE cross-referencing)
- `cve`, `fixed_in` — CVE metadata (for vulnerability findings)

The reporter uses `mitigates_cwes` to show messages like "Fixing this also mitigates 19 active CVEs."

### Advisory Fetcher

`advisory-fetcher.ts` fetches live CVE/GHSA data from [jgamblin/OpenClawCVEs](https://github.com/jgamblin/OpenClawCVEs) (updated hourly). Each advisory becomes a `version_compare` rule. Results are cached to `~/.openclaw-carapace/cache/` for 1 hour.

### YAML Rules

Rules are the core value of this project. Each rule is a single YAML file with:

```yaml
id: rule_id
severity: critical|high|medium|low
title: "Human-readable title"
description: "What's wrong and why it matters"
recommendation: "Exactly what to change"
config_path: "dot.path.to.config"
auto_fixable: true|false
fix: # Optional: config.patch payload
  some.key: value
mitigates_cwes: ["CWE-78"] # Optional: CWE cross-references
check:
  type: value_equals # One of the 13 check types
  path: some.config.path
  value: expected_value
```

See `rules/schema.yaml` for the full schema documentation.

## Key Design Decisions

1. **YAML rules are the source of truth.** Both this CLI and the CoChat Python backend consume the same YAML files. CoChat downloads them from this GitHub repo at runtime.

2. **CVEs are fetched live, not bundled.** The `jgamblin/OpenClawCVEs` repo provides 80+ advisories updated hourly. We don't maintain static CVE copies.

3. **Config score and CVE exposure are separate.** A well-configured gateway on an old version gets an A config grade + a CVE warning. The grade reflects what you control today.

4. **Findings explain the "why" and the fix.** Every rule's `description` explains the risk, and `recommendation` tells you exactly what to change. Many rules are `auto_fixable` with a `fix` payload.

5. **Firewall patterns are reference data.** The CLI ships pattern YAML files used by CoChat's runtime firewall. The CLI itself doesn't run a firewall.

## CLI Commands

| Command                                 | Description                                |
| --------------------------------------- | ------------------------------------------ |
| `openclaw-carapace audit`               | Audit a gateway config (text/json/sarif)   |
| `openclaw-carapace skill scan <path>`   | Scan a skill directory for security issues |
| `openclaw-carapace skill blocklist`     | List known-malicious indicators            |
| `openclaw-carapace profiles list\|show` | View hardening profiles                    |
| `openclaw-carapace patterns`            | List exec firewall patterns                |
| `openclaw-carapace rules`               | List all audit rules                       |

## Exit Codes

| Code | Meaning                                  |
| ---- | ---------------------------------------- |
| 0    | Clean (no high/critical config findings) |
| 1    | High severity config finding             |
| 2    | Critical severity config finding         |
| 3    | Skill matches the blocklist              |

## Contributing

The most impactful contributions are **new audit rules** and **blocklist updates**. To add a new rule:

1. Create a YAML file in `rules/{severity}/` following the schema
2. The `description` should explain the risk, not just the setting
3. The `recommendation` should tell the user exactly what to change
4. Add `mitigates_cwes` if the rule mitigates known vulnerability classes
5. Run `npm run build && node dist/cli.js rules` to verify it loads

## Downstream Consumers

- **CoChat** (`cochat-open-webui` repo) — Python backend downloads these YAML files on startup, caches to `~/.openclaw-carapace/rules/`, and evaluates them with a Python port of the engine. The frontend displays results in the OpenClaw Carapace dashboard.
- **npm** — Published as `@cochatai/openclaw-carapace` for direct CLI and library usage.
