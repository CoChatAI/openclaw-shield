#!/usr/bin/env node

import { Command } from "commander";
import { readConfig } from "./config-reader.js";
import {
  loadRules,
  loadPatterns,
  loadProfiles,
  loadSkillRules,
  loadSkillBlocklist,
} from "./loader.js";
import {
  fetchAdvisoryRules,
  loadCachedAdvisoryRules,
} from "./advisory-fetcher.js";
import type { Rule } from "./types.js";
import { evaluateRules } from "./engine.js";
import { scanSkill } from "./skill-scanner.js";
import { buildAuditResult } from "./scorer.js";
import {
  reportText,
  reportJson,
  reportSarif,
  reportProfiles,
  reportPatterns,
  reportRulesList,
  reportSkillScan,
} from "./reporter.js";

const program = new Command();

program
  .name("openclaw-carapace")
  .description(
    "Security auditor, CVE checker, and skill scanner for OpenClaw gateways",
  )
  .version("0.1.0");

// ---------------------------------------------------------------------------
// audit — config + vulnerability checks combined
// ---------------------------------------------------------------------------

program
  .command("audit")
  .description(
    "Audit an OpenClaw gateway config for misconfigurations and known CVEs",
  )
  .option("-c, --config <path>", "Path to openclaw.json")
  .option("-f, --format <format>", "Output format: text, json, sarif", "text")
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity: critical, high, medium, low",
    "low",
  )
  .option("--rules-dir <path>", "Custom rules directory")
  .option("--no-vulns", "Skip CVE/vulnerability checks")
  .option(
    "--offline",
    "Don't fetch advisories from network (use cache/static only)",
  )
  .action(async (opts) => {
    try {
      const { config, path: configPath } = readConfig(opts.config);

      // Load config audit rules
      const rules = loadRules(opts.rulesDir);

      // Load vulnerability rules — fetch live advisories or use cache
      let vulnRules: Rule[] = [];
      if (opts.vulns !== false) {
        if (opts.offline) {
          vulnRules = loadCachedAdvisoryRules();
        } else {
          try {
            vulnRules = await fetchAdvisoryRules();
          } catch {
            // Network failed — fall back to cache
            vulnRules = loadCachedAdvisoryRules();
          }
        }
        if (vulnRules.length === 0 && opts.format === "text") {
          console.error(
            "  ⚠ No vulnerability data available. Run without --offline to fetch advisories.",
          );
        }
      }

      // Combine and evaluate
      const allRules = [...rules, ...vulnRules];
      const findings = evaluateRules(allRules, config);

      // Filter by min severity
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const minIdx = severityOrder.indexOf(opts.minSeverity);
      const filtered =
        minIdx >= 0
          ? findings.filter((f) => severityOrder.indexOf(f.severity) <= minIdx)
          : findings;

      const result = buildAuditResult(filtered, allRules.length, configPath);

      if (opts.format === "sarif") {
        console.log(reportSarif(result));
      } else if (opts.format === "json") {
        console.log(reportJson(result));
      } else {
        console.log(reportText(result));
      }

      const hasCritical = filtered.some((f) => f.severity === "critical");
      const hasHigh = filtered.some((f) => f.severity === "high");
      if (hasCritical) process.exit(2);
      if (hasHigh) process.exit(1);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// skill — scan skills for security issues
// ---------------------------------------------------------------------------

const skillCmd = program
  .command("skill")
  .description("Scan OpenClaw skills for security issues");

skillCmd
  .command("scan <path>")
  .description(
    "Scan a skill directory for security issues and blocklist matches",
  )
  .option("-f, --format <format>", "Output format: text, json", "text")
  .option("--author <author>", "Skill author (for blocklist check)")
  .option("--name <name>", "Skill name (for blocklist check)")
  .action((skillPath, opts) => {
    try {
      const staticRules = loadSkillRules();
      const blocklist = loadSkillBlocklist();

      const result = scanSkill(skillPath, staticRules, blocklist, {
        author: opts.author,
        name: opts.name,
      });

      if (opts.format === "json") {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(reportSkillScan(result));
      }

      if (result.blocked) process.exit(3);
      if (result.findings.some((f) => f.severity === "critical"))
        process.exit(2);
      if (result.findings.some((f) => f.severity === "high")) process.exit(1);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
  });

skillCmd
  .command("blocklist")
  .description("List known-malicious skill indicators")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .action((opts) => {
    const blocklist = loadSkillBlocklist();
    if (opts.format === "json") {
      console.log(JSON.stringify(blocklist, null, 2));
    } else {
      console.log("");
      console.log("  OpenClaw Carapace Skill Blocklist");
      console.log("");
      for (const entry of blocklist) {
        console.log(`  [${entry.severity}] ${entry.id}: ${entry.title}`);
        if (entry.indicators.authors?.length) {
          console.log(`    Authors: ${entry.indicators.authors.join(", ")}`);
        }
        if (entry.indicators.c2_ips?.length) {
          console.log(`    C2 IPs: ${entry.indicators.c2_ips.join(", ")}`);
        }
        if (entry.indicators.domains?.length) {
          console.log(`    Domains: ${entry.indicators.domains.join(", ")}`);
        }
        console.log("");
      }
    }
  });

// ---------------------------------------------------------------------------
// profiles
// ---------------------------------------------------------------------------

const profilesCmd = program
  .command("profiles")
  .description("View hardening profiles");

profilesCmd
  .command("list")
  .description("List available hardening profiles")
  .option("--profiles-dir <path>", "Custom profiles directory")
  .action((opts) => {
    const profiles = loadProfiles(opts.profilesDir);
    console.log(reportProfiles(profiles));
  });

profilesCmd
  .command("show <id>")
  .description("Show details for a hardening profile")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .option("--profiles-dir <path>", "Custom profiles directory")
  .action((id, opts) => {
    const profiles = loadProfiles(opts.profilesDir);
    const profile = profiles.find((p) => p.id === id);
    if (!profile) {
      console.error(`Profile not found: ${id}`);
      console.error(`Available: ${profiles.map((p) => p.id).join(", ")}`);
      process.exit(1);
    }
    if (opts.format === "json") {
      console.log(JSON.stringify(profile, null, 2));
    } else {
      console.log(reportProfiles([profile]));
      console.log("  Config patch:");
      console.log(JSON.stringify(profile.patch, null, 2));
    }
  });

// ---------------------------------------------------------------------------
// patterns
// ---------------------------------------------------------------------------

program
  .command("patterns")
  .description("List built-in exec firewall patterns")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .option("--patterns-dir <path>", "Custom patterns directory")
  .action((opts) => {
    const catalog = loadPatterns(opts.patternsDir);
    if (opts.format === "json") {
      console.log(JSON.stringify(catalog, null, 2));
    } else {
      console.log(reportPatterns(catalog));
    }
  });

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

program
  .command("rules")
  .description("List all audit rules (config + vulnerability)")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .option("--rules-dir <path>", "Custom rules directory")
  .option("--offline", "Don't fetch advisories from network")
  .action(async (opts) => {
    const configRules = loadRules(opts.rulesDir);
    let vulnRules: Rule[];
    if (opts.offline) {
      vulnRules = loadCachedAdvisoryRules();
    } else {
      try {
        vulnRules = await fetchAdvisoryRules();
      } catch {
        vulnRules = loadCachedAdvisoryRules();
      }
    }
    const allRules = [...configRules, ...vulnRules];
    if (opts.format === "json") {
      console.log(JSON.stringify(allRules, null, 2));
    } else {
      console.log(reportRulesList(allRules));
    }
  });

program.parse();
