#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { auditPath, renderMarkdown } = require('../src/audit');

function usage() {
  console.log(`MCPLens — pre-install security audit for MCP servers

Usage:
  mcplens <path-to-server-folder|path-to-mcp.json> [--out-dir <dir>] [--fail-on <score>]

Options:
  --out-dir <dir>   Where to write audit-report.json and audit-report.md
                    (default: ./mcplens-report)
  --fail-on <score> Exit with code 2 when the risk score is >= <score>
                    (useful as a CI gate). Disabled by default.
  -h, --help        Show this help.

The audited code is never executed. Reports are static-analysis results.`);
}

function main(argv) {
  const args = argv.slice(2);
  if (!args.length || args.includes('-h') || args.includes('--help')) { usage(); return 0; }
  let target = null;
  let outDir = path.resolve('mcplens-report');
  let failOn = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out-dir') outDir = path.resolve(args[++i]);
    else if (args[i] === '--fail-on') failOn = Number(args[++i]);
    else if (!args[i].startsWith('-')) target = args[i];
    else { console.error(`Unknown option: ${args[i]}`); usage(); return 1; }
  }
  if (!target) { usage(); return 1; }

  let report;
  try {
    report = auditPath(target);
  } catch (err) {
    console.error(`MCPLens: ${err.message}`);
    return 1;
  }

  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'audit-report.json');
  const mdPath = path.join(outDir, 'audit-report.md');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(mdPath, renderMarkdown(report));

  console.log(`MCPLens audit: ${report.target}`);
  console.log(`Files scanned: ${report.filesScanned.length}`);
  console.log(`Permissions: ${report.permissions.filesystem.length} filesystem paths, ` +
    `${report.permissions.network.length} network domains, ` +
    `${report.permissions.environmentVariables.length} environment variables`);
  console.log(`Findings: ${report.summary.totalFindings} ` +
    `(critical ${report.summary.critical}, high ${report.summary.high}, ` +
    `medium ${report.summary.medium}, low ${report.summary.low}), ` +
    `prompt injection ${report.summary.promptInjection}`);
  console.log(`Risk score: ${report.riskScore}/100 (${report.riskLevel})`);
  console.log(`Reports written: ${jsonPath}`);
  console.log(`                 ${mdPath}`);

  if (failOn !== null && report.riskScore >= failOn) {
    console.error(`MCPLens: risk score ${report.riskScore} >= --fail-on ${failOn}, failing.`);
    return 2;
  }
  return 0;
}

if (require.main === module) process.exit(main(process.argv));
module.exports = { main };
