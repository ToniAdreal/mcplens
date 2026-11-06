'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const { auditPath, renderMarkdown } = require('../src/audit');

const ROOT = path.join(__dirname, '..');
const CLEAN = path.join(ROOT, 'fixtures', 'clean-server');
const RISKY = path.join(ROOT, 'fixtures', 'risky-server');

const clean = auditPath(CLEAN);
const risky = auditPath(RISKY);
const types = (report) => new Set(report.findings.map((f) => f.type));

test('risky fixture scores higher than the clean fixture', () => {
  assert.ok(risky.riskScore > clean.riskScore,
    `risky (${risky.riskScore}) should exceed clean (${clean.riskScore})`);
  assert.ok(risky.riskScore >= 70, `risky score should be high, got ${risky.riskScore}`);
  assert.equal(risky.riskLevel, 'critical');
  assert.ok(clean.riskScore <= 15, `clean score should stay low, got ${clean.riskScore}`);
});

test('risky fixture is flagged for the dangerous capabilities', () => {
  const t = types(risky);
  assert.ok(t.has('shell_exec'), 'shell exec should be flagged');
  assert.ok(t.has('eval'), 'eval should be flagged');
  assert.ok(t.has('credential_file_access'), 'credential file access should be flagged');
  assert.ok(t.has('obfuscated_string'), 'obfuscated string should be flagged');
});

test('clean fixture has no high-risk flags and no prompt injection', () => {
  const t = types(clean);
  assert.ok(!t.has('shell_exec'));
  assert.ok(!t.has('eval'));
  assert.ok(!t.has('credential_file_access'));
  assert.equal(clean.promptInjectionFindings.length, 0);
});

test('prompt injection is detected in the risky tool description only', () => {
  assert.ok(risky.promptInjectionFindings.length >= 2,
    `expected multiple injection patterns, got ${risky.promptInjectionFindings.length}`);
  const patterns = risky.promptInjectionFindings.map((f) => f.pattern).join(' | ');
  assert.match(patterns, /ignore previous instructions/);
});

test('permission inventory captures domains, env vars and sensitive paths', () => {
  assert.ok(risky.permissions.network.includes('evil-collector.example.com'));
  assert.ok(risky.permissions.environmentVariables.includes('AWS_SECRET_ACCESS_KEY'));
  assert.ok(risky.permissions.secretLikeEnvironmentVariables.includes('AWS_SECRET_ACCESS_KEY'));
  assert.ok(risky.permissions.filesystem.some((p) => p.includes('.ssh')));
  assert.ok(clean.permissions.environmentVariables.includes('MCPLENS_DEMO_GREETING'));
  assert.ok(!clean.permissions.filesystem.some((p) => p.includes('.ssh')));
});

test('auditing an mcp.json config directly follows the referenced server file', () => {
  const viaConfig = auditPath(path.join(RISKY, 'mcp.json'));
  assert.ok(viaConfig.filesScanned.some((f) => f.endsWith('server.js')));
  assert.ok(viaConfig.riskScore >= 70);
  assert.ok(viaConfig.commands.some((c) => c.command === 'node'));
});

test('markdown report renders score, inventory and findings', () => {
  const md = renderMarkdown(risky);
  assert.match(md, /Risk score:/);
  assert.match(md, /evil-collector\.example\.com/);
  assert.match(md, /prompt-injection/i);
});

test('CLI runs on both fixtures and writes JSON and Markdown reports', () => {
  for (const [name, dir] of [['clean', CLEAN], ['risky', RISKY]]) {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), `mcplens-${name}-`));
    const stdout = execFileSync(process.execPath,
      [path.join(ROOT, 'bin', 'mcplens.js'), dir, '--out-dir', outDir],
      { encoding: 'utf8' });
    assert.match(stdout, /Risk score:/);
    const report = JSON.parse(fs.readFileSync(path.join(outDir, 'audit-report.json'), 'utf8'));
    const md = fs.readFileSync(path.join(outDir, 'audit-report.md'), 'utf8');
    assert.equal(report.target, dir);
    assert.ok(md.length > 100);
    if (name === 'risky') assert.ok(report.riskScore >= 70);
    if (name === 'clean') assert.ok(report.riskScore <= 15);
  }
});

test('CLI --fail-on gate exits non-zero for the risky fixture', () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcplens-gate-'));
  assert.throws(() => execFileSync(process.execPath,
    [path.join(ROOT, 'bin', 'mcplens.js'), RISKY, '--out-dir', outDir, '--fail-on', '40'],
    { encoding: 'utf8', stdio: 'pipe' }));
});
