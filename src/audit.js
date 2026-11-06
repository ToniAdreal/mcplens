'use strict';

const fs = require('node:fs');
const path = require('node:path');

const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.json', '.py', '.md']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage']);

const INJECTION_PATTERNS = [
  { re: /ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?)/i, label: 'ignore previous instructions' },
  { re: /disregard\s+(all\s+)?(previous|prior|above|the)/i, label: 'disregard previous instructions' },
  { re: /do\s+not\s+tell\s+(the\s+)?user/i, label: 'do not tell the user' },
  { re: /don'?t\s+tell\s+(the\s+)?user/i, label: 'do not tell the user' },
  { re: /exfiltrat/i, label: 'exfiltration wording' },
  { re: /send\s+(the\s+)?.{0,40}(credentials?|secrets?|api[\s_-]?keys?|passwords?|tokens?|environment variables)/i, label: 'send secrets elsewhere' },
  { re: /reveal\s+(the\s+)?.{0,30}(system prompt|credentials?|secrets?|api[\s_-]?keys?)/i, label: 'reveal secrets / system prompt' },
  { re: /override\s+(the\s+)?.{0,20}(instructions?|system|rules?|safety)/i, label: 'override instructions' },
  { re: /hidden\s+instruction/i, label: 'hidden instruction' },
  { re: /you\s+must\s+(always|never)\b/i, label: 'coercive must-always/never wording' },
  { re: /system\s+prompt/i, label: 'mentions system prompt' },
];

const SECRET_ENV_RE = /(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)/i;
// Note: a bare ".env" here means a dotenv FILE (".env", "./.env", ".env.local"),
// never process.env.<NAME> property access, hence the separate ENV_FILE_RE.
const SENSITIVE_PATH_RE = /(\.ssh|id_rsa|id_ed25519|\.aws[\\/]credentials|\.git-credentials|\.npmrc|credentials\.json|\.kube[\\/]config|\.gnupg)/i;
const ENV_FILE_RE = /["'`][^"'`]*\.env(\.[A-Za-z0-9_-]+)?["'`]/;
function isSensitiveLine(line) { return SENSITIVE_PATH_RE.test(line) || ENV_FILE_RE.test(line); }
function isSensitiveLiteral(lit) { return SENSITIVE_PATH_RE.test(lit) || /(^|\/)\.env(\.|$)/.test(lit); }

function isTextFile(file) {
  return TEXT_EXTENSIONS.has(path.extname(file).toLowerCase()) || path.basename(file) === 'mcp.json';
}

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(full, out);
    } else if (entry.isFile() && isTextFile(full)) {
      out.push(full);
    }
  }
  return out;
}

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

function addFinding(findings, type, severity, file, line, evidence, message) {
  findings.push({ type, severity, file, line, evidence: String(evidence).slice(0, 160), message });
}

function extractStringLiterals(line) {
  const literals = [];
  const re = /(["'`])((?:\\.|(?!\1)[^\\])*?)\1/g;
  let m;
  while ((m = re.exec(line)) !== null) literals.push(m[2]);
  return literals;
}

function scanFile(file, rel, content, acc) {
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    const lineNo = idx + 1;

    // Environment variables: process.env.X / process.env['X'] / os.environ
    for (const m of line.matchAll(/process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g)) acc.env.add(m[1]);
    for (const m of line.matchAll(/process\.env\[['"]([^'"]+)['"]\]/g)) acc.env.add(m[1]);
    for (const m of line.matchAll(/environ(?:\.get)?\(['"]([^'"]+)['"]\)/g)) acc.env.add(m[1]);

    // Network domains from URLs
    for (const m of line.matchAll(/(?:https?|wss?):\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?/g)) acc.network.add(m[1]);

    // Filesystem-looking string literals
    for (const lit of extractStringLiterals(line)) {
      if (/^(~|\/|\.\/|\.\.\/|[A-Za-z]:\\)/.test(lit) || isSensitiveLiteral(lit)) {
        if (lit.length >= 2 && !/^https?:\/\//.test(lit)) acc.filesystem.add(lit);
      }
      // Bare domains inside fetch/request-style strings
      if (/\bfetch\s*\(|\baxios\b|\brequest\s*\(/.test(line)) {
        const d = lit.match(/^([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:\/|$)/);
        if (d) acc.network.add(d[1]);
      }
    }
    if (isSensitiveLine(line)) {
      const lits = extractStringLiterals(line).filter((l) => isSensitiveLiteral(l));
      if (lits.length) lits.forEach((l) => acc.filesystem.add(l));
      addFinding(acc.findings, 'credential_file_access', 'critical', rel, lineNo, line.trim(),
        'References a credential / SSH / secret file location.');
    }

    // Shell execution
    if (/child_process/.test(line) || /\b(exec|execSync|execFile|spawn|spawnSync)\s*\(/.test(line)) {
      addFinding(acc.findings, 'shell_exec', 'high', rel, lineNo, line.trim(),
        'Shell execution capability (child_process / exec / spawn).');
    }
    // eval / dynamic code
    if (/\beval\s*\(/.test(line) || /new\s+Function\s*\(/.test(line)) {
      addFinding(acc.findings, 'eval', 'high', rel, lineNo, line.trim(),
        'Dynamic code evaluation (eval / new Function).');
    }
    // Obfuscation: long base64 blobs, hex escapes, atob / base64 decode
    if (/[A-Za-z0-9+/]{48,}={0,2}/.test(line) || /(\\x[0-9a-fA-F]{2}){4,}/.test(line) ||
        /\batob\s*\(/.test(line) || /Buffer\.from\([^)]*['"]base64['"]\)/.test(line)) {
      addFinding(acc.findings, 'obfuscated_string', 'medium', rel, lineNo, line.trim(),
        'Possibly obfuscated string (long base64 / hex escapes / base64 decode).');
    }
    // Filesystem API use (inventory only, low on its own)
    if (/\bfs\.(readFile|writeFile|readdir|createReadStream|createWriteStream)|readFileSync|writeFileSync/.test(line)) {
      addFinding(acc.findings, 'filesystem_api', 'low', rel, lineNo, line.trim(),
        'Uses a filesystem read/write API.');
    }
  });

  // Prompt injection inside tool description strings (whole-file, multiline
  // aware, including descriptions built from concatenated string literals)
  const descRe = /description\s*[:=]\s*((?:(["'`])(?:\\.|(?!\2)[\s\S])*?\2\s*(?:\+\s*)?)+)/g;
  let dm;
  while ((dm = descRe.exec(content)) !== null) {
    const text = [...dm[1].matchAll(/(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/g)].map((x) => x[2]).join(' ');
    for (const pat of INJECTION_PATTERNS) {
      if (pat.re.test(text)) {
        const finding = {
          type: 'prompt_injection', severity: 'critical', file: rel,
          line: lineOf(content, dm.index), evidence: text.slice(0, 160),
          message: `Tool description contains a prompt-injection pattern: ${pat.label}.`,
          pattern: pat.label,
        };
        acc.findings.push(finding);
        acc.promptInjection.push(finding);
      }
    }
  }
}

function scanMcpConfig(file, rel, content, acc, baseDir) {
  let cfg;
  try { cfg = JSON.parse(content); } catch { return []; }
  const servers = cfg.mcpServers || cfg.servers || {};
  const referenced = [];
  for (const [name, srv] of Object.entries(servers)) {
    if (!srv || typeof srv !== 'object') continue;
    if (srv.command) {
      addFinding(acc.findings, 'config_command', 'low', rel, 1, `${name}: ${srv.command}`,
        `Config launches a command for server "${name}". Review it like any installed binary.`);
      acc.commands.push({ server: name, command: srv.command, args: Array.isArray(srv.args) ? srv.args : [] });
    }
    if (srv.env && typeof srv.env === 'object') {
      for (const key of Object.keys(srv.env)) acc.env.add(key);
    }
    if (Array.isArray(srv.args)) {
      for (const arg of srv.args) {
        if (typeof arg !== 'string') continue;
        if (/^(~|\/|\.\/|\.\.\/)/.test(arg) || /\.m?js$|\.py$/.test(arg)) {
          acc.filesystem.add(arg);
          const candidate = path.resolve(baseDir, arg.replace(/^~\//, ''));
          if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) referenced.push(candidate);
        }
        const d = arg.match(/(?:https?|wss?):\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
        if (d) acc.network.add(d[1]);
      }
    }
    if (srv.url) {
      const d = String(srv.url).match(/(?:https?|wss?):\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
      if (d) acc.network.add(d[1]);
    }
  }
  return referenced;
}

function computeRiskScore(findings, env, network) {
  let score = 0;
  const byType = {};
  for (const f of findings) byType[f.type] = (byType[f.type] || 0) + 1;
  score += Math.min(25, (byType.shell_exec || 0) * 15);
  score += Math.min(20, (byType.eval || 0) * 15);
  score += Math.min(25, (byType.credential_file_access || 0) * 20);
  score += Math.min(30, (byType.prompt_injection || 0) * 20);
  score += Math.min(15, (byType.obfuscated_string || 0) * 10);
  score += Math.min(10, (byType.filesystem_api || 0) * 2);
  for (const name of env) if (SECRET_ENV_RE.test(name)) score += 5;
  score += Math.min(10, network.size * 3);
  return Math.max(0, Math.min(100, score));
}

function riskLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  if (score > 0) return 'low';
  return 'minimal';
}

function auditPath(target) {
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Target not found: ${target}`);
  }
  const stat = fs.statSync(resolved);
  const baseDir = stat.isDirectory() ? resolved : path.dirname(resolved);

  let files = stat.isDirectory() ? walk(resolved) : [resolved];
  const acc = {
    env: new Set(), network: new Set(), filesystem: new Set(),
    findings: [], promptInjection: [], commands: [],
  };

  // First pass: configs may reference server entry files outside the folder.
  for (const file of [...files]) {
    const rel = path.relative(baseDir, file) || path.basename(file);
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (path.basename(file) === 'mcp.json' || /mcp.*\.json$/i.test(path.basename(file))) {
      for (const ref of scanMcpConfig(file, rel, content, acc, baseDir)) {
        if (!files.includes(ref)) files.push(ref);
      }
    }
  }
  for (const file of files) {
    const rel = path.relative(baseDir, file) || path.basename(file);
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    scanFile(file, rel, content, acc);
  }

  const envList = [...acc.env].sort();
  const networkList = [...acc.network].sort();
  const fsList = [...acc.filesystem].sort();
  const score = computeRiskScore(acc.findings, acc.env, acc.network);

  return {
    tool: 'MCPLens',
    version: '0.1.0',
    target: resolved,
    scannedAt: new Date().toISOString(),
    filesScanned: files.map((f) => path.relative(baseDir, f) || path.basename(f)).sort(),
    permissions: {
      filesystem: fsList,
      network: networkList,
      environmentVariables: envList,
      secretLikeEnvironmentVariables: envList.filter((n) => SECRET_ENV_RE.test(n)),
    },
    commands: acc.commands,
    promptInjectionFindings: acc.promptInjection,
    findings: acc.findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line),
    riskScore: score,
    riskLevel: riskLevel(score),
    summary: {
      totalFindings: acc.findings.length,
      critical: acc.findings.filter((f) => f.severity === 'critical').length,
      high: acc.findings.filter((f) => f.severity === 'high').length,
      medium: acc.findings.filter((f) => f.severity === 'medium').length,
      low: acc.findings.filter((f) => f.severity === 'low').length,
      promptInjection: acc.promptInjection.length,
    },
  };
}

function renderMarkdown(report) {
  const lines = [];
  lines.push(`# MCPLens Audit Report`);
  lines.push('');
  lines.push(`- Target: \`${report.target}\``);
  lines.push(`- Scanned at: ${report.scannedAt}`);
  lines.push(`- Files scanned: ${report.filesScanned.length}`);
  lines.push(`- **Risk score: ${report.riskScore}/100 (${report.riskLevel})**`);
  lines.push('');
  lines.push('## Permission inventory');
  lines.push('');
  lines.push('### Filesystem paths touched');
  lines.push(report.permissions.filesystem.length ? report.permissions.filesystem.map((p) => `- \`${p}\``).join('\n') : '- (none detected)');
  lines.push('');
  lines.push('### Network domains contacted');
  lines.push(report.permissions.network.length ? report.permissions.network.map((p) => `- ${p}`).join('\n') : '- (none detected)');
  lines.push('');
  lines.push('### Environment variables read');
  lines.push(report.permissions.environmentVariables.length ? report.permissions.environmentVariables.map((p) => `- ${p}`).join('\n') : '- (none detected)');
  lines.push('');
  if (report.commands.length) {
    lines.push('## Commands launched by config');
    for (const c of report.commands) lines.push(`- ${c.server}: \`${c.command} ${(c.args || []).join(' ')}\``);
    lines.push('');
  }
  lines.push('## Findings');
  lines.push('');
  if (!report.findings.length) {
    lines.push('No risky patterns detected by the static checks.');
  } else {
    lines.push('| Severity | Type | Location | Evidence |');
    lines.push('| --- | --- | --- | --- |');
    for (const f of report.findings) {
      const ev = String(f.evidence).replace(/\|/g, '\\|').replace(/\n/g, ' ');
      lines.push(`| ${f.severity} | ${f.type} | ${f.file}:${f.line} | \`${ev}\` |`);
    }
  }
  lines.push('');
  lines.push('## Prompt-injection check');
  lines.push('');
  lines.push(report.promptInjectionFindings.length
    ? report.promptInjectionFindings.map((f) => `- ${f.file}:${f.line} — ${f.message}`).join('\n')
    : 'No prompt-injection patterns found in tool descriptions.');
  lines.push('');
  lines.push('## Notes');
  lines.push('');
  lines.push('MCPLens is a static, pre-install audit. It reads source and config text only; it never executes the audited server. A clean result is not a guarantee of safety, and a flagged pattern can be legitimate in context. Review critical and high findings before installing.');
  lines.push('');
  return lines.join('\n');
}

module.exports = { auditPath, renderMarkdown, computeRiskScore, riskLevel };
