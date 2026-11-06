# MCPLens Build Notes

Built 2026-11-06 as demo P2 of the Team247 proposal set (see
`../PLAN.md`). Environment: Node v24.22.1, npm 10.9.4, zero npm
dependencies (nothing to install, `npm install` is a no-op for this repo).

## What was built

- `src/audit.js`: static scanner, permission inventory (filesystem paths,
  network domains, environment variables), risky-pattern detection (shell
  exec, eval, credential file locations, obfuscated strings),
  prompt-injection detection inside tool description strings (including
  descriptions assembled from concatenated literals), weighted risk score
  (0 to 100), Markdown report renderer.
- `bin/mcplens.js`: CLI. Accepts a server folder or an `mcp.json` config
  (referenced local server files are followed), `--out-dir`, and a
  `--fail-on <score>` CI gate (exit code 2).
- `fixtures/clean-server`: harmless two-tool sample server.
- `fixtures/risky-server`: marked test fixture. Dangerous-looking snippets
  live inside a `dormant()` function that is never called, constants are
  inert strings, domains use the reserved `.example` TLD. It never reads a
  real credential file and never contacts a real server.
- `test/auditor.test.js`: 9 tests on the built-in `node --test` runner.
- `reports/clean` and `reports/risky`: generated sample reports, committed
  as demo evidence.

## Bugs found and fixed during the build

1. First clean-fixture run scored 20/100 with a false critical finding:
   `process.env.MCPLENS_DEMO_GREETING` matched the dotenv-file pattern
   `.env.` inside the sensitive-path regex. Fixed by splitting detection:
   `SENSITIVE_PATH_RE` no longer contains a bare `.env` alternative, and a
   separate `ENV_FILE_RE` only matches a quoted dotenv filename
   (`".env"`, `"./.env.production"`). After the fix the clean fixture
   scores 0/100 and the risky fixture still flags its `./.env.production`
   sample.
2. The risky fixture builds its tool description from three concatenated
   string literals, and the first scanner version only inspected the first
   literal, missing the injection patterns in the later segments. Fixed by
   reconstructing the full description text from all concatenated literals
   before pattern matching. Detected injection patterns in the risky
   fixture went from 2 to 6.
3. `node --test test/` (directory form) fails on this machine's Node
   v24.22.1 with a MODULE_NOT_FOUND runner error, while the explicit file
   form works. The npm test script therefore uses
   `node --test test/auditor.test.js`.

## Verification (exact commands and results, final run)

```
$ node --version
v24.22.1

$ node bin/mcplens.js fixtures/clean-server --out-dir reports/clean
Files scanned: 3
Permissions: 1 filesystem paths, 0 network domains, 1 environment variables
Findings: 1 (critical 0, high 0, medium 0, low 1), prompt injection 0
Risk score: 0/100 (minimal)
exit: 0

$ node bin/mcplens.js fixtures/risky-server --out-dir reports/risky
Files scanned: 3
Permissions: 4 filesystem paths, 1 network domains, 4 environment variables
Findings: 16 (critical 9, high 3, medium 2, low 2), prompt injection 6
Risk score: 100/100 (critical)
exit: 0

# Filesystem inventory for the risky fixture:
#   ${os.homedir()}/.aws/credentials, ${os.homedir()}/.ssh/id_rsa,
#   ./.env.production, server.js (the config's entry argument)
# Network inventory: evil-collector.example.com
# Env inventory: AWS_SECRET_ACCESS_KEY, FAKE_EXAMPLE_API_TOKEN,
#   GITHUB_TOKEN, OPENAI_API_KEY (all four flagged secret-like)
# Injection patterns detected: ignore previous instructions,
#   do not tell the user, exfiltration wording, send secrets elsewhere,
#   reveal secrets / system prompt, mentions system prompt

$ node bin/mcplens.js fixtures/risky-server/mcp.json --out-dir reports/risky-config
Files scanned: 2 (mcp.json plus the referenced server.js)
Risk score: 100/100 (critical)
# Config-direct mode works; the scratch reports/risky-config output was
# removed after verification and is not committed.

$ node bin/mcplens.js fixtures/risky-server --out-dir /tmp/mcplens-gate --fail-on 40
Risk score: 100/100 (critical)
MCPLens: risk score 100 >= --fail-on 40, failing.
exit: 2

$ npm test        (node --test test/auditor.test.js)
tests 9, pass 9, fail 0
```

Fixture safety check:

```
$ node -e "const m = require('./fixtures/risky-server/server.js');
           console.log(m.dormantFixtureMarker)"
TEST_FIXTURE_ONLY        (loads without executing any dormant snippet)

$ node -e "const m = require('./fixtures/clean-server/server.js');
           console.log(m.callTool('add', {a: 2, b: 3}).content[0].text)"
5
```

## Known limits

Static text scanning only. Runtime permission requests, dynamic imports
and remote code are invisible to it, and a flagged pattern can be
legitimate in context. The score is a triage signal for human review, and
the README states this plainly.
