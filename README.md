# MCPLens

**Audit an MCP server before you install it.**

Installing an MCP (Model Context Protocol) server means running somebody
else's code inside your agent workflow. That code can read files, read
environment variables, open network connections and run shell commands.
Tool descriptions are text your model will read, so a description can also
carry prompt-injection instructions aimed at the model. Today most teams
install MCP servers with no audit at all. MCPLens is the pre-install check:
point it at a server folder or an `mcp.json` config, and it tells you what
that server can touch and what looks risky, before anything runs.

MCPLens is a static auditor. It reads source and config text only and never
executes the audited server. It has zero dependencies and runs anywhere
Node 18 or newer runs.

## What it reports

- **Permission inventory**: filesystem paths referenced, network domains
  contacted, environment variables read, with secret-looking variables
  (tokens, API keys, passwords) called out separately.
- **Risky pattern flags**: shell execution (`child_process`, `exec`,
  `spawn`), dynamic code evaluation (`eval`, `new Function`), references to
  credential locations (SSH keys, AWS credentials, dotenv files,
  `.git-credentials`, `.npmrc`), and obfuscated strings (long base64 blobs,
  hex escapes, base64 decoding).
- **Prompt-injection detection**: tool `description` strings, including
  descriptions assembled from concatenated string literals, are checked for
  injection patterns such as instructions to ignore previous instructions,
  hide actions from the user, send credentials elsewhere, or reveal the
  system prompt.
- **Risk score**: a simple weighted score from 0 to 100 with a level
  (minimal, low, medium, high, critical), designed to be explainable from
  the findings list rather than treated as a verdict.
- **Reports in Markdown and JSON**: the Markdown report reads well in a
  pull request or a ticket; the JSON report feeds CI and dashboards.

## Usage

```bash
# Audit a server folder
node bin/mcplens.js path/to/mcp-server --out-dir reports/my-server

# Audit an mcp.json config (referenced local server files are followed)
node bin/mcplens.js path/to/mcp.json --out-dir reports/from-config

# Try it on the bundled fixtures
npm run audit:clean   # writes reports/clean
npm run audit:risky   # writes reports/risky

# CI gate: fail the build when the score reaches a threshold
node bin/mcplens.js path/to/mcp-server --fail-on 40
```

Exit codes: 0 for a completed audit, 1 for a usage or IO error, 2 when the
`--fail-on` threshold is reached.

## Fixtures

Two sample servers live under `fixtures/`:

- `fixtures/clean-server`: two harmless tools, no filesystem or network
  access, one non-secret environment variable. MCPLens scores it
  **0/100 (minimal)**.
- `fixtures/risky-server`: a clearly marked **test fixture** that contains
  the pattern shapes MCPLens detects: shell execution, `eval`, SSH and AWS
  credential paths, a secret-named environment variable set, an obfuscated
  base64 sample, an `.example` collector domain, and a tool description
  carrying prompt-injection text. Every dangerous-looking snippet sits
  inside a function that is never called, the constants are inert strings,
  and the domains use the reserved `.example` TLD. It never reads a real
  credential file and never contacts a real server. MCPLens scores it
  **100/100 (critical)**. Sample reports for both fixtures are committed
  under `reports/`.

## Tests

```bash
npm test
```

Nine tests run the auditor against both fixtures and assert the risky
fixture scores higher and gets flagged for shell execution, `eval`,
credential access, obfuscation and prompt injection, that the clean fixture
stays clean, that auditing an `mcp.json` directly follows the referenced
server file, and that the CLI writes both report formats and honors the
`--fail-on` gate.

## Who it is for

Development teams and platform engineers who are adopting MCP across a
team. One developer installing one server is a small risk. Fifty developers
installing whatever servers they find, with shared credentials in their
environment, is a supply-chain problem. MCPLens gives the team one shared,
repeatable pre-install check and an artifact (the report) that a reviewer
can actually read.

## Monetization

- **Free CLI (this repo)**: the auditor, fixtures and report formats are
  free. Adoption first, because an audit tool only matters once teams run
  it by default.
- **Paid team CI plan**: per-repository pricing for a hosted CI service
  that audits every `mcp.json` change in pull requests, blocks merges above
  a score threshold the team sets, tracks score history per server, and
  alerts when an updated server gains new permissions (a new domain, a new
  credential path, a changed tool description). Permission drift alerts are
  the part teams cannot easily build themselves from the CLI alone.
- Later: a registry of community-submitted audit reports for popular public
  MCP servers, so a team can check a server's current report before anyone
  downloads it.

## Layout

```
bin/mcplens.js            CLI entry point
src/audit.js              Scanner, scoring, Markdown renderer
fixtures/clean-server/    Known-good sample server
fixtures/risky-server/    Test fixture with planted pattern samples
reports/                  Sample reports generated from the fixtures
test/auditor.test.js      node --test suite
```

## Limitations

Static text scanning has blind spots. It cannot see permissions a server
requests at runtime through dynamic imports or remote code, and a flagged
pattern can be legitimate in context (a backup tool really does read many
files). Treat the score as a triage signal: critical and high findings get
a human review before install, and the audit complements, rather than
replaces, sandboxing and least-privilege credentials.
