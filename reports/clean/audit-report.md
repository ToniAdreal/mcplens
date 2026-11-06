# MCPLens Audit Report

- Target: `/home/hatch/workspace/team247-proposals/mcplens/fixtures/clean-server`
- Scanned at: 2026-11-06T09:28:58.084Z
- Files scanned: 3
- **Risk score: 0/100 (minimal)**

## Permission inventory

### Filesystem paths touched
- `server.js`

### Network domains contacted
- (none detected)

### Environment variables read
- MCPLENS_DEMO_GREETING

## Commands launched by config
- clean-demo: `node server.js`

## Findings

| Severity | Type | Location | Evidence |
| --- | --- | --- | --- |
| low | config_command | mcp.json:1 | `clean-demo: node` |

## Prompt-injection check

No prompt-injection patterns found in tool descriptions.

## Notes

MCPLens is a static, pre-install audit. It reads source and config text only; it never executes the audited server. A clean result is not a guarantee of safety, and a flagged pattern can be legitimate in context. Review critical and high findings before installing.
