# secretsweep

[English] · [简体中文](README_CN.md)

[![CI](https://github.com/xuange-hu/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/secretsweep/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-435-brightgreen)](#coverage)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](#zero-dependencies)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Zero-dependency credential leak scanner.** 86 provider rules, entropy detection,
placeholder triage, and baseline diffs that make it usable as a PR gate instead
of a one-off report.

```bash
pip install secretsweep-audit      # or: uvx --from secretsweep-audit secretsweep
secretsweep scan .
```

The leading tools in this space are excellent and written in Go (gitleaks ~30k★,
trufflehog ~28k★). The Python slot is served by detect-secrets, which carries
dependencies and a plugin architecture. secretsweep is the other shape: one
import-free package, deterministic, fast enough to run on every commit.

---

## Three steps

```bash
pip install secretsweep-audit
secretsweep demo                   # 1. see it work on a repo that leaks on purpose
secretsweep scan .                 # 2. scan your own tree
```

```text
$ secretsweep scan .
src/config.py
  CRITICAL     4:17  github-pat  ghp_************7g
          GitHub personal access token | confidence=likely entropy=5.17
          classic personal access token (repo + org scopes possible)
  CRITICAL     5:31  postgres-uri  R7kQ******Zx
          PostgreSQL URI with password | confidence=likely entropy=3.58
  HIGH         2:22  aws-access-key-id  AKIA************PU
          AWS access key id | confidence=likely entropy=4.22
          long-lived IAM user key
```

---

## What it does differently

### 1. It separates real leaks from documented examples

Most false positives are not "strings that look like keys" - they are
*documented* keys. `AKIAIOSFODNN7EXAMPLE` matches every AWS regex ever written.
secretsweep scores each candidate:

| confidence | meaning | default |
|---|---|---|
| `real` / `likely` | nothing says it is fake | reported |
| `placeholder` | known example value, template reference, repeated/sequential bytes, `<your-key-here>` | hidden (`--show-placeholders` to see them) |

### 2. It reads the room, not just the string

The same 40 characters mean different things in `docs/example.env` and in
`.github/workflows/deploy.yml`. Every finding carries the bucket it was found in
(`source`, `config`, `ci`, `test`, `example`, `docs`, `vendor`, `lockfile`) and
the severity is adjusted from there:

```text
tests/fixtures/tokens.json
  INFO         2:13  generic-token-assignment  R7kQ************7g
          Generic token assignment | confidence=likely | bucket=test
          bucket:test
```

### 3. It tells you what the credential can do

Offline inference from the shape of the value - no network calls, nothing leaves
the machine:

- `AKIA…` is a long-lived IAM user key; `ASIA…` is a temporary STS session that
  expires on its own; `AGPA…` cannot sign requests at all.
- `ghp_…` is a classic token that cannot be scoped to one repo; `github_pat_…`
  is fine-grained.
- `sk_live_…` moves real money; `sk_test_…` does not.
- A JWT is decoded (not verified) to report `alg`, `sub`, and `exp` - an expired
  token is downgraded a level because it is not what you rotate first.

### 4. Baselines: the only way this survives an old repository

```bash
secretsweep baseline .                       # snapshot what is already there
secretsweep scan . --baseline .secretsweep-baseline.json
```

Fingerprints are `path|rule|value-hash`, so a baseline survives line drift but a
*new* secret in a baselined file still fails the build. `--prune` shrinks the
baseline as leaks get fixed.

---

## Commands

| command | what it does |
|---|---|
| `scan [PATH]` | scan a file or a tree; `--json`, `--sarif`, `--history`, `--baseline` |
| `baseline PATH` | write a baseline so only *new* leaks fail CI |
| `diff PATH --baseline F` | show new / resolved without writing anything |
| `rules [--tag T]` | list the 86 rules and their entropy gates |
| `entropy VALUE` | explain one string: length, charset, bits/char |
| `demo` | write a leaky repo and scan it |

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`),
`2` usage error.

Useful scan flags: `--min-severity`, `--entropy-min` (raise every gate),
`--tag`, `--exclude-rule`, `--ignore-glob`, `--skip-dir`, `--show-placeholders`,
`--no-inline-ignore`, `--no-evidence`.

### Inline suppressions

```python
TOKEN = "ghp_..."        # secretsweep:ignore
KEY = "AKIA..."          # secretsweep:ignore[aws-access-key-id]
```

### `.secretsweepignore`

gitignore-style globs, read from the scan root:

```gitignore
# the rule library carries one sample per rule - fixtures, not leaks
src/secretsweep/samples.py
tests/**
```

---

## CI

```yaml
- name: secret scan
  run: |
    pip install secretsweep-audit
    secretsweep scan . --baseline .secretsweep-baseline.json --sarif secrets.sarif.json
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: secrets.sarif.json
```

SARIF 2.1.0 output includes `security-severity`, so findings land in code
scanning with the right ranking.

---

## GitHub Action

```yaml
- uses: xuange-hu/secretsweep@v1
  with:
    path: .
    fail-on: high
    baseline: .secretsweep-baseline.json   # optional
    sarif: secrets.sarif.json              # optional
```

The action installs **nothing**: it runs the checked-out Python source with the
runner's interpreter. A credential scanner that pulled a dependency tree into
your CI would be working against its own purpose.

| input | default | purpose |
|---|---|---|
| `path` | `.` | file or directory to scan |
| `fail-on` | `high` | `critical`/`high`/`medium`/`low`/`info`/`none` |
| `baseline` | — | only fail on findings absent from the baseline |
| `sarif` | — | write SARIF 2.1.0 for code scanning upload |
| `min-severity` | `info` | hide findings below this level |
| `tag`, `exclude-rule` | — | comma separated rule selection |
| `history` | `false` | scan `git log -p` instead of the working tree |
| `extra-args` | — | any CLI flag, passed through verbatim |

Outputs: `findings`, `max-severity`, `files-scanned`, `exit-code`, `report`,
`sarif`. The report is also written to the job summary, capped at 64 KB so a
noisy run cannot drown the log.

```yaml
- uses: xuange-hu/secretsweep@v1
  id: sweep
  continue-on-error: true
  with:
    path: .
- name: Upload
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.sweep.outputs.sarif }}
```

`action-test.yml` runs the action against a tree that leaks on purpose and
asserts that it fails, so a regression in the action breaks CI here rather than
in your workflow.

---

## MCP server

```bash
pip install "secretsweep-audit[mcp]"
secretsweep-mcp
```

| tool | purpose |
|---|---|
| `secretsweep_scan` | scan a path; summary + masked findings |
| `secretsweep_scan_text` | scan a pasted snippet, log line, or diff |
| `secretsweep_baseline` | build a baseline document |
| `secretsweep_diff` | diff a scan against a baseline |
| `secretsweep_rules` | list rules and their gates |
| `secretsweep_entropy` | is this string random-looking? |
| `secretsweep_sarif` | SARIF for dashboards |
| `secretsweep_demo` | scan the built-in demo repo |

Claude Code / Cursor / Cline config:

```json
{
  "mcpServers": {
    "secretsweep": {
      "command": "uvx",
      "args": ["--from", "secretsweep-audit[mcp]", "secretsweep-mcp"]
    }
  }
}
```

Pinned to `mcp>=1.2,<2` on purpose: 2.x renames `FastMCP` to `MCPServer`.

---

## Zero dependencies

The runtime package imports nothing outside the standard library. `mcp` is an
optional extra and is the only entry in it.

| module | responsibility |
|---|---|
| `patterns.py` | 86 rules with entropy gates and validators |
| `entropy.py` | Shannon entropy, charset classification, token windowing |
| `placeholders.py` | real / likely / placeholder triage |
| `context.py` | path bucketing and severity adjustment |
| `capability.py` | offline inference: what can this credential do |
| `scanner.py` | the pipeline, overlap resolution, dedupe |
| `baseline.py` | fingerprint baselines and diffs |
| `history.py` | `git log -p` scanning |
| `ignore.py` | `.secretsweepignore` globs |
| `sarif.py` | SARIF 2.1.0 |
| `report.py` | text and JSON rendering |
| `samples.py` | one trigger sample per rule |
| `entrypoint.py` | GitHub Action entrypoint (reuses the CLI parser, no deps) |

---

## Coverage

- **86 rules** across cloud (AWS/GCP/Azure), git hosting, package registries,
  chat, payments, LLM providers, observability, SaaS, databases, and key
  material - plus entropy-gated generic assignments.
- **Connection URIs**: postgres, mysql, mongodb, redis, amqp, basic-auth URLs.
- **Key material**: PEM blocks, inline SSH keys, JWTs, Kubernetes service
  account tokens.
- **History**: `secretsweep scan --history` walks `git log -p`.

---

## Scope

Secret *detection* - finding credentials that are already sitting in a tree so
they can be rotated. It never calls out to a provider, never verifies a
credential, and does nothing about bypassing access controls.

---

## License

MIT. See [LICENSE](LICENSE).
