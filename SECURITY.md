# Security policy

## Scope

**secretsweep** — Credential leak scanner with placeholder grading and a baseline gate — is a static analysis tool: it reads **any file in a tree, plus git history when asked** and prints a report.
The security questions that apply to it are the ones that apply to any tool
that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report.
It never writes to the files it reads.

## Reporting a vulnerability in secretsweep

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/secretsweep/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`secretsweep --version`);
2. the input that triggers it — the actual file is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **A real credential that is not reported.** A false negative is the one failure mode with no second chance.
- **A regex that backtracks catastrophically.** 86 patterns run over every line of every file; one pathological pattern is a denial of service on the user's own CI.
- **A placeholder graded as a live secret**, or a live secret graded as a placeholder — either way the user stops reading the report.
- **A path that escapes the directory it was pointed at**, or history walking that reaches outside the repository.

## What does not count

- A rule firing on input you consider correct. That is a false positive: open
  an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
