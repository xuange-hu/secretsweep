# 传播文案（发布动作需本人确认，自动化不代发）

仓库：https://github.com/xuange-hu/secretsweep
PyPI：`pip install secretsweep` / MCP：`uvx --from "secretsweep[mcp]" secretsweep-mcp`

## 一句话

> Zero-dependency secret scanner that separates real leaks from documented
> examples, reads the file's context, tells you what each credential can do,
> and gates PRs with a baseline instead of a wall of noise.

## Show HN（标题候选）

1. `secretsweep - a zero-dependency secret scanner that triages placeholders`
2. `Show HN: secretsweep - secret scanning that survives an old repository`
3. `Show HN: I wrote a credential leak scanner in Python with no dependencies`

正文草案：

```
I kept hitting the same problem with secret scanners: on day one on an old repo
they report 400 findings, 395 of which are `AKIAIOSFODNN7EXAMPLE` in the docs,
so everyone ignores them from day two.

secretsweep is my attempt at the other shape. Zero runtime dependencies, 86
provider rules, and three things I had not seen done in one tool:

1. Placeholder triage. Most false positives are not "strings that look like
   keys", they are *documented* keys. The value shape decides: known example
   values, template references (`${VAR}`, `process.env.X`), repeated or
   sequential bytes, low character variety, angle-bracket placeholders. Those
   are reported as `placeholder` and hidden by default.

2. Context. The same 40 characters in docs/example.env and in
   .github/workflows/deploy.yml are not the same risk. Every finding carries
   the bucket it was found in (source/config/ci/test/example/docs/vendor) and
   the severity moves from there.

3. Offline capability inference. AKIA is a long-lived IAM key, ASIA is a
   temporary STS session that expires by itself, AGPA cannot sign requests at
   all. ghp_ is a classic token you cannot scope to one repo. sk_live_ moves
   real money. A JWT is decoded (not verified) for alg/sub/exp, and an expired
   token is downgraded because it is not what you rotate first.

And the part that makes it usable in CI: fingerprints are path|rule|value-hash,
so `secretsweep baseline .` snapshots the存量 and `scan --baseline` only fails
on new leaks. Line drift does not invalidate the baseline; a new secret in a
baselined file does.

Python 3.10+, no dependencies, SARIF output, 8 MCP tools, MIT.
```

## Reddit r/carhacking 不适用；改投

- r/ExperiencedDevs / r/devsecops：`Baselines are the only way secret scanning survives an old repo`
- r/Python：`A zero-dependency secret scanner (86 rules, SARIF, MCP tools)`
- r/selfhosted：`Secret scanning in CI without a SaaS`

r/devsecops 草案：

```
Title: Secret scanners fail on old repos. I built one that starts from a baseline.

Body:
The failure mode I keep seeing: you turn on a secret scanner, it finds 400
things, 395 are example values in the docs, and the tool gets removed a week
later.

What I did differently:
- placeholder triage by value shape (known examples, templates, repeated or
  sequential bytes, low variety) - hidden by default, not just allowlisted
- path buckets (test/example/docs/vendor) move severity down with a reason
- fingerprints are path|rule|value-hash so baselines survive refactors
- `--sarif` with security-severity for code scanning
- zero dependencies, so `pip install` is it

Curious what breaks for you: which false positive class is worst in your repos?
```

## X 发布串

1/ `secretsweep` - 零依赖的密钥泄露扫描器，86 条规则。
2/ 最大的误报来源不是"像密钥的字符串"，而是**文档里的示例密钥**。按值的形状分级：已知示例值、模板引用、重复/连续字节 → `placeholder`，默认不报。
3/ 同一个字符串在 docs/example.env 和 .github/workflows/deploy.yml 里不是一个风险。每条 finding 带 bucket，严重级据此调整。
4/ 离线推断能力：AKIA 长期密钥 / ASIA 临时会话 / AGPA 不能签名；ghp_ 无法限定仓库；JWT 过期自动降级。不外联任何厂商。
5/ 基线：`secretsweep baseline .` → `scan --baseline`。挪行不失效，新密钥一定挂。
6/ `pip install secretsweep`。MIT。

## Awesome 清单提交用简介（英文，60–120 词）

> secretsweep - Zero-dependency credential leak scanner for Python. 86 provider
> rules (AWS/GCP/Azure, GitHub, npm, PyPI, Slack, Stripe, OpenAI, databases,
> PEM/JWT) plus entropy-gated generic assignments. Distinguishes real leaks from
> documented examples using value-shape triage, adjusts severity by path context,
> infers what each credential can do offline, and supports fingerprint baselines
> so CI fails only on new leaks. SARIF 2.1.0, MCP server, MIT.

可投清单：awesome-python-security、awesome-devsecops、awesome-mcp-servers、
awesome-secret-management、awesome-supply-chain-security。
