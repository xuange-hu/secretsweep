# secretsweep · 中文说明

[English](README.md) | 简体中文

零依赖的**凭据泄露扫描器**：86 条厂商规则、熵检测、占位符分级、基线差分。
不是"扫一遍出报告"的工具，而是能长期挂在 PR 门禁上的工具。

```bash
pip install secretsweep        # 或 uvx secretsweep
secretsweep demo               # 先看它在一个故意泄露的仓库上跑
secretsweep scan .
```

## 三步跑通

```text
1. pip install secretsweep
2. secretsweep demo                 # 无需联网、无需 git，直接看到输出
3. secretsweep scan .               # 扫自己的工程
```

输出示例（已经脱敏，密钥不会出现在终端里）：

```text
src/config.py
  CRITICAL     4:17  github-pat  ghp_************7g
          GitHub personal access token | confidence=likely entropy=5.17
          classic personal access token（可能是完整账号权限）
  CRITICAL     5:31  postgres-uri  R7kQ******Zx
          PostgreSQL URI with password | confidence=likely entropy=3.58
```

## 和别的扫描器有什么不一样

### 1. 区分「真泄露」和「文档示例」

绝大多数误报不是"长得像密钥的字符串"，而是**文档里的示例密钥**：
`AKIAIOSFODNN7EXAMPLE` 能命中世上所有 AWS 正则。secretsweep 给每个候选打分：

| 置信度 | 含义 | 默认 |
|---|---|---|
| `real` / `likely` | 没有任何证据说明它是假的 | 报告 |
| `placeholder` | 已知示例值 / 模板引用 / 重复或连续字节 / `<your-key-here>` | 隐藏（`--show-placeholders` 可看） |

判据是结构性的：字符集种类数、重复块、连续序列、词典命中、`${...}` / `process.env` 引用、
哈希长度与熵，而不是"加一条 allowlist"。

### 2. 看文件在哪，不只看字符串长啥样

同样的 40 个字符，在 `docs/example.env` 和 `.github/workflows/deploy.yml` 里含义完全不同。
每条 finding 都带上它所在的桶（`source` / `config` / `ci` / `test` / `example` / `docs` /
`vendor` / `lockfile`），并据此调整严重级：

```text
tests/fixtures/tokens.json
  INFO         2:13  generic-token-assignment  R7kQ************7g
          Generic token assignment | confidence=likely | bucket=test
          bucket:test
```

### 3. 告诉你这把钥匙能开哪扇门（纯离线推断）

不联网、不外发，只从值的形状推断：

- `AKIA…` 长期 IAM 用户密钥；`ASIA…` 临时 STS 会话（自己会过期）；`AGPA…` 根本不能签名。
- `ghp_…` classic 令牌，无法限定到单个仓库；`github_pat_…` 才是细粒度。
- `sk_live_…` 能刷真钱；`sk_test_…` 不能。
- JWT 只解码不验签，报告 `alg` / `sub` / `exp`——**已过期的令牌自动降一级**，
  因为它不是你该第一时间轮换的那个。

### 4. 基线：老仓库唯一能装上门禁的方式

```bash
secretsweep baseline .                    # 给存量拍个快照
secretsweep scan . --baseline .secretsweep-baseline.json
```

指纹是 `path|rule|value-hash`，所以代码挪行不会让基线失效，但**同一文件里新出现的密钥**
一定会让构建失败。`--prune` 会随修复把基线缩小。

## 命令

| 命令 | 作用 |
|---|---|
| `scan [PATH]` | 扫描；`--json` / `--sarif` / `--history` / `--baseline` |
| `baseline PATH` | 生成基线，让**新增**泄露才挂 CI |
| `diff PATH --baseline F` | 只看新增/已修复，不落盘 |
| `rules [--tag T]` | 列出 86 条规则与熵阈值 |
| `entropy VALUE` | 单字符串体检：长度、字符集、bits/char |
| `demo` | 造一个会泄露的仓库并扫描 |

退出码：`0` 干净，`1` 有达到 `--fail-on`（默认 `high`）的发现，`2` 用法错误。

常用参数：`--min-severity`、`--entropy-min`（整体抬高熵阈值）、`--tag`、`--exclude-rule`、
`--ignore-glob`、`--skip-dir`、`--show-placeholders`、`--no-inline-ignore`、`--no-evidence`。

## 抑制方式

```python
TOKEN = "ghp_..."      # secretsweep:ignore
KEY   = "AKIA..."      # secretsweep:ignore[aws-access-key-id]
```

`.secretsweepignore`（gitignore 风格 glob）：

```gitignore
src/secretsweep/samples.py   # 规则库自带样本，是夹具不是泄露
tests/**
```

## git 历史

```bash
secretsweep scan . --history --max-commits 500
```

从文件里删掉不等于从对象库里删掉。`--history` 走 `git log -p`，报告仍然存在于历史中的泄露，
并带上 `commit:<sha>`。

## CI / SARIF

```yaml
- run: |
    pip install secretsweep
    secretsweep scan . --baseline .secretsweep-baseline.json --sarif secrets.sarif.json
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: secrets.sarif.json
```

SARIF 2.1.0 带 `security-severity`，能正确排进 code scanning。

## MCP

```bash
pip install "secretsweep[mcp]"
secretsweep-mcp
```

8 个工具：`secretsweep_scan`、`secretsweep_scan_text`、`secretsweep_baseline`、
`secretsweep_diff`、`secretsweep_rules`、`secretsweep_entropy`、`secretsweep_sarif`、
`secretsweep_demo`。

```json
{
  "mcpServers": {
    "secretsweep": {
      "command": "uvx",
      "args": ["--from", "secretsweep[mcp]", "secretsweep-mcp"]
    }
  }
}
```

固定在 `mcp>=1.2,<2`：2.x 把 `FastMCP` 改名成了 `MCPServer`。

## 边界

做的是**泄露检测**——找出树里已经躺着的凭据，好让你去轮换。它从不外联厂商、从不验证凭据，
也不做任何绕过访问控制的事。

MIT 协议。
