"""The composite action is a supported entrypoint, so it gets tested like one.

Two layers:
  * contract tests - action.yml must declare every input the entrypoint reads,
    map each one into the step environment, and declare every output the
    entrypoint writes. A typo in action.yml is otherwise invisible until
    somebody's CI job silently scans the wrong path.
  * behaviour tests - entrypoint.main() is invoked in-process with a staged
    GITHUB_OUTPUT / GITHUB_STEP_SUMMARY, and the parsed outputs are asserted.

No YAML parser: the checks needed here are indentation-shaped, and the project
ships zero dependencies.
"""

import importlib.util
import json
import os
import re
import sys
import textwrap

import pytest

from secretsweep import cli as cli_mod

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION_YML = os.path.join(ROOT, "action.yml")
ENTRYPOINT = os.path.join(ROOT, "entrypoint.py")

# Built from fragments so this repository never contains a literal that GitHub
# push protection will reject. The runtime value is unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"


def load_entrypoint():
    spec = importlib.util.spec_from_file_location("secretsweep_action_entrypoint", ENTRYPOINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def action_text() -> str:
    with open(ACTION_YML, encoding="utf-8") as fh:
        return fh.read()


def entrypoint_text() -> str:
    with open(ENTRYPOINT, encoding="utf-8") as fh:
        return fh.read()


def block_keys(text: str, block: str) -> list[str]:
    """Two-space keys under a top-level `block:` line."""
    keys: list[str] = []
    inside = False
    for raw in text.splitlines():
        if raw.startswith(block + ":"):
            inside = True
            continue
        if not inside:
            continue
        if not raw.strip():
            continue
        if raw.startswith("  ") and not raw.startswith("   "):
            keys.append(raw.strip().partition(":")[0])
        elif not raw.startswith(" "):
            break
    return keys


def parse_outputs(text: str) -> dict:
    """Parse GITHUB_OUTPUT, including the `name<<delim` heredoc form."""
    lines = text.splitlines()
    out: dict[str, str] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        head = line.split("<<")[0]
        if "<<" in line and "=" not in head:
            name, delimiter = line.split("<<", 1)
            body: list[str] = []
            index += 1
            while index < len(lines) and lines[index] != delimiter:
                body.append(lines[index])
                index += 1
            index += 1
            out[name] = "\n".join(body)
            continue
        name, _, value = line.partition("=")
        if name:
            out[name] = value
        index += 1
    return out


@pytest.fixture
def action(tmp_path, monkeypatch):
    module = load_entrypoint()
    # The runner's own bookkeeping files must live outside the scanned tree,
    # otherwise they show up in `files-scanned`.
    work = tmp_path / "_gha"
    work.mkdir()
    out_file = work / "github_output.txt"
    summary_file = work / "summary.md"
    out_file.write_text("", encoding="utf-8")
    summary_file.write_text("", encoding="utf-8")

    for key in list(os.environ):
        if key.startswith("INPUT_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    def run(path=None, **overrides):
        if path is not None:
            monkeypatch.setenv("INPUT_PATH", str(path))
        # kwarg underscores map straight onto INPUT_<UPPER> (action.yml turns
        # `min-severity` into INPUT_MIN_SEVERITY for us).
        for name, value in overrides.items():
            monkeypatch.setenv("INPUT_" + name.upper(), str(value))
        code = module.main()
        return code, parse_outputs(out_file.read_text(encoding="utf-8")), summary_file.read_text(encoding="utf-8")

    return run


@pytest.fixture
def leaky(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text(
        f'aws_access_key_id = "{AWS_KEY}"\n'
        'GITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"\n',
        encoding="utf-8",
    )
    return tree


@pytest.fixture
def clean(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text('GREETING = "hello world"\nPORT = 8080\n', encoding="utf-8")
    return tree


# --------------------------------------------------------------------------
# contract
# --------------------------------------------------------------------------


def test_action_runs_as_a_composite_action():
    text = action_text()
    assert re.search(r"^runs:", text, re.M)
    assert re.search(r"^  using: composite$", text, re.M)


def test_action_has_no_install_step():
    # The whole point: a credential scanner that adds nothing to your CI
    # supply chain. `pip install` in this file would defeat that.
    assert "pip install" not in action_text()


def test_every_declared_input_reaches_the_entrypoint():
    text = action_text()
    source = entrypoint_text()
    forwarded = set(re.findall(r"^ {8}(INPUT_[A-Z0-9_]+):", text, re.M))
    for name in block_keys(text, "inputs"):
        if name == "python-version":  # consumed by setup-python, not the scanner
            continue
        env_name = "INPUT_" + name.upper().replace("-", "_")
        assert env_name in forwarded, f"{name} is declared but never forwarded"
        assert name in source, f"{name} is declared but entrypoint.py never reads it"


def test_no_undeclared_input_is_forwarded():
    declared = {name for name in block_keys(action_text(), "inputs") if name != "python-version"}
    forwarded = set(re.findall(r"^ {8}(INPUT_[A-Z0-9_]+):", action_text(), re.M))
    for env_name in forwarded:
        name = env_name[len("INPUT_") :].lower().replace("_", "-")
        assert name in declared, f"{env_name} is forwarded but not declared"


def test_every_declared_output_is_written():
    for name in block_keys(action_text(), "outputs"):
        assert f'"{name}"' in entrypoint_text(), f"output {name} is declared but never written"


def test_action_pins_its_actions_to_shas():
    # unpinned actions are how CI gets supply-chain popped
    for ref in re.findall(r"uses:\s+([\w./-]+@\S+)", action_text()):
        _, _, version = ref.partition("@")
        assert re.fullmatch(r"[0-9a-f]{40}", version), f"{ref} is not pinned to a commit sha"


def test_entrypoint_has_no_third_party_imports():
    source = entrypoint_text()
    for banned in ("yaml", "requests", "click", "rich", "tomllib", "mcp"):
        assert f"import {banned}" not in source


# --------------------------------------------------------------------------
# behaviour
# --------------------------------------------------------------------------


def test_clean_tree_passes(action, clean):
    code, outputs, summary = action(path=clean)
    assert code == 0
    assert outputs["findings"] == "0"
    assert outputs["max-severity"] == "none"
    assert outputs["exit-code"] == "0"
    assert "secretsweep" in summary


def test_leaky_tree_fails_and_masks_the_secret(action, leaky):
    code, outputs, _ = action(path=leaky)
    assert code == 1
    assert int(outputs["findings"]) >= 2
    assert outputs["max-severity"] in ("high", "critical")
    assert "aws-access-key-id" in outputs["report"]
    assert AWS_KEY not in outputs["report"], "the action must never echo a raw secret"


def test_fail_on_none_never_fails(action, leaky):
    code, outputs, _ = action(path=leaky, fail_on="none")
    assert code == 0
    assert int(outputs["findings"]) >= 2, "findings are still reported, they just do not fail the job"


def test_fail_on_critical_ignores_high(action, tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text(f'aws_access_key_id = "{AWS_KEY}"\n', encoding="utf-8")
    code, outputs, _ = action(path=tree, fail_on="critical")
    assert code == 0
    assert int(outputs["findings"]) == 1, "the high finding is still reported"


def test_baseline_suppresses_known_findings(action, leaky, tmp_path):
    baseline = tmp_path / "baseline.json"
    assert cli_mod.main(["baseline", str(leaky), "-o", str(baseline)]) == 0
    code, outputs, _ = action(path=leaky, baseline=baseline)
    assert code == 0
    assert outputs["findings"] == "0"


def test_new_leak_escapes_the_baseline(action, leaky, tmp_path):
    baseline = tmp_path / "baseline.json"
    cli_mod.main(["baseline", str(leaky), "-o", str(baseline)])
    (leaky / "app.py").write_text(
        'GITHUB_TOKEN = "ghp_T4wC8jH5fB1dY6sA0eU3oI7gR7kQ2vLm9pZx"\n', encoding="utf-8"
    )
    code, outputs, _ = action(path=leaky, baseline=baseline)
    assert code == 1
    assert int(outputs["findings"]) >= 1


def test_sarif_input_writes_a_file(action, leaky, tmp_path):
    target = tmp_path / "results.sarif.json"
    code, outputs, _ = action(path=leaky, sarif=target)
    assert code == 1
    assert outputs["sarif"] == str(target)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"]


def test_json_input_emits_json(action, leaky, capsys):
    action(path=leaky, json="true")
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["findings"] >= 2


def test_extra_args_are_honoured(action, leaky):
    _, outputs, _ = action(path=leaky, extra_args="--exclude-rule aws-access-key-id")
    assert "aws-access-key-id" not in outputs["report"]
    assert "github-pat" in outputs["report"]


def test_tag_input_narrows_the_ruleset(action, leaky):
    _, outputs, _ = action(path=leaky, tag="aws")
    assert "aws-access-key-id" in outputs["report"]
    assert "github-pat" not in outputs["report"]


def test_min_severity_input_filters(action, leaky):
    # aws-access-key-id is high, the ghp_ token is critical
    _, outputs, _ = action(path=leaky, min_severity="critical")
    assert "aws-access-key-id" not in outputs["report"]
    assert "github-pat" in outputs["report"]


def test_missing_path_is_an_error(action, tmp_path):
    code, _, _ = action(path=tmp_path / "nope")
    assert code == 2


def test_files_scanned_is_reported(action, leaky):
    _, outputs, _ = action(path=leaky)
    assert int(outputs["files-scanned"]) >= 1


def test_step_summary_contains_the_finding_count(action, leaky):
    _, outputs, summary = action(path=leaky)
    assert f"{outputs['findings']} finding(s)" in summary


def test_report_output_is_truncated_when_enormous(action, tmp_path, monkeypatch):
    # one file, many leaks: the step output must stay bounded
    body = "\n".join(f'key_{i} = "{AWS_KEY}"' for i in range(4000))
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    _, outputs, _ = action(path=tmp_path)
    assert len(outputs["report"].encode("utf-8")) <= 70 * 1024


def test_action_agrees_with_the_cli(action, leaky, capsys):
    """The action reuses the CLI parser; prove they do not drift."""
    _, outputs, _ = action(path=leaky)
    capsys.readouterr()
    cli_mod.main(["scan", str(leaky), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["findings"] == int(outputs["findings"])


def heredoc_blocks(text: str) -> list[str]:
    """Pull the `python - <<'PY' ... PY` scripts out of a workflow file."""
    blocks: list[str] = []
    buffer: list[str] | None = None
    for line in text.splitlines():
        if buffer is None:
            if line.strip().endswith("<<'PY'"):
                buffer = []
            continue
        if line.strip() == "PY":
            # the body is indented to the YAML step; strip that common prefix
            blocks.append(textwrap.dedent("\n".join(buffer)))
            buffer = None
        else:
            buffer.append(line)
    return blocks


def test_action_test_workflow_scripts_still_agree(tmp_path, monkeypatch):
    """The workflow plants a secret, then asserts the report masked it.

    Those live in two separate heredocs, so nothing stops one from changing
    quoting without the other noticing - which is exactly how the first
    action-test run went red: the plant wrote `'AKIA...'` (repr) while the
    check only looked for `"..."`. Running them against each other here keeps
    them honest without pushing a commit to find out.
    """
    workflow = os.path.join(ROOT, ".github", "workflows", "action-test.yml")
    with open(workflow, encoding="utf-8") as fh:
        blocks = heredoc_blocks(fh.read())
    assert len(blocks) >= 2, "expected the plant script and the masking check"

    demo = tmp_path / "_demo"
    demo.mkdir()
    monkeypatch.setattr(sys, "argv", ["plant", str(demo)])
    exec(compile(blocks[0], "plant.py", "exec"), {"__name__": "__main__"})

    planted = (demo / "app.py").read_text(encoding="utf-8")
    value = re.search(r"=\s*['\"]([^'\"]+)['\"]", planted).group(1)
    assert value.startswith("AKIA")

    masked = value[:4] + "*" * 12 + value[-2:]
    monkeypatch.setenv("REPORT", f"  HIGH  1:22  aws-access-key-id  {masked}\n> {masked}")
    monkeypatch.setattr(sys, "argv", ["check", str(demo / "app.py")])
    exec(compile(blocks[1], "check.py", "exec"), {"__name__": "__main__"})
