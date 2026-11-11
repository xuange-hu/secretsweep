import json

import pytest

from secretsweep import mcp_server

# Fixture values are assembled from fragments: a secret scanner's own repository
# must not contain literals that GitHub push protection (or any other scanner)
# will flag. Runtime values are unchanged.
AWS_KEY = "AK" + "IA3RJ4E5TZLMXQW7PU"
S40 = "qN3xT7vLm2pR9wZ4cK8jH5fB1dY6sA0eU3o" + "I7gXz"


AWS_LINE = f'aws_access_key_id = "{AWS_KEY}"'


class FakeServer:
    """Stands in for FastMCP so registration is testable without the SDK."""

    def __init__(self):
        self.registered = {}

    def tool(self, name=None, **_kwargs):
        def decorator(fn):
            self.registered[name or fn.__name__] = fn
            return fn

        return decorator


def test_manifest_lists_every_tool():
    manifest = mcp_server.tool_manifest()
    names = {m["name"] for m in manifest}
    assert names == {n for n, _ in mcp_server.TOOLS}
    assert all(m["summary"] for m in manifest)


def test_register_returns_the_tool_count():
    server = FakeServer()
    assert mcp_server.register(server) == len(mcp_server.TOOLS)
    assert len(server.registered) == len(mcp_server.TOOLS)


def test_scan_tool_never_returns_raw_secrets(tmp_path):
    (tmp_path / "app.py").write_text(AWS_LINE + "\n", encoding="utf-8")
    payload = json.loads(mcp_server.tool_scan(str(tmp_path)))
    assert payload["summary"]["total"] == 1
    finding = payload["findings"][0]
    assert AWS_KEY not in json.dumps(finding)
    assert finding["masked"].startswith("AKIA")


def test_scan_tool_on_missing_path():
    assert "error" in json.loads(mcp_server.tool_scan("/definitely/not/here"))


def test_scan_text_tool_works_on_snippets():
    payload = json.loads(mcp_server.tool_scan_text(AWS_LINE))
    assert payload["findings"][0]["rule"] == "aws-access-key-id"


def test_baseline_and_diff_tools_roundtrip(tmp_path):
    (tmp_path / "app.py").write_text(AWS_LINE + "\n", encoding="utf-8")
    baseline_json = mcp_server.tool_baseline(str(tmp_path))
    assert json.loads(baseline_json)["count"] == 1
    payload = json.loads(mcp_server.tool_diff(str(tmp_path), baseline_json))
    assert payload["new"] == []
    assert payload["persisted"] == 1

    (tmp_path / "app.py").write_text(AWS_LINE + '\nGITHUB_TOKEN = "ghp_R7kQ2vLm9pZxT4wC8jH5fB1dY6sA0eU3oI7g"\n', encoding="utf-8")
    payload = json.loads(mcp_server.tool_diff(str(tmp_path), baseline_json))
    assert [f["rule"] for f in payload["new"]] == ["github-pat"]


def test_diff_tool_rejects_bad_json(tmp_path):
    assert "error" in json.loads(mcp_server.tool_diff(str(tmp_path), "{not json"))


def test_rules_tool_filters_by_tag():
    payload = json.loads(mcp_server.tool_rules("aws"))
    assert all("aws" in r["tags"] for r in payload)
    assert len(json.loads(mcp_server.tool_rules())) > len(payload)


def test_entropy_tool():
    payload = json.loads(mcp_server.tool_entropy(S40))
    assert payload["random_looking"] is True
    assert payload["length"] == 40


def test_sarif_tool(tmp_path):
    (tmp_path / "app.py").write_text(AWS_LINE + "\n", encoding="utf-8")
    payload = json.loads(mcp_server.tool_sarif(str(tmp_path)))
    assert payload["runs"][0]["results"][0]["ruleId"] == "aws-access-key-id"


def test_demo_tool():
    payload = json.loads(mcp_server.tool_demo())
    assert payload["summary"]["total"] > 0
    assert "github-pat" in {f["rule"] for f in payload["findings"]}


@pytest.mark.parametrize("name", [n for n, _ in mcp_server.TOOLS])
def test_every_tool_returns_a_string(name):
    fn = dict(mcp_server.TOOLS)[name]
    if name == "secretsweep_demo":
        assert isinstance(fn(), str)
    elif name == "secretsweep_entropy":
        assert isinstance(fn("abc"), str)
    elif name == "secretsweep_rules":
        assert isinstance(fn(), str)
    elif name == "secretsweep_diff":
        assert isinstance(fn("/definitely/not/here", "{}"), str)
    else:
        assert isinstance(fn("/definitely/not/here"), str)


def test_served_tools_match_manifest_with_descriptions():
    """The names an agent calls must be the names the manifest promises, and
    FastMCP serves an empty description when the registered function has no
    docstring - an unidentified tool is an uncallable tool."""
    pytest.importorskip("mcp")
    import asyncio

    server = mcp_server.create_server()
    tools = asyncio.run(server.list_tools())
    served = {t.name for t in tools}
    manifest = {t["name"] for t in mcp_server.tool_manifest()}
    assert served == manifest, f"only served: {served - manifest}; only manifest: {manifest - served}"
    for t in tools:
        assert (t.description or "").strip(), f"{t.name} has no description"
