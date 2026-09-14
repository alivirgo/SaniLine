"""
SaniLine CLI Tests.

Tests CLI command execution, exit codes, rich outputs, and compact flags.
"""

from click.testing import CliRunner
from saniline.cli.main import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "SaniLine" in result.output
    assert "0.1.0" in result.output


def test_cli_rules():
    runner = CliRunner()
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    assert "SL-SEC-001" in result.output
    assert "SL-RCE-001" in result.output


def test_cli_check_clean_file(tmp_path):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("def hello():\n    return 'world'\n")

    runner = CliRunner()
    result = runner.invoke(main, ["check", str(safe_file)])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_cli_check_compact_mode(tmp_path):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("def hello():\n    return 'world'\n")

    runner = CliRunner()
    result = runner.invoke(main, ["check", str(safe_file), "--compact"])
    assert result.exit_code == 0
    assert "PASS_MILITARY_SPEC" in result.output


def test_cli_sanitize_in_place(tmp_path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("import subprocess\nsubprocess.run(c, shell=True)\n")

    runner = CliRunner()
    result = runner.invoke(main, ["sanitize", str(vuln_file), "--in-place"])
    assert result.exit_code == 0
    content = vuln_file.read_text()
    assert "shell=False" in content
