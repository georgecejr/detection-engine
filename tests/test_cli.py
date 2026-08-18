from detection_engine.cli import main


def test_cli_validate(capsys) -> None:
    assert main(["validate"]) == 0
    captured = capsys.readouterr()
    assert "Validated" in captured.out


def test_cli_list(capsys) -> None:
    assert main(["list"]) == 0
    captured = capsys.readouterr()
    assert "okta_mfa_factor_reset" in captured.out
    assert "aws_cloudtrail_stopped" in captured.out


def test_cli_run_json(capsys) -> None:
    assert main(["run", "--json"]) == 0
    captured = capsys.readouterr()
    assert "rule_id" in captured.out
    assert "2d4d54ee-9656-4502-b779-6d12d31b1e6e" in captured.out
