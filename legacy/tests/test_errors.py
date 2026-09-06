"""The error hierarchy must preserve the fixed public exit codes."""

import pytest

from vulnassess.errors import (
    AdapterError,
    ConfigError,
    IntelUnavailable,
    LLMUnavailable,
    ScopeError,
    VulnAssessError,
    error_exit_code,
)


@pytest.mark.parametrize(
    ("error_type", "code"),
    [
        (ConfigError, 2),
        (ScopeError, 3),
        (AdapterError, 4),
        (IntelUnavailable, 5),
        (LLMUnavailable, 6),
    ],
)
def test_contract_exit_codes(error_type: type[VulnAssessError], code: int) -> None:
    error = error_type("Missing config/scope.yaml")

    assert isinstance(error, VulnAssessError)
    assert str(error) == "Missing config/scope.yaml"
    assert error_exit_code(error) == code


def test_unexpected_error_exit_code() -> None:
    assert error_exit_code(RuntimeError("unexpected")) == 1
