"""Public errors and their fixed command-line exit codes."""

from typing import ClassVar


class VulnAssessError(Exception):
    """An actionable failure whose message identifies the affected input."""

    exit_code: ClassVar[int] = 1


class ConfigError(VulnAssessError):
    """A missing or invalid configuration path, command, or key."""

    exit_code: ClassVar[int] = 2


class ScopeError(VulnAssessError):
    """A target is outside the explicitly authorised scope."""

    exit_code: ClassVar[int] = 3


class AdapterError(VulnAssessError):
    """Scanner execution or parsing failed for the named artifact."""

    exit_code: ClassVar[int] = 4


class IntelUnavailable(VulnAssessError):
    """A required local intelligence artifact is missing or invalid."""

    exit_code: ClassVar[int] = 5


class LLMUnavailable(VulnAssessError):
    """The explicitly configured local model is unavailable."""

    exit_code: ClassVar[int] = 6


def error_exit_code(error: BaseException) -> int:
    """Map known errors without treating unexpected exceptions as user errors."""
    return error.exit_code if isinstance(error, VulnAssessError) else 1
