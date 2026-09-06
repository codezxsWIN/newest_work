"""Public errors and their fixed command-line exit codes.

Every message names the missing path, command or configuration key.
"""


class VulnAssessError(Exception):
    """An actionable failure whose message identifies the affected input."""

    exit_code = 1


class ConfigError(VulnAssessError):
    """Bad or missing configuration, bad truth file, or a stage run out of order."""

    exit_code = 2


class ScopeError(VulnAssessError):
    """A target is outside the authorised scope, or is the canary."""

    exit_code = 3


class AdapterError(VulnAssessError):
    """A scanner file is missing, unreadable, or not the expected format."""

    exit_code = 4


class IntelUnavailable(VulnAssessError):
    """A feed snapshot is missing, or enrich ran before the feeds were loaded."""

    exit_code = 5


class LLMUnavailable(VulnAssessError):
    """Reserved: no model is used in this prototype."""

    exit_code = 6
