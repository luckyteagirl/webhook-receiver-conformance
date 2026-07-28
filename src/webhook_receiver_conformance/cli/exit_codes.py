"""One stable exit-code contract shared by every CLI execution surface."""
# ruff: noqa: D105, EM101, INP001, TRY003

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from webhook_receiver_conformance.errors import (
    CliExitCategory,
    ExitCode,
    ResultCategory,
    exit_for_result,
)


class CommandSurface(StrEnum):
    """CLI surfaces that must not reinterpret a terminal result."""

    RUN = "run"
    RESUME = "resume"
    REPLAY = "replay"


@dataclass(frozen=True, slots=True)
class ExitCodeMapping:
    """One documented terminal-result mapping."""

    result: ResultCategory
    cli_category: CliExitCategory
    code: ExitCode

    def __post_init__(self) -> None:
        if type(self.result) is not ResultCategory:
            raise TypeError("result must be a ResultCategory")
        if type(self.cli_category) is not CliExitCategory:
            raise TypeError("cli_category must be a CliExitCategory")
        if type(self.code) is not ExitCode:
            raise TypeError("code must be an ExitCode")
        if exit_for_result(self.result) != (self.cli_category, self.code):
            raise ValueError("exit mapping differs from the locked error contract")


EXIT_CODE_MAPPINGS: Final = tuple(
    ExitCodeMapping(result, *exit_for_result(result)) for result in ResultCategory
)
EXIT_CODE_TABLE: Final = MappingProxyType(
    {mapping.result: mapping for mapping in EXIT_CODE_MAPPINGS}
)


def exit_mapping_for(
    result: ResultCategory,
    *,
    surface: CommandSurface,
) -> ExitCodeMapping:
    """Return the same locked mapping for run, resume, and replay."""
    if type(result) is not ResultCategory:
        raise TypeError("result must be a ResultCategory")
    if type(surface) is not CommandSurface:
        raise TypeError("surface must be a CommandSurface")
    return EXIT_CODE_TABLE[result]


def process_exit_code(
    result: ResultCategory,
    *,
    surface: CommandSurface,
) -> ExitCode:
    """Return the documented process code without command-specific overrides."""
    return exit_mapping_for(result, surface=surface).code


__all__ = [
    "EXIT_CODE_MAPPINGS",
    "EXIT_CODE_TABLE",
    "CommandSurface",
    "ExitCodeMapping",
    "exit_mapping_for",
    "process_exit_code",
]
