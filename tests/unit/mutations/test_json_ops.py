"""Run the normative structural-mutation vectors through the locked module."""
# ruff: noqa: F403, INP001

from __future__ import annotations

from tests.unit.mutations.test_structural import *

from webhook_receiver_conformance.mutations.json_ops import (
    STRUCTURAL_MUTATION_REGISTRY as JSON_OPS_REGISTRY,
)
from webhook_receiver_conformance.mutations.structural import (
    STRUCTURAL_MUTATION_REGISTRY as STRUCTURAL_REGISTRY,
)


def test_locked_json_ops_surface_uses_the_normative_registry() -> None:
    """The compatibility surface must not fork operator registrations."""
    assert JSON_OPS_REGISTRY is STRUCTURAL_REGISTRY
