"""Machine-check the TEST-001 pure-component coverage inventory."""
# ruff: noqa: INP001

from __future__ import annotations

import ast
import json
from pathlib import Path, PurePosixPath
from typing import TypedDict, cast

ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = ROOT / "validation" / "unit-test-coverage-inventory.json"
EXPECTED_KEYS = {
    "schema_version",
    "requirement_id",
    "component_granularity",
    "categories",
    "components",
}
EXPECTED_CATEGORIES = (
    "domain",
    "parser",
    "policy",
    "serializer",
    "state-transition",
)
_CATEGORY_ORDER = {category: index for index, category in enumerate(EXPECTED_CATEGORIES)}


class ComponentEntry(TypedDict):
    """One production component and its isolated unit-test mapping."""

    component: str
    categories: list[str]
    source: str
    unit_tests: list[str]


class CoverageInventory(TypedDict):
    """Machine-readable TEST-001 coverage artifact."""

    schema_version: int
    requirement_id: str
    component_granularity: str
    categories: list[str]
    components: list[ComponentEntry]


def _load_inventory() -> CoverageInventory:
    value = cast("object", json.loads(INVENTORY_PATH.read_text(encoding="utf-8")))
    assert isinstance(value, dict)
    document = cast("dict[str, object]", value)
    assert set(document) == EXPECTED_KEYS
    return cast("CoverageInventory", document)


def _safe_relative_path(value: str) -> Path:
    posix_path = PurePosixPath(value)
    assert not posix_path.is_absolute()
    assert ".." not in posix_path.parts
    assert posix_path.as_posix() == value
    return ROOT.joinpath(*posix_path.parts)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


def _has_test_function(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
        for node in ast.walk(tree)
    )


def _has_behavioral_symbol(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    has_definition = any(
        isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        for node in tree.body
    )
    has_public_reexports = any(
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in (node.targets if isinstance(node, ast.Assign) else (node.target,))
        )
        for node in tree.body
    )
    return has_definition or has_public_reexports


def test_inventory_is_complete_well_formed_and_sorted() -> None:
    inventory = _load_inventory()

    assert inventory["schema_version"] == 1
    assert inventory["requirement_id"] == "TEST-001"
    assert inventory["component_granularity"] == "Python module"
    assert tuple(inventory["categories"]) == EXPECTED_CATEGORIES
    assert inventory["components"]

    component_names = [entry["component"] for entry in inventory["components"]]
    assert component_names == sorted(component_names)
    assert len(component_names) == len(set(component_names))
    used_categories: set[str] = set()

    for entry in inventory["components"]:
        component = entry["component"]
        categories = entry["categories"]
        source = entry["source"]
        unit_tests = entry["unit_tests"]

        assert categories
        assert categories == sorted(categories, key=_CATEGORY_ORDER.__getitem__)
        assert set(categories) <= set(EXPECTED_CATEGORIES)
        used_categories.update(categories)
        assert source == f"src/{component.replace('.', '/')}.py"
        source_path = _safe_relative_path(source)
        assert source_path.is_file()
        assert _has_behavioral_symbol(source_path)
        assert unit_tests
        assert unit_tests == sorted(set(unit_tests))

        for test in unit_tests:
            assert test.startswith("tests/unit/")
            assert PurePosixPath(test).name.startswith("test_")
            test_path = _safe_relative_path(test)
            assert test_path.is_file()
            assert _has_test_function(test_path)
            assert component in _imported_modules(test_path)

    assert used_categories == set(EXPECTED_CATEGORIES)


def test_every_self_declared_pure_module_is_in_the_inventory() -> None:
    inventory = _load_inventory()
    inventoried_sources = {entry["source"] for entry in inventory["components"]}
    self_declared_pure: set[str] = set()

    for path in sorted((ROOT / "src" / "webhook_receiver_conformance").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_docstring = (ast.get_docstring(tree) or "").casefold()
        if "pure" in module_docstring or "side-effect-free" in module_docstring:
            self_declared_pure.add(path.relative_to(ROOT).as_posix())

    assert self_declared_pure <= inventoried_sources
