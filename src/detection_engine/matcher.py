from __future__ import annotations

import ast
from typing import Any

from detection_engine.models import Rule

RESERVED_DETECTION_KEYS = {"condition", "timeframe"}


def _find_key(mapping: dict[str, Any], name: str) -> str | None:
    lowered = name.lower()
    for key in mapping:
        if str(key).lower() == lowered:
            return key
    return None


def lookup(event: Any, path: str) -> list[Any]:
    """Return values at a dotted path, walking nested objects and lists."""
    nodes: list[Any] = [event]
    for part in path.split("."):
        next_nodes: list[Any] = []
        for node in nodes:
            if isinstance(node, dict):
                key = _find_key(node, part)
                if key is None:
                    continue
                value = node[key]
                if isinstance(value, list):
                    next_nodes.extend(value)
                else:
                    next_nodes.append(value)
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, dict):
                        key = _find_key(item, part)
                        if key is None:
                            continue
                        value = item[key]
                        if isinstance(value, list):
                            next_nodes.extend(value)
                        else:
                            next_nodes.append(value)
        nodes = next_nodes
    return nodes


def _parse_field(spec: str) -> tuple[str, set[str]]:
    field, *modifiers = spec.split("|")
    return field, {modifier.lower() for modifier in modifiers}


def _stringify(value: Any) -> str:
    return "" if value is None else str(value)


def _values_match(actual: list[Any], expected: Any, modifiers: set[str]) -> bool:
    candidates = expected if isinstance(expected, list) else [expected]
    contains = "contains" in modifiers
    casefold = "i" in modifiers or contains
    for candidate in candidates:
        wanted = _stringify(candidate)
        for value in actual:
            have = _stringify(value)
            if casefold:
                left, right = have.lower(), wanted.lower()
            else:
                left, right = have, wanted
            if contains:
                if right and right in left:
                    return True
            elif left == right:
                return True
    return False


def selection_matches(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    if not selection:
        return False
    for field_spec, expected in selection.items():
        field, modifiers = _parse_field(str(field_spec))
        actual = lookup(event, field)
        if not _values_match(actual, expected, modifiers):
            return False
    return True


def _eval_condition(condition: str, selections: dict[str, bool]) -> bool:
    normalized = condition.strip()
    if not normalized:
        return any(selections.values())

    class _Names(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:
            if node.id not in selections:
                raise ValueError(f"unknown detection identifier '{node.id}'")
            return ast.Constant(selections[node.id])

    tree = ast.parse(normalized, mode="eval")
    tree = _Names().visit(tree)
    ast.fix_missing_locations(tree)
    for node in ast.walk(tree):
        if not isinstance(
            node,
            (
                ast.Expression,
                ast.BoolOp,
                ast.UnaryOp,
                ast.Constant,
                ast.And,
                ast.Or,
                ast.Not,
                ast.Load,
            ),
        ):
            raise ValueError(f"unsupported condition: {condition}")
    result = eval(compile(tree, "<condition>", "eval"), {"__builtins__": {}}, {})
    return bool(result)


def matches(rule: Rule, event: dict[str, Any]) -> bool:
    detection = rule.detection
    if not isinstance(detection, dict):
        return False

    selections: dict[str, bool] = {}
    for name, body in detection.items():
        if name in RESERVED_DETECTION_KEYS:
            continue
        if not isinstance(body, dict):
            selections[name] = False
            continue
        selections[name] = selection_matches(event, body)

    condition = str(detection.get("condition", "")).strip()
    if not condition:
        return bool(selections) and all(selections.values())
    return _eval_condition(condition, selections)
