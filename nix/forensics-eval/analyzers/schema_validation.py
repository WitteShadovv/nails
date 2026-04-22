#!/usr/bin/env python3
"""Small JSON-schema validator for bundled forensics contracts.

This intentionally supports only the draft-07 subset used by the local
schemas under nix/forensics-eval/fixtures/schemas/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SchemaValidationError(RuntimeError):
    """Raised when payload validation fails."""


def _join(path: str, fragment: str) -> str:
    if not path or path == "$":
        return f"$.{fragment}"
    return f"{path}.{fragment}"


def _pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _resolve_pointer(document: Any, pointer: str) -> Any:
    if pointer == "#":
        return document
    if not pointer.startswith("#/"):
        raise SchemaValidationError(f"Unsupported schema reference: {pointer}")
    current = document
    for raw_token in pointer[2:].split("/"):
        token = _pointer_token(raw_token)
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        raise SchemaValidationError(f"Unresolvable schema reference: {pointer}")
    return current


def _matches_type(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise SchemaValidationError(f"Unsupported schema type: {expected}")


def _validate_type(schema: dict[str, Any], value: Any, path: str) -> None:
    expected = schema.get("type")
    if expected is None:
        return
    allowed = expected if isinstance(expected, list) else [expected]
    if any(_matches_type(item, value) for item in allowed):
        return
    joined = ", ".join(allowed)
    raise SchemaValidationError(f"{path}: expected type {joined}")


def _validate_enum(schema: dict[str, Any], value: Any, path: str) -> None:
    enum = schema.get("enum")
    if enum is not None and value not in enum:
        raise SchemaValidationError(f"{path}: value {value!r} not in enum {enum!r}")


def _validate_string(schema: dict[str, Any], value: Any, path: str) -> None:
    if not isinstance(value, str):
        return
    min_length = schema.get("minLength")
    if min_length is not None and len(value) < min_length:
        raise SchemaValidationError(
            f"{path}: string length {len(value)} < minimum {min_length}"
        )


def _validate_integer(schema: dict[str, Any], value: Any, path: str) -> None:
    if not (isinstance(value, int) and not isinstance(value, bool)):
        return
    minimum = schema.get("minimum")
    if minimum is not None and value < minimum:
        raise SchemaValidationError(f"{path}: value {value} < minimum {minimum}")


def _validate_array(
    schema: dict[str, Any], value: Any, document: dict[str, Any], path: str
) -> None:
    if not isinstance(value, list):
        return
    min_items = schema.get("minItems")
    if min_items is not None and len(value) < min_items:
        raise SchemaValidationError(
            f"{path}: array length {len(value)} < minimum {min_items}"
        )
    item_schema = schema.get("items")
    if item_schema is None:
        return
    for index, item in enumerate(value):
        validate_payload(item_schema, item, document=document, path=f"{path}[{index}]")


def _validate_object(
    schema: dict[str, Any], value: Any, document: dict[str, Any], path: str
) -> None:
    if not isinstance(value, dict):
        return
    required = schema.get("required", [])
    for key in required:
        if key not in value:
            raise SchemaValidationError(f"{path}: missing required property '{key}'")

    properties = schema.get("properties", {})
    additional_properties = schema.get("additionalProperties", True)
    for key, item in value.items():
        if key in properties:
            validate_payload(
                properties[key], item, document=document, path=_join(path, key)
            )
            continue
        if isinstance(additional_properties, dict):
            validate_payload(
                additional_properties,
                item,
                document=document,
                path=_join(path, key),
            )
            continue
        if additional_properties is False:
            raise SchemaValidationError(
                f"{path}: unexpected property '{key}' not allowed by schema"
            )


def validate_payload(
    schema: dict[str, Any],
    payload: Any,
    *,
    document: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    document = document or schema
    if "$ref" in schema:
        resolved = _resolve_pointer(document, schema["$ref"])
        validate_payload(resolved, payload, document=document, path=path)
        return

    _validate_type(schema, payload, path)
    _validate_enum(schema, payload, path)
    _validate_string(schema, payload, path)
    _validate_integer(schema, payload, path)
    _validate_array(schema, payload, document, path)
    _validate_object(schema, payload, document, path)


def load_schema(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise SchemaValidationError(f"Schema must be a JSON object: {path}")
    return payload


def validate_with_schema_path(schema_path: Path, payload: Any) -> None:
    validate_payload(load_schema(schema_path), payload)
