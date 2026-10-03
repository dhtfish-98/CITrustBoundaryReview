"""Bounded, constructor-free YAML events and POSIX no-follow file reader."""

import os
import stat
from dataclasses import dataclass

import yaml
from yaml import events as ye

from .contracts import OpenInput


@dataclass
class Node:
    kind: str
    value: object
    line: int
    column: int

    @property
    def pos(self):
        return (self.line, self.column)

    def get(self, key):
        return self.value.get(key) if self.kind == "map" else None


def scalar(node):
    if node is None:
        return None
    if node.kind != "scalar":
        raise OpenInput("expected_scalar")
    return node.value


def mapping(node):
    if node is None:
        return {}
    if node.kind != "map":
        raise OpenInput("expected_mapping")
    return node.value


def sequence(node):
    if node is None or node.kind != "seq":
        raise OpenInput("expected_sequence")
    return node.value


def parse_yaml(data, limits):
    if not isinstance(data, bytes):
        raise TypeError("expected_bytes")
    if len(data) > limits.input_bytes:
        raise OpenInput("input_budget")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise OpenInput("invalid_utf8") from None
    stack, root, documents, count = [], None, 0, 0

    def add(node):
        nonlocal root
        if not stack:
            if root is not None:
                raise OpenInput("multiple_documents")
            root = node
        else:
            parent, key = stack[-1]
            if parent.kind == "seq":
                parent.value.append(node)
            elif key is None:
                if node.kind != "scalar" or node.value in parent.value:
                    raise OpenInput("duplicate_or_complex_key")
                if node.value == "<<":
                    raise OpenInput("yaml_merge_key")
                stack[-1][1] = node.value
            else:
                parent.value[key] = node
                stack[-1][1] = None

    try:
        for event in yaml.parse(text, Loader=yaml.BaseLoader):
            if isinstance(event, ye.DocumentStartEvent):
                documents += 1
                if documents > 1 or event.version or event.tags:
                    raise OpenInput("multiple_documents_or_directives")
            if isinstance(event, ye.AliasEvent) or getattr(event, "anchor", None):
                raise OpenInput("yaml_anchor_or_alias")
            if getattr(event, "tag", None) is not None:
                raise OpenInput("yaml_explicit_tag")
            if isinstance(event, (ye.ScalarEvent, ye.MappingStartEvent, ye.SequenceStartEvent)):
                count += 1
                if count > limits.yaml_nodes:
                    raise OpenInput("yaml_node_budget")
                kind = (
                    "scalar"
                    if isinstance(event, ye.ScalarEvent)
                    else ("map" if isinstance(event, ye.MappingStartEvent) else "seq")
                )
                value = event.value if kind == "scalar" else ({} if kind == "map" else [])
                if kind == "scalar" and len(value) > limits.scalar_chars:
                    raise OpenInput("scalar_budget")
                node = Node(kind, value, event.start_mark.line + 1, event.start_mark.column + 1)
                add(node)
                if kind != "scalar":
                    stack.append([node, None])
                    if len(stack) > limits.yaml_depth:
                        raise OpenInput("yaml_depth_budget")
            elif isinstance(event, (ye.MappingEndEvent, ye.SequenceEndEvent)):
                if not stack or (stack[-1][0].kind == "map" and stack[-1][1] is not None):
                    raise OpenInput("invalid_yaml_structure")
                stack.pop()
    except (yaml.YAMLError, RecursionError, UnicodeError):
        raise OpenInput("invalid_yaml") from None
    if root is None or root.kind != "map" or stack:
        raise OpenInput("expected_workflow_mapping")
    return root, count


def read_local(path, limits):
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC")
    directory_capabilities = getattr(os, "supports_dir_fd", None)
    directory_relative_open = (
        isinstance(directory_capabilities, (set, frozenset)) and os.open in directory_capabilities
    )
    if (
        os.name != "posix"
        or any(
            type(getattr(os, flag, None)) is not int or getattr(os, flag) <= 0 for flag in required
        )
        or not directory_relative_open
    ):
        raise OpenInput("unsupported_platform")
    if not isinstance(path, str) or not path or "\0" in path or ".." in path.split("/"):
        raise OpenInput("invalid_local_path")
    parts = os.path.abspath(path).split("/")[1:]
    descriptors = []
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(descriptor)
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if index != len(parts) - 1:
                flags |= os.O_DIRECTORY
            descriptor = os.open(part, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OpenInput("not_regular_file")
        if before.st_size > limits.input_bytes:
            raise OpenInput("input_budget")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, limits.input_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limits.input_bytes:
                raise OpenInput("input_budget")
        after = os.fstat(descriptor)
        if (
            any(
                getattr(before, key) != getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            )
            or len(data) != before.st_size
        ):
            raise OpenInput("input_changed_during_read")
        return bytes(data)
    except (OSError, ValueError):
        raise OpenInput("local_read_unavailable") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
