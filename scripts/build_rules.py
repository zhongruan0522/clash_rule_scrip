#!/usr/bin/env python3
"""Aggregate custom and upstream rules into four standalone rule providers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]
CUSTOM = ROOT / "custom"
UPSTREAM = CUSTOM / "upstream.yml"
DIST = ROOT / "dist"

CATEGORIES = {
    "REJECT": "block.yaml",
    "US-ZJ": "clean-node.yaml",
    "LSDL": "foreign-line.yaml",
    "DIRECT": "china-direct.yaml",
}

CUSTOM_FILES = {
    "REJECT": "block.yaml",
    "US-ZJ": "clean-node.yaml",
    "LSDL": "foreign-line.yaml",
    "DIRECT": "china-direct.yaml",
}

SUPPORTED_CLASSICAL_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "PROCESS-NAME",
    "PROCESS-NAME-WILDCARD",
}

def fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "clash-rule-aggregator"})
    try:
        with urlopen(request, timeout=30) as response:
            return response.read()
    except Exception as error:
        raise RuntimeError(f"failed to download {url}: {error}") from error


def canonical_source_url(provider: dict[str, Any]) -> str:
    url = provider["url"]
    # The repository only stores MRS files. Their YAML counterparts are kept in
    # the same MetaCubeX branch, so merge the text form without external tools.
    if url.endswith(".mrs"):
        url = url[:-4] + ".yaml"
    return url


def source_location(provider: dict[str, Any]) -> str:
    url = canonical_source_url(provider)
    if "cdn.jsdelivr.net/gh/" in url:
        path = urlparse(url).path.removeprefix("/gh/")
        repo, reference_and_path = path.split("@", 1)
        reference, source_path = reference_and_path.split("/", 1)
        return f"https://raw.githubusercontent.com/{repo}/{reference}/{source_path}"
    return url


def normalize_domain(item: str) -> str:
    if item.startswith("+."):
        return f"DOMAIN-SUFFIX,{item[2:]}"
    if item.startswith("."):
        # Classical rules cannot express "subdomains only". The closest stable
        # match is DOMAIN-SUFFIX; flag it through the stderr report if it appears.
        return f"DOMAIN-SUFFIX,{item[1:]}"
    return f"DOMAIN,{item}"


def normalize_payload(payload: list[str], behavior: str, provider_name: str) -> list[str]:
    normalized: list[str] = []
    for raw in payload:
        item = str(raw).strip().strip("'\"")
        if not item or item.startswith("#"):
            continue

        if behavior == "domain":
            if "://" in item or "/" in item:
                raise ValueError(f"{provider_name}: unsupported domain item {item!r}")
            normalized.append(normalize_domain(item))
            continue

        if behavior == "ipcidr":
            rule_type = "IP-CIDR6" if ":" in item else "IP-CIDR"
            normalized.append(f"{rule_type},{item}")
            continue

        rule_type = item.split(",", 1)[0].upper()
        if rule_type not in SUPPORTED_CLASSICAL_TYPES:
            # Some upstream classical files mix in plain domain-provider entries.
            # Detecting bare domains preserves the source rules safely.
            if "," not in item:
                normalized.append(normalize_domain(item))
                continue
            raise ValueError(
                f"{provider_name}: unsupported classical rule type {rule_type!r}: {item!r}"
            )
        normalized.append(item)
    return normalized


def validate_custom(payload: list[str], filename: str) -> list[str]:
    normalized: list[str] = []
    for raw in payload:
        rule = str(raw).strip()
        if not rule:
            continue
        rule_type = rule.split(",", 1)[0].upper()
        if rule_type not in SUPPORTED_CLASSICAL_TYPES:
            raise ValueError(f"custom/{filename}: unsupported rule type {rule_type!r}: {rule!r}")
        normalized.append(rule)
    return normalized


def write_category(path: Path, rules: list[str]) -> None:
    body = "payload:\n"
    body += "".join(f"  - {rule}\n" for rule in rules)
    path.write_text(body, encoding="utf-8", newline="\n")


def main() -> None:
    config = yaml.safe_load(UPSTREAM.read_text(encoding="utf-8"))
    providers = config.get("providers", [])
    if not providers:
        raise ValueError("custom/upstream.yml contains no upstream providers")

    selected: dict[str, list[str]] = {path: [] for path in CATEGORIES.values()}
    seen: dict[str, str] = {}
    sources_used: set[str] = set()

    custom_rules: dict[str, list[str]] = {}
    custom_counts: dict[str, int] = {}
    for target, filename in CATEGORIES.items():
        custom_filename = CUSTOM_FILES[target]
        path = CUSTOM / custom_filename
        if not path.exists():
            custom_counts[filename] = 0
            continue
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        payload = parsed.get("payload") if isinstance(parsed, dict) else None
        if not isinstance(payload, list):
            raise ValueError(f"Custom rule pack has no payload list: {path}")
        converted = validate_custom(payload, custom_filename)
        custom_rules[target] = converted
        custom_counts[filename] = len(converted)

    # Preserve the original priority: broad ad upstream precedes custom clean
    # telemetry rules; within each other category, custom rules take priority.
    for target, filename in CATEGORIES.items():
        target_providers = [
            provider for provider in providers if provider["target"] == target
        ]

        def add_rules(rules: list[str]) -> None:
            for rule in rules:
                if rule in seen:
                    continue
                seen[rule] = filename
                selected[filename].append(rule)

        if target == "REJECT":
            for provider in target_providers:
                provider_name = provider["name"]
                url = source_location(provider)
                parsed = yaml.safe_load(fetch(url))
                payload = parsed.get("payload") if isinstance(parsed, dict) else None
                if not isinstance(payload, list):
                    raise ValueError(f"{provider_name}: no payload list at {url}")
                sources_used.add(url)
                add_rules(normalize_payload(payload, provider["behavior"], provider_name))
            add_rules(custom_rules.get(target, []))
        else:
            add_rules(custom_rules.get(target, []))
            for provider in target_providers:
                provider_name = provider["name"]
                url = source_location(provider)
                parsed = yaml.safe_load(fetch(url))
                payload = parsed.get("payload") if isinstance(parsed, dict) else None
                if not isinstance(payload, list):
                    raise ValueError(f"{provider_name}: no payload list at {url}")
                sources_used.add(url)
                add_rules(normalize_payload(payload, provider["behavior"], provider_name))

    DIST.mkdir(exist_ok=True)
    for filename in CATEGORIES.values():
        output_path = DIST / filename
        if output_path.exists() and not selected[filename]:
            output_path.unlink()
            continue
        write_category(output_path, selected[filename])

    for filename, output_rules in selected.items():
        print(f"{filename}: {len(output_rules)} rules")
    print(f"custom rules loaded: {sum(custom_counts.values())} ({custom_counts})")
    print(f"upstream providers merged: {len(sources_used)}")


if __name__ == "__main__":
    main()
