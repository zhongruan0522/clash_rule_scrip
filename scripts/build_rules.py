#!/usr/bin/env python3
"""Aggregate auditable upstream sources into four standalone rule providers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "sources" / "upstream.yml"
DIST = ROOT / "dist"

CATEGORIES = {
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


def write_category(path: Path, rules: list[str]) -> None:
    body = "payload:\n"
    body += "".join(f"  - {rule}\n" for rule in rules)
    path.write_text(body, encoding="utf-8", newline="\n")


def main() -> None:
    config = yaml.safe_load(UPSTREAM.read_text(encoding="utf-8"))
    providers = config.get("providers", [])
    if not providers:
        raise ValueError("sources/upstream.yml contains no upstream providers")

    selected: dict[str, list[str]] = {path: [] for path in CATEGORIES.values()}
    seen: dict[str, str] = {}
    sources_used: set[str] = set()

    # Existing packs carry the private inline rules. Keeping them as a baseline
    # lets cloud workflows refresh upstream sources without publishing 1.yml.
    baseline_counts: dict[str, int] = {}
    for filename, rules in selected.items():
        path = DIST / filename
        if not path.exists():
            continue
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        payload = parsed.get("payload") if isinstance(parsed, dict) else None
        if not isinstance(payload, list):
            raise ValueError(f"Existing rule pack has no payload list: {path}")
        for rule in payload:
            if rule in seen:
                continue
            seen[rule] = filename
            rules.append(rule)
        baseline_counts[filename] = len(rules)

    for provider in providers:
        provider_name = provider["name"]
        target = provider["target"]
        if target not in CATEGORIES:
            raise ValueError(f"Unknown output target {target!r} for {provider_name!r}")
        output = CATEGORIES[target]
        url = source_location(provider)
        data = fetch(url)
        parsed = yaml.safe_load(data)
        payload = parsed.get("payload") if isinstance(parsed, dict) else None
        if not isinstance(payload, list):
            raise ValueError(f"{provider_name}: no payload list at {url}")
        converted = normalize_payload(payload, provider["behavior"], provider_name)
        sources_used.add(url)

        for rule in converted:
            if rule in seen:
                continue
            seen[rule] = output
            selected[output].append(rule)

    DIST.mkdir(exist_ok=True)
    for filename in CATEGORIES.values():
        output_path = DIST / filename
        if output_path.exists() and not selected[filename]:
            output_path.unlink()
            continue
        write_category(output_path, selected[filename])

    for filename, output_rules in selected.items():
        print(f"{filename}: {len(output_rules)} rules")
    print(f"baseline rules loaded: {sum(baseline_counts.values())}")
    print(f"upstream providers merged: {len(sources_used)}")


if __name__ == "__main__":
    main()
