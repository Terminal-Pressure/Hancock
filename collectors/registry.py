from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from types import ModuleType
from typing import Callable

_VALID_ID = re.compile(r"^[a-z][a-z0-9_\-]*$")


class CollectorRegistryError(ValueError):
    """Raised when collector registration or execution fails validation."""


@dataclass(frozen=True)
class CollectorSpec:
    """Metadata that describes a runnable collector."""

    collector_id: str
    module: str
    entrypoint: str = "collect"
    name: str = ""
    description: str = ""

    def validate(self) -> None:
        if not self.collector_id or not _VALID_ID.match(self.collector_id):
            raise CollectorRegistryError(
                f"Invalid collector_id '{self.collector_id}'. Use lowercase letters, numbers, '_' or '-'."
            )
        if not self.module or not isinstance(self.module, str):
            raise CollectorRegistryError(f"Collector '{self.collector_id}' has invalid module metadata.")
        if not self.entrypoint or not isinstance(self.entrypoint, str):
            raise CollectorRegistryError(f"Collector '{self.collector_id}' has invalid entrypoint metadata.")
        if self.name is not None and not isinstance(self.name, str):
            raise CollectorRegistryError(f"Collector '{self.collector_id}' has invalid name metadata.")
        if self.description is not None and not isinstance(self.description, str):
            raise CollectorRegistryError(f"Collector '{self.collector_id}' has invalid description metadata.")


class CollectorRegistry:
    """Registry for dynamically-loaded collectors."""

    def __init__(self) -> None:
        self._collectors: dict[str, CollectorSpec] = {}

    def register(self, spec: CollectorSpec) -> None:
        spec.validate()
        if spec.collector_id in self._collectors:
            raise CollectorRegistryError(f"Duplicate collector_id '{spec.collector_id}'.")
        self._collectors[spec.collector_id] = spec

    def register_many(self, specs: list[CollectorSpec]) -> None:
        for spec in specs:
            self.register(spec)

    def get(self, collector_id: str) -> CollectorSpec:
        try:
            return self._collectors[collector_id]
        except KeyError as exc:
            raise CollectorRegistryError(f"Unknown collector '{collector_id}'.") from exc

    def list_collectors(self) -> list[CollectorSpec]:
        return [self._collectors[key] for key in sorted(self._collectors)]

    def _load_module(self, module_name: str) -> ModuleType:
        return importlib.import_module(module_name)

    def load_callable(self, collector_id: str) -> Callable:
        spec = self.get(collector_id)
        module = self._load_module(spec.module)
        try:
            entrypoint = getattr(module, spec.entrypoint)
        except AttributeError as exc:
            raise CollectorRegistryError(
                f"Collector '{collector_id}' entrypoint '{spec.entrypoint}' was not found in '{spec.module}'."
            ) from exc

        if not callable(entrypoint):
            raise CollectorRegistryError(
                f"Collector '{collector_id}' entrypoint '{spec.entrypoint}' is not callable."
            )
        return entrypoint

    def run(self, collector_id: str, *args, **kwargs):
        return self.load_callable(collector_id)(*args, **kwargs)


def build_default_registry() -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register_many(
        [
            CollectorSpec(
                collector_id="pentest-kb",
                module="collectors.pentest_kb",
                entrypoint="build",
                name="Pentest KB",
                description="Build pentest knowledge base samples.",
            ),
            CollectorSpec(
                collector_id="soc-kb",
                module="collectors.soc_kb",
                entrypoint="build",
                name="SOC KB",
                description="Build SOC knowledge base samples.",
            ),
            CollectorSpec(
                collector_id="mitre",
                module="collectors.mitre_collector",
                name="MITRE ATT&CK",
                description="Collect MITRE ATT&CK data.",
            ),
            CollectorSpec(
                collector_id="nvd",
                module="collectors.nvd_collector",
                name="NVD CVE",
                description="Collect NVD CVE data.",
            ),
            CollectorSpec(
                collector_id="kev",
                module="collectors.cisa_kev_collector",
                name="CISA KEV",
                description="Collect CISA Known Exploited Vulnerabilities.",
            ),
            CollectorSpec(
                collector_id="ghsa",
                module="collectors.ghsa_collector",
                name="GHSA",
                description="Collect GitHub Security Advisories.",
            ),
            CollectorSpec(
                collector_id="atomic",
                module="collectors.atomic_collector",
                name="Atomic Red Team",
                description="Collect Atomic Red Team tests.",
            ),
            CollectorSpec(
                collector_id="formatter-v2",
                module="formatter.to_mistral_jsonl_v2",
                entrypoint="format_all",
                name="Formatter v2",
                description="Format phase-2 data into v2 JSONL.",
            ),
            CollectorSpec(
                collector_id="formatter-v3",
                module="collectors.formatter_v3",
                entrypoint="format_all",
                name="Formatter v3",
                description="Format phase-3 data into v3 JSONL.",
            ),
        ]
    )
    return registry
