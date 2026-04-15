from __future__ import annotations

import sys
import types

import pytest

from collectors.registry import CollectorRegistry, CollectorRegistryError, CollectorSpec


def test_dynamic_loading_executes_registered_collector(monkeypatch):
    module_name = "tests.fake_dynamic_collector"
    module = types.ModuleType(module_name)
    called = {"count": 0}

    def collect():
        called["count"] += 1
        return {"status": "ok"}

    module.collect = collect
    monkeypatch.setitem(sys.modules, module_name, module)

    registry = CollectorRegistry()
    registry.register(CollectorSpec(collector_id="fake", module=module_name))

    result = registry.run("fake")

    assert result == {"status": "ok"}
    assert called["count"] == 1


def test_duplicate_collector_id_is_rejected():
    registry = CollectorRegistry()
    spec = CollectorSpec(collector_id="nvd", module="collectors.nvd_collector")

    registry.register(spec)

    with pytest.raises(CollectorRegistryError, match="Duplicate collector_id"):
        registry.register(spec)


@pytest.mark.parametrize(
    "spec",
    [
        CollectorSpec(collector_id="", module="collectors.nvd_collector"),
        CollectorSpec(collector_id="bad id", module="collectors.nvd_collector"),
        CollectorSpec(collector_id="nvd", module=""),
        CollectorSpec(collector_id="nvd", module="collectors.nvd_collector", entrypoint=""),
    ],
)
def test_bad_metadata_is_rejected(spec):
    registry = CollectorRegistry()

    with pytest.raises(CollectorRegistryError):
        registry.register(spec)
