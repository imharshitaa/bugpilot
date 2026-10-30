"""Tests for core/plugin_manager.py: merging builtin + external plugin
config and loading modules by source type. Uses temp config files so these
tests are isolated from the project's real config/modules.yaml content."""

import pytest
import yaml

from core.plugin_manager import PluginManager


def _write_yaml(path, data):
    path.write_text(yaml.safe_dump(data))
    return str(path)


def _manager(tmp_path, modules=None, plugins=None):
    module_path = _write_yaml(tmp_path / "modules.yaml", {"modules": modules or {}})
    plugin_path = _write_yaml(tmp_path / "plugins.yaml", {"plugins": plugins or {}})
    return PluginManager(module_config_path=module_path, plugin_config_path=plugin_path)


def test_list_plugins_merges_builtin_and_external(tmp_path):
    manager = _manager(
        tmp_path,
        modules={"xss": {"enabled": True, "description": "builtin xss"}},
        plugins={"custom": {"enabled": True, "description": "ext", "source": "python_file", "path": "x.py"}},
    )

    plugins = manager.list_plugins()

    assert plugins["xss"]["source"] == "builtin"
    assert plugins["xss"]["enabled"] is True
    assert plugins["custom"]["source"] == "python_file"
    assert plugins["custom"]["path"] == "x.py"


def test_enabled_plugin_names_filters_disabled(tmp_path):
    manager = _manager(
        tmp_path,
        modules={
            "xss": {"enabled": True},
            "sqli": {"enabled": False},
        },
    )

    assert manager.enabled_plugin_names() == ["xss"]


def test_plugin_descriptions_maps_name_to_description(tmp_path):
    manager = _manager(tmp_path, modules={"xss": {"enabled": True, "description": "desc here"}})
    assert manager.plugin_descriptions() == {"xss": "desc here"}


def test_load_plugin_builtin_imports_real_module(tmp_path):
    manager = _manager(tmp_path, modules={"xss": {"enabled": True}})
    module = manager.load_plugin("xss")
    assert hasattr(module, "run")


def test_load_plugin_unknown_name_raises_keyerror(tmp_path):
    manager = _manager(tmp_path, modules={"xss": {"enabled": True}})
    with pytest.raises(KeyError):
        manager.load_plugin("does_not_exist")


def test_load_plugin_python_file_missing_path_raises_valueerror(tmp_path):
    manager = _manager(
        tmp_path,
        plugins={"custom": {"enabled": True, "source": "python_file", "path": None}},
    )
    with pytest.raises(ValueError):
        manager.load_plugin("custom")


def test_load_plugin_python_file_nonexistent_file_raises_filenotfound(tmp_path):
    manager = _manager(
        tmp_path,
        plugins={"custom": {"enabled": True, "source": "python_file", "path": "nope.py"}},
    )
    with pytest.raises(FileNotFoundError):
        manager.load_plugin("custom")


def test_load_plugin_python_file_loads_real_file(tmp_path):
    plugin_file = tmp_path / "custom_module.py"
    plugin_file.write_text("def run(endpoints, utils, payload_rules):\n    return []\n")

    manager = _manager(
        tmp_path,
        plugins={"custom": {"enabled": True, "source": "python_file", "path": str(plugin_file)}},
    )

    module = manager.load_plugin("custom")

    assert module.run([], None, {}) == []


def test_load_plugin_unsupported_source_raises_valueerror(tmp_path):
    manager = _manager(
        tmp_path,
        plugins={"custom": {"enabled": True, "source": "weird_source"}},
    )
    with pytest.raises(ValueError):
        manager.load_plugin("custom")
