"""Plugin manager for builtin and file-based scan modules."""

import importlib
import importlib.util
import os

from core.utils import load_yaml


class PluginManager:
    def __init__(
        self,
        module_config_path="config/modules.yaml",
        plugin_config_path="config/plugins.yaml",
    ):
        self.module_config = load_yaml(module_config_path) or {}
        self.plugin_config = load_yaml(plugin_config_path) or {"plugins": {}}

    def list_plugins(self):
        merged = {}

        builtin = self.module_config.get("modules", {})
        for name, meta in builtin.items():
            merged[name] = {
                "name": name,
                "enabled": bool(meta.get("enabled", False)),
                "description": meta.get("description", ""),
                "source": "builtin",
                "path": None,
            }

        external = self.plugin_config.get("plugins", {})
        for name, meta in external.items():
            merged[name] = {
                "name": name,
                "enabled": bool(meta.get("enabled", False)),
                "description": meta.get("description", ""),
                "source": meta.get("source", "python_file"),
                "path": meta.get("path"),
            }

        return merged

    def enabled_plugin_names(self):
        return [
            name
            for name, meta in self.list_plugins().items()
            if meta.get("enabled", False)
        ]

    def plugin_descriptions(self):
        return {
            name: meta.get("description", "") for name, meta in self.list_plugins().items()
        }

    def _load_builtin(self, name):
        return importlib.import_module(f"modules.{name}")

    def _load_python_file(self, name, path):
        if not path:
            raise ValueError(f"Plugin '{name}' missing file path.")

        full_path = path
        if not os.path.isabs(full_path):
            full_path = os.path.join(os.getcwd(), full_path)

        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Plugin file not found: {full_path}")

        spec = importlib.util.spec_from_file_location(f"plugin_{name}", full_path)
        if not spec or not spec.loader:
            raise ImportError(f"Unable to load plugin spec for {name}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def load_plugin(self, name):
        plugins = self.list_plugins()
        meta = plugins.get(name)
        if not meta:
            raise KeyError(f"Unknown plugin: {name}")

        source = meta.get("source", "builtin")
        if source == "builtin":
            return self._load_builtin(name)
        if source == "python_file":
            return self._load_python_file(name, meta.get("path"))

        raise ValueError(f"Unsupported plugin source '{source}' for plugin '{name}'")
