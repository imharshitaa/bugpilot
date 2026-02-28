"""
workflow.py
------------
Interactive workflow to collect scan intent and selected test cases.
"""

from core.utils import load_yaml
from core.plugin_manager import PluginManager

try:
    from rich.console import Console
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


console = Console() if RICH_AVAILABLE else None


TARGET_TYPES = {
    "1": "web_app",
    "2": "api",
    "3": "mobile_backend",
    "4": "other",
}


class Workflow:
    def __init__(self, module_config_path="config/modules.yaml", test_case_path="config/test_cases.yaml"):
        self.module_config = load_yaml(module_config_path)
        self.test_case_catalog = load_yaml(test_case_path)
        self.plugin_manager = PluginManager(module_config_path=module_config_path)

    def _enabled_modules(self):
        return self.plugin_manager.enabled_plugin_names()

    def ask_target_type(self):
        if RICH_AVAILABLE:
            console.print("\n[bold green]Select target type:[/bold green]")
            console.print("[cyan]1.[/cyan] Web App")
            console.print("[cyan]2.[/cyan] API")
            console.print("[cyan]3.[/cyan] Mobile Backend")
            console.print("[cyan]4.[/cyan] Other")
        else:
            print("\nSelect target type:")
            print("1. Web App")
            print("2. API")
            print("3. Mobile Backend")
            print("4. Other")
        choice = input("Choice [1-4]: ").strip()
        return TARGET_TYPES.get(choice, "web_app")

    def ask_targets(self, fallback_targets=None):
        fallback_targets = fallback_targets or []
        raw = input(
            "Enter target URLs (comma-separated). Leave blank to use config/scope.txt: "
        ).strip()

        if raw:
            targets = [value.strip() for value in raw.split(",") if value.strip()]
            return [url for url in targets if url.startswith("http")]

        return fallback_targets

    def ask_test_cases(self):
        enabled = self._enabled_modules()
        modules = self.plugin_manager.plugin_descriptions()

        if RICH_AVAILABLE:
            table = Table(title="Available Test Cases / Modules", style="green")
            table.add_column("#", style="bright_green", justify="right")
            table.add_column("Module", style="cyan")
            table.add_column("Description", style="green")
            for idx, module in enumerate(enabled, start=1):
                desc = modules.get(module, "")
                table.add_row(str(idx), module, desc)
            console.print(table)
        else:
            print("\nAvailable test cases/modules:")
            for idx, module in enumerate(enabled, start=1):
                desc = modules.get(module, "")
                print(f"{idx}. {module} - {desc}")

        raw = input(
            "Choose modules by number/name (comma-separated) or 'all' [all]: "
        ).strip()

        if not raw or raw.lower() == "all":
            return enabled

        selected = []
        for token in [part.strip() for part in raw.split(",") if part.strip()]:
            if token.isdigit():
                index = int(token) - 1
                if 0 <= index < len(enabled):
                    selected.append(enabled[index])
                continue

            if token in enabled:
                selected.append(token)

        return sorted(set(selected)) or enabled

    def build_test_plan(self, selected_modules):
        catalog = self.test_case_catalog.get("test_cases", {})
        plan = {}

        for module in selected_modules:
            entry = catalog.get(module, {})
            default_script = f"modules/{module}.py"
            plan[module] = {
                "attack_method": entry.get("attack_method", "custom-module-validation"),
                "custom_scripts": entry.get("custom_scripts", [default_script]),
                "tools": entry.get("tools", {"kali": [], "opensource": []}),
                "commands": entry.get("commands", [f"python {default_script}"]),
            }

        return plan

    def ask_output_formats(self):
        raw = input(
            "Output formats (comma-separated: markdown,json,sarif) [markdown,json]: "
        ).strip()
        if not raw:
            return ["markdown", "json"]

        allowed = {"markdown", "json", "sarif"}
        formats = [fmt.strip().lower() for fmt in raw.split(",") if fmt.strip()]
        formats = [fmt for fmt in formats if fmt in allowed]
        return formats or ["markdown", "json"]

    def collect(self, fallback_targets=None):
        target_type = self.ask_target_type()
        targets = self.ask_targets(fallback_targets=fallback_targets)
        selected_modules = self.ask_test_cases()
        test_plan = self.build_test_plan(selected_modules)
        lab_environment = input(
            "Enter lab validation environment (name or URL) for exploitation proof [local-lab]: "
        ).strip() or "local-lab"
        output_formats = self.ask_output_formats()

        return {
            "target_type": target_type,
            "targets": targets,
            "selected_modules": selected_modules,
            "test_plan": test_plan,
            "exploitation_policy": "Detect on target, validate exploitability only in controlled lab",
            "lab_environment": lab_environment,
            "output_formats": output_formats,
        }
