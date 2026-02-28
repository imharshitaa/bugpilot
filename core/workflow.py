"""
workflow.py
------------
Interactive workflow to collect scan intent and selected test cases.
"""

from core.utils import load_yaml


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

    def _enabled_modules(self):
        modules = self.module_config.get("modules", {})
        return [name for name, meta in modules.items() if meta.get("enabled", False)]

    def ask_target_type(self):
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
        modules = self.module_config.get("modules", {})

        print("\nAvailable test cases/modules:")
        for idx, module in enumerate(enabled, start=1):
            desc = modules[module].get("description", "")
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

    def collect(self, fallback_targets=None):
        target_type = self.ask_target_type()
        targets = self.ask_targets(fallback_targets=fallback_targets)
        selected_modules = self.ask_test_cases()
        test_plan = self.build_test_plan(selected_modules)
        lab_environment = input(
            "Enter lab validation environment (name or URL) for exploitation proof [local-lab]: "
        ).strip() or "local-lab"

        return {
            "target_type": target_type,
            "targets": targets,
            "selected_modules": selected_modules,
            "test_plan": test_plan,
            "exploitation_policy": "Detect on target, validate exploitability only in controlled lab",
            "lab_environment": lab_environment,
        }
