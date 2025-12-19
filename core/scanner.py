"""
scanner.py
-----------
Central engine that:
- Loads modules
- Applies payloads
- Sends requests
- Detects vulnerabilities
- Returns structured findings
"""

import yaml
import importlib

class Scanner:
    def __init__(self, utils, validator):
        self.utils = utils
        self.validator = validator

        self.module_config = self.load_yaml("config/modules.yaml")
        self.payload_rules = self.load_yaml("config/payload_rules.yaml")

    def load_yaml(self, path):
        with open(path, "r") as f:
            return yaml.safe_load(f)

    # ------------------------------------------------ #
    # Run All Enabled Modules
    # ------------------------------------------------ #
    def run_modules(self, endpoints):
        findings = []

        for module_name, data in self.module_config["modules"].items():
            if data["enabled"]:
                mod = importlib.import_module(f"modules.{module_name}")
                module_findings = mod.run(endpoints, self.utils, self.payload_rules)
                findings.extend(module_findings)

        return self.validator.deduplicate(findings)
