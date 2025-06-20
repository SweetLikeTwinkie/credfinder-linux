import json
import os

class ConfigLoader:
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self._config = self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return {}

    def get(self, key, default=None):
        return self._config.get(key, default)

    def set_scan_paths(self, target_path):
        # Override scan paths for all modules
        for section in self._config.get("scan_paths", {}):
            if isinstance(self._config["scan_paths"][section], list):
                self._config["scan_paths"][section] = [target_path]
            elif isinstance(self._config["scan_paths"][section], dict):
                for sub in self._config["scan_paths"][section]:
                    self._config["scan_paths"][section][sub] = [target_path]

    def set_opsec_mode(self, enabled=True):
        self._config["opsec"] = self._config.get("opsec", {})
        self._config["opsec"]["minimal_logging"] = enabled
        self._config["opsec"]["no_network_calls"] = enabled
        self._config["opsec"]["clean_exit"] = enabled

    def save(self):
        with open(self.config_path, 'w') as f:
            json.dump(self._config, f, indent=2) 