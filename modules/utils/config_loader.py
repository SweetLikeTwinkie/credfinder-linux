import json
import os
import sys

class ConfigLoader:
    """Loader and manager for application configuration files."""
    def __init__(self, config_path="config.json"):
        """Initialize the ConfigLoader with the given config file path."""
        self.config_path = config_path
        self._config = self._load_config()

    def _load_config(self):
        """Load configuration from the config file, handling errors and size limits."""
        if os.path.exists(self.config_path):
            try:
                # Check file size first
                file_size = os.path.getsize(self.config_path)
                if file_size > 10 * 1024 * 1024:  # 10MB limit
                    print(f"Error: Config file {self.config_path} is too large ({file_size} bytes)")
                    return {}
                
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                return config_data
                
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON in config file {self.config_path}: {e}")
                return {}
            except RecursionError as e:
                print(f"Error: Config file {self.config_path} has excessive nesting depth")
                return {}
            except MemoryError as e:
                print(f"Error: Config file {self.config_path} is too large to process")
                return {}
            except Exception as e:
                print(f"Error: Could not read config file {self.config_path}: {e}")
                return {}
        else:
            print(f"Warning: Config file {self.config_path} not found, using defaults")
            return {}

    def get(self, key, default=None):
        """Get a configuration value by key, returning default if not found."""
        return self._config.get(key, default)

    def set_scan_paths(self, target_path):
        """Override scan paths for all modules with the given target path."""
        # Override scan paths for all modules
        for section in self._config.get("scan_paths", {}):
            if isinstance(self._config["scan_paths"][section], list):
                self._config["scan_paths"][section] = [target_path]
            elif isinstance(self._config["scan_paths"][section], dict):
                for sub in self._config["scan_paths"][section]:
                    self._config["scan_paths"][section][sub] = [target_path]

    def set_opsec_mode(self, enabled=True):
        """Enable or disable operational security (opsec) mode."""
        self._config["opsec"] = self._config.get("opsec", {})
        self._config["opsec"]["minimal_logging"] = enabled
        self._config["opsec"]["no_network_calls"] = enabled
        self._config["opsec"]["clean_exit"] = enabled

    def save(self):
        """Save the current configuration to the config file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"Error: Could not save config file {self.config_path}: {e}") 