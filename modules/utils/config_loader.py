import json
import os
import sys
from modules.utils.logger import get_logger

class ConfigLoader:
    """Loader and manager for application configuration files."""
    def __init__(self, config_path="config.json"):
        """Initialize the ConfigLoader with the given config file path."""
        self.config_path = config_path
        self.logger = get_logger("credfinder.configloader")
        self._config = self._load_config()

    def _load_config(self):
        """Load configuration from the config file, handling errors and size limits."""
        if not os.path.exists(self.config_path):
            self.logger.warning(f"Config file {self.config_path} not found, using defaults")
            return {}
        
        # Validate that config_path is actually a file
        if not os.path.isfile(self.config_path):
            self.logger.error(f"Config path {self.config_path} is not a regular file")
            return {}
        
        try:
            # Check file size first
            file_size = os.path.getsize(self.config_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                self.logger.error(f"Config file {self.config_path} is too large ({file_size} bytes)")
                return {}
            
            # Check if file is empty
            if file_size == 0:
                self.logger.warning(f"Config file {self.config_path} is empty, using defaults")
                return {}
            
            with open(self.config_path, 'r') as f:
                config_data = json.load(f)
                
            # Validate that we got a dictionary
            if not isinstance(config_data, dict):
                self.logger.error(f"Config file {self.config_path} does not contain a valid JSON object")
                return {}
                
            # Basic validation of required structure
            if not self._validate_config_structure(config_data):
                self.logger.warning(f"Config file {self.config_path} has invalid structure, some features may not work")
            
            return config_data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in config file {self.config_path}: {e}")
            return {}
        except RecursionError as e:
            self.logger.error(f"Config file {self.config_path} has excessive nesting depth")
            return {}
        except MemoryError as e:
            self.logger.error(f"Config file {self.config_path} is too large to process")
            return {}
        except PermissionError as e:
            self.logger.error(f"Permission denied reading config file {self.config_path}: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Could not read config file {self.config_path}: {e}")
            return {}
    
    def _validate_config_structure(self, config_data: dict) -> bool:
        """Validate basic config structure"""
        try:
            required_sections = ['modules', 'scan_paths', 'patterns']
            missing_sections = []
            
            for section in required_sections:
                if section not in config_data:
                    missing_sections.append(section)
            
            if missing_sections:
                self.logger.warning(f"Config missing required sections: {missing_sections}")
                return False
                
            # Validate modules section structure
            if 'modules' in config_data:
                modules = config_data['modules']
                if not isinstance(modules, dict):
                    self.logger.warning("Config 'modules' section should be a dictionary")
                    return False
                    
                for module_name, module_config in modules.items():
                    if not isinstance(module_config, dict):
                        self.logger.warning(f"Module '{module_name}' config should be a dictionary")
                        return False
                        
                    required_fields = ['enabled', 'priority', 'timeout']
                    for field in required_fields:
                        if field not in module_config:
                            self.logger.warning(f"Module '{module_name}' missing required field: {field}")
                            return False
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Error validating config structure: {e}")
            return False

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
            self.logger.error(f"Could not save config file {self.config_path}: {e}") 