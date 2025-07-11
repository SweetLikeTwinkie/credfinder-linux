#!/usr/bin/env python3
"""
Test script to verify module coordination is working correctly
"""

import os
import sys
import json
import tempfile
import threading
import time
import shutil
import signal
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from modules.utils.config_loader import ConfigLoader
from modules.utils.scan_cache import get_scan_cache, reset_scan_cache
from modules.utils.logger import get_logger
from modules.utils.smart_exclusions import get_smart_exclusions, is_excluded

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler('test_results.txt', mode='w'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('test_runner')

def log_test(message):
    """Log test output to both file and console"""
    logger.info(message)

def initialize_test_environment():
    """Initialize the test environment with necessary configurations"""
    config = ConfigLoader("config.json")
    reset_scan_cache()
    get_scan_cache(config)
    get_smart_exclusions(config)

def test_territory_ownership():
    """Test module territory ownership"""
    log_test("\n=== Testing Module Territory Ownership ===\n")
    
    import fnmatch
    import os
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    
    test_cases = [
        # Dotfile scanner cases
        ("~/.env", "dotfile_scanner", True),
        ("~/.env", "file_grepper", False),
        ("~/.aws/credentials", "dotfile_scanner", True),
        ("~/.aws/credentials", "git_scanner", False),
        ("~/projects/app/config.yml", "file_grepper", True),
        ("~/projects/app/config.yml", "dotfile_scanner", False),
        ("/tmp/apikeys.env", "file_grepper", True),
        ("/tmp/apikeys.env", "dotfile_scanner", True),  # Changed to True since it's a .env file
        ("~/.ssh/id_rsa", "ssh_scanner", True),
        ("~/.ssh/id_rsa", "file_grepper", False),
        ("~/projects/myrepo/.env", "git_scanner", True),
        ("~/projects/myrepo/.env", "file_grepper", False),  # Changed to False since it's owned by dotfile_scanner
        ("~/.bash_history", "history_parser", True),
        ("~/.bash_history", "file_grepper", False),
    ]
    
    for path, module, should_scan in test_cases:
        result = scan_cache.should_module_scan_file(module, os.path.expanduser(path))
        if result == should_scan:
            log_test(f"✅ PASS: {module} {'can' if should_scan else 'cannot'} scan {path}")
            passed += 1
        else:
            log_test(f"❌ FAIL: {module} {'cannot' if should_scan else 'can'} scan {path} (expected: {'can' if should_scan else 'cannot'})")
            failed += 1
            
            # Debug output for failures
            if module == "git_scanner" and ".aws/credentials" in path:
                log_test("\n🔍 SPECIAL DEBUG: git_scanner for ~/.aws/credentials")
                log_test(f"  Result from should_module_scan_file: {result}")
                log_test(f"  Expected: {should_scan}")
                log_test(f"  Git patterns: {scan_cache.module_territories.get('file_ownership', {}).get('git_scanner', [])}...")
                log_test(f"  dotfile_scanner can scan it: {scan_cache.should_module_scan_file('dotfile_scanner', os.path.expanduser(path))}")
            elif module == "file_grepper" and ".env" in path:
                log_test(f"\nDEBUG: Testing file_grepper for {path}")
                expanded_path = os.path.abspath(os.path.expanduser(path))
                log_test(f"  Expanded path: {expanded_path}")
                log_test(f"  File exists: {os.path.exists(expanded_path)}")
                module_patterns = scan_cache.module_territories.get('file_ownership', {}).get('file_grepper', [])
                log_test(f"  Module patterns: {module_patterns}")
                for pattern in module_patterns:
                    log_test(f"    Pattern '{pattern}' matches: {fnmatch.fnmatch(expanded_path.lower(), pattern.lower())}")
                file_ownership = scan_cache.module_territories.get('file_ownership', {})
                for owner_module, patterns in file_ownership.items():
                    if owner_module != module:
                        for pattern in patterns:
                            if fnmatch.fnmatch(expanded_path.lower(), pattern.lower()):
                                log_test(f"  ⚠️  File is owned by {owner_module} via pattern '{pattern}'")
                log_test("\n  🔍 DEEP DEBUG for file_grepper:")
                for owner_module, patterns in file_ownership.items():
                    if owner_module != module:
                        for pattern in patterns:
                            if fnmatch.fnmatch(expanded_path.lower(), pattern.lower()):
                                log_test(f"    File is claimed by {owner_module} via pattern '{pattern}'")
            elif module == "dotfile_scanner" and ".env" in path:
                log_test(f"\nDEBUG: Testing dotfile_scanner for {path}")
                expanded_path = os.path.abspath(os.path.expanduser(path))
                log_test(f"  Expanded path: {expanded_path}")
                log_test(f"  File exists: {os.path.exists(expanded_path)}")
                module_patterns = scan_cache.module_territories.get('file_ownership', {}).get('dotfile_scanner', [])
                log_test(f"  Module patterns: {module_patterns}")
                for pattern in module_patterns:
                    log_test(f"    Pattern '{pattern}' matches: {fnmatch.fnmatch(expanded_path.lower(), pattern.lower())}")
        
        log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
        return failed == 0

def test_pattern_ownership():
    """Test that pattern ownership is correctly enforced"""
    log_test("\n=== Testing Pattern Ownership ===\n")
    
    # Load config
    config = ConfigLoader("config.json")
    
    # Reset and get scan cache
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    # Get all patterns from config
    all_patterns = config.get("patterns", {})
    if not all_patterns:
        log_test("❌ FAIL: No patterns found in config")
        return False
    
    # Test pattern filtering for each module
    modules_to_test = {
        "dotfile_scanner": ["environment_vars", "credentials"],
        "file_grepper": ["api_tokens", "jwt_tokens", "passwords", "database_urls", "environment_vars", "credentials"],
        "git_scanner": ["private_keys", "aws_keys", "database_urls", "environment_vars", "credentials"],
        "history_parser": ["aws_keys", "api_tokens", "jwt_tokens", "passwords", "credentials", "environment_vars"],
        "ssh_scanner": ["private_keys"]
    }
    
    passed = 0
    failed = 0
    
    for module_name, expected_patterns in modules_to_test.items():
        filtered_patterns = scan_cache.get_filtered_patterns(module_name, all_patterns)
        actual_patterns = set(filtered_patterns.keys())
        expected_set = set(expected_patterns)
        
        # Debug output
        log_test(f"\nTesting {module_name}:")
        log_test(f"  Expected patterns: {sorted(expected_set)}")
        log_test(f"  Actual patterns: {sorted(actual_patterns)}")
        log_test(f"  Missing patterns: {sorted(expected_set - actual_patterns)}")
        log_test(f"  Extra patterns: {sorted(actual_patterns - expected_set)}")
        
        if actual_patterns == expected_set:
            log_test(f"✅ PASS: {module_name} has correct patterns")
            passed += 1
        else:
            log_test(f"❌ FAIL: {module_name} patterns mismatch")
            failed += 1
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_cache_functionality():
    """Test cache functionality"""
    log_test("\n=== Testing Cache Functionality ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    
    # Test files with different content
    test_files = {
        "/tmp/test_aws_keys.txt": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "/tmp/test_env_file.env": "DATABASE_URL=postgresql://user:pass@localhost/db\nAPI_KEY=sk_test_1234567890abcdef",
        "/tmp/test_config.yml": "password: 'super_secret_123'\napi_token: 'abc123xyz789'"
    }
    
    # Create test files
    for file_path, content in test_files.items():
        with open(file_path, 'w') as f:
            f.write(content)
    
    try:
        # Test reading and caching
        # Create the files
        for file_path, content in test_files.items():
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Test cache behavior
        for file_path in test_files:
            # First read should be a cache miss
            content1 = scan_cache.get_file_content(file_path)
            stats1 = scan_cache.get_cache_statistics()
            
            # Second read should be a cache hit
            content2 = scan_cache.get_file_content(file_path)
            stats2 = scan_cache.get_cache_statistics()
            
            # Verify content is the same
            if content1 == content2 == test_files[file_path]:
                log_test(f"✅ PASS: File content correctly cached and retrieved for {os.path.basename(file_path)}")
                passed += 1
            else:
                log_test(f"❌ FAIL: File content mismatch for {os.path.basename(file_path)}")
                failed += 1
            
            # Verify cache statistics
            if stats2["cache_hits"] > stats1["cache_hits"]:
                log_test(f"✅ PASS: Cache hit recorded for {os.path.basename(file_path)}")
                log_test(f"  Cache hit rate: {stats2['cache_hit_rate_percent']}%")
                passed += 1
            else:
                log_test(f"❌ FAIL: Cache statistics incorrect for {os.path.basename(file_path)}")
                log_test(f"  Before - Hits: {stats1['cache_hits']}, Misses: {stats1['cache_misses']}")
                log_test(f"  After  - Hits: {stats2['cache_hits']}, Misses: {stats2['cache_misses']}")
                failed += 1
        
    finally:
        # Clean up
        for file_path in test_files:
            if os.path.exists(file_path):
                os.remove(file_path)
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_single_case():
    """Test a specific edge case scenario"""
    log_test("\n=== Testing Single Case Scenario ===\n")
    
    # Load config
    config = ConfigLoader("config.json")
    
    # Reset and get scan cache
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    # Test case: File that should be scanned by multiple modules but with different patterns
    test_file = "/tmp/test_multi_module.env"
    test_content = """
    # Database configuration
    DATABASE_URL=postgresql://user:pass@localhost/db
    
    # AWS credentials
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    
    # API tokens
    STRIPE_SECRET_KEY=sk_test_1234567890abcdef
    GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456
    
    # SSH key
    SSH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
    """
    
    try:
        # Create test file
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Test module access
        test_cases = [
            ("dotfile_scanner", True, ["environment_vars", "credentials"]),
            ("file_grepper", True, ["api_tokens", "jwt_tokens", "passwords", "database_urls", "environment_vars", "credentials"]),
            ("git_scanner", False, ["private_keys", "aws_keys", "database_urls", "environment_vars", "credentials"]),
            ("ssh_scanner", False, ["private_keys"])
        ]
        
        passed = 0
        failed = 0
        
        for module_name, should_scan, expected_patterns in test_cases:
            # Test file access
            can_scan = scan_cache.should_module_scan_file(module_name, test_file)
            if can_scan == should_scan:
                log_test(f"✅ PASS: {module_name} {'can' if should_scan else 'cannot'} scan the file")
                passed += 1
            else:
                log_test(f"❌ FAIL: {module_name} {'can' if can_scan else 'cannot'} scan the file (expected: {'can' if should_scan else 'cannot'})")
                failed += 1
            
            # Test pattern access
            if can_scan:
                all_patterns = config.get("patterns", {})
                filtered_patterns = scan_cache.get_filtered_patterns(module_name, all_patterns)
                actual_patterns = set(filtered_patterns.keys())
                expected_set = set(expected_patterns)
                
                if actual_patterns == expected_set:
                    log_test(f"✅ PASS: {module_name} has correct patterns")
                    log_test(f"  Patterns: {sorted(actual_patterns)}")
                    passed += 1
                else:
                    log_test(f"❌ FAIL: {module_name} patterns mismatch")
                    log_test(f"  Expected: {sorted(expected_set)}")
                    log_test(f"  Actual: {sorted(actual_patterns)}")
                    failed += 1
        
        # Test caching
        content1 = scan_cache.get_file_content(test_file)
        stats1 = scan_cache.get_cache_statistics()
        
        content2 = scan_cache.get_file_content(test_file)
        stats2 = scan_cache.get_cache_statistics()
        
        if content1 == content2 == test_content:
            log_test("✅ PASS: File content correctly cached and retrieved")
            passed += 1
        else:
            log_test("❌ FAIL: File content mismatch")
            failed += 1
        
        if stats2["cache_hits"] > stats1["cache_hits"]:
            log_test("✅ PASS: Cache hit recorded")
            log_test(f"  Cache hit rate: {stats2['cache_hit_rate_percent']}%")
            passed += 1
        else:
            log_test("❌ FAIL: Cache statistics incorrect")
            log_test(f"  Before - Hits: {stats1['cache_hits']}, Misses: {stats1['cache_misses']}")
            log_test(f"  After  - Hits: {stats2['cache_hits']}, Misses: {stats2['cache_misses']}")
            failed += 1
        
    finally:
        # Clean up
        if os.path.exists(test_file):
            os.remove(test_file)
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_error_handling():
    """Test error handling"""
    log_test("\n=== Testing Error Handling ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    
    # Test cases for error handling
    test_cases = [
        # Non-existent file
        ("non_existent_file.txt", lambda: scan_cache.get_file_content("/path/to/non_existent_file.txt"), FileNotFoundError),
        
        # Permission denied
        ("/root/restricted.txt", lambda: scan_cache.get_file_content("/root/restricted.txt"), FileNotFoundError),
        
        # Invalid module name
        ("invalid_module", lambda: scan_cache.should_module_scan_file("invalid_module", "/tmp/test.txt"), ValueError),
        
        # Empty path
        ("empty_path", lambda: scan_cache.get_file_content(""), ValueError),
        
        # None path
        ("none_path", lambda: scan_cache.get_file_content(None), ValueError),
        
        # Directory path
        ("directory_path", lambda: scan_cache.get_file_content("/tmp"), IsADirectoryError),
    ]
    
    for test_name, test_func, expected_error in test_cases:
        try:
            test_func()
            log_test(f"❌ FAIL: {test_name} - Expected {expected_error.__name__} but no error was raised")
            failed += 1
        except Exception as e:
            if isinstance(e, expected_error):
                log_test(f"✅ PASS: {test_name} - Correctly raised {expected_error.__name__}")
                passed += 1
            else:
                log_test(f"❌ FAIL: {test_name} - Expected {expected_error.__name__} but got {type(e).__name__}")
                failed += 1
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_concurrent_scanning():
    """Test behavior under concurrent scanning operations"""
    log_test("\n=== Testing Concurrent Scanning ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    # Create test files
    test_files = []
    for i in range(10):
        fd, path = tempfile.mkstemp()
        os.write(fd, f"Test content {i}".encode())
        os.close(fd)
        test_files.append(path)
    
    try:
        def scan_file(file_path):
            content = scan_cache.get_file_content(file_path)
            time.sleep(0.1)  # Simulate processing
            return content
        
        # Test concurrent access
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(scan_file, f) for f in test_files]
            results = [f.result() for f in futures]
        
        # Verify results
        expected_contents = [f"Test content {i}" for i in range(10)]
        if results == expected_contents:
            log_test("✅ PASS: Concurrent file scanning produced correct results")
            return True
        else:
            log_test("❌ FAIL: Concurrent file scanning results mismatch")
            return False
            
    finally:
        # Cleanup
        for file_path in test_files:
            if os.path.exists(file_path):
                os.remove(file_path)

def test_memory_limits():
    """Test behavior with memory-intensive operations"""
    log_test("\n=== Testing Memory Usage Limits ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    small_files = []  # Initialize small_files list
    
    # Create a large test file (100MB)
    large_file = "/tmp/large_test_file.txt"
    try:
        with open(large_file, 'wb') as f:
            f.write(b'0' * (100 * 1024 * 1024))  # 100MB
        
        # Test reading large file
        try:
            content = scan_cache.get_file_content(large_file)
            if len(content) == 100 * 1024 * 1024:
                log_test("✅ PASS: Successfully read large file")
                passed += 1
            else:
                log_test("❌ FAIL: Large file content size mismatch")
                failed += 1
        except ValueError as e:
            if "File too large" in str(e):
                log_test("✅ PASS: Correctly rejected large file")
                passed += 1
            else:
                log_test(f"❌ FAIL: Unexpected error while reading large file: {str(e)}")
                failed += 1
        except MemoryError:
            log_test("❌ FAIL: Memory error while reading large file")
            failed += 1
        
        # Test cache behavior with many files
        try:
            for i in range(1000):
                fd, path = tempfile.mkstemp()
                os.write(fd, f"Small file {i}".encode())
                os.close(fd)
                small_files.append(path)
                scan_cache.get_file_content(path)
            
            log_test("✅ PASS: Successfully cached many files")
            passed += 1
        except Exception as e:
            log_test(f"❌ FAIL: Error while caching many files: {str(e)}")
            failed += 1
            
    finally:
        # Cleanup
        if os.path.exists(large_file):
            os.remove(large_file)
        for file_path in small_files:
            if os.path.exists(file_path):
                os.remove(file_path)
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_pattern_edge_cases():
    """Test pattern edge cases"""
    log_test("\n=== Testing Pattern Edge Cases ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    
    # Test cases
    test_cases = [
        # Empty path
        ("", "file_grepper", False),
        
        # Long path
        ("/a" * 500 + "/test.txt", "file_grepper", True),
        
        # Unicode path
        ("/tmp/测试/test.txt", "file_grepper", True),
        
        # Unicode path with emoji
        ("/tmp/🔑/secrets.env", "dotfile_scanner", True),
        
        # Special characters in path
        ("/tmp/test!@#$%^&*()_+-=.txt", "file_grepper", True),
        
        # Path traversal attempt
        ("../../../etc/passwd", "file_grepper", False),
        
        # Multiple extensions
        ("/tmp/test.tar.gz.env", "dotfile_scanner", True),
        
        # Hidden directory
        ("~/.hidden/.secret/.env", "dotfile_scanner", True),
        
        # Uppercase extension
        ("~/.ENV", "dotfile_scanner", True),
        
        # Mixed case path
        ("~/Projects/API_KEYS.txt", "file_grepper", True),
    ]
    
    for path, module, should_scan in test_cases:
        try:
            if not path:
                try:
                    scan_cache.should_module_scan_file(module, path)
                    log_test(f"❌ FAIL: {module} should have rejected empty path")
                    failed += 1
                except ValueError:
                    log_test(f"✅ PASS: {module} correctly rejected empty path")
                    passed += 1
            else:
                result = scan_cache.should_module_scan_file(module, path)
                if result == should_scan:
                    log_test(f"✅ PASS: {module} correctly {'allowed' if should_scan else 'rejected'} {path}")
                    passed += 1
                else:
                    log_test(f"❌ FAIL: {module} incorrectly {'rejected' if should_scan else 'allowed'} {path}")
                    failed += 1
        except Exception as e:
            if not path and isinstance(e, ValueError):
                log_test(f"✅ PASS: {module} correctly rejected empty path")
                passed += 1
            else:
                log_test(f"❌ FAIL: {module} incorrectly handled {path}: {str(e)}")
                failed += 1
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_filesystem_edge_cases():
    """Test file system edge cases"""
    log_test("\n=== Testing File System Edge Cases ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    
    test_dir = tempfile.mkdtemp()
    try:
        # Test symlinks
        normal_file = os.path.join(test_dir, "normal.txt")
        symlink_file = os.path.join(test_dir, "symlink.txt")
        with open(normal_file, 'w') as f:
            f.write("test content")
        os.symlink(normal_file, symlink_file)
        
        # Test broken symlinks
        broken_symlink = os.path.join(test_dir, "broken.txt")
        os.symlink("/nonexistent", broken_symlink)
        
        # Test circular symlinks
        circular1 = os.path.join(test_dir, "circular1")
        circular2 = os.path.join(test_dir, "circular2")
        os.symlink(circular2, circular1)
        os.symlink(circular1, circular2)
        
        # Test cases
        test_cases = [
            # Normal symlink
            (symlink_file, True, None),
            
            # Broken symlink
            (broken_symlink, False, FileNotFoundError),
            
            # Circular symlink
            (circular1, False, OSError),
            
            # Device files (if running as root)
            ("/dev/null", False, ValueError),
            
            # Named pipes
            (os.path.join(test_dir, "pipe"), False, ValueError),
        ]
        
        # Create named pipe
        try:
            os.mkfifo(os.path.join(test_dir, "pipe"))
        except:
            pass
        
        for path, should_read, expected_error in test_cases:
            try:
                content = scan_cache.get_file_content(path)
                if should_read:
                    if content == "test content":
                        log_test(f"✅ PASS: Successfully read {os.path.basename(path)}")
                        passed += 1
                    else:
                        log_test(f"❌ FAIL: Content mismatch for {os.path.basename(path)}")
                        failed += 1
                else:
                    log_test(f"❌ FAIL: Should not have been able to read {os.path.basename(path)}")
                    failed += 1
            except Exception as e:
                if expected_error and isinstance(e, expected_error):
                    log_test(f"✅ PASS: Correctly handled error for {os.path.basename(path)}")
                    passed += 1
                else:
                    log_test(f"❌ FAIL: Unexpected error for {os.path.basename(path)}: {str(e)}")
                    failed += 1
        
    finally:
        # Cleanup
        shutil.rmtree(test_dir)
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_config_validation():
    """Test configuration validation"""
    log_test("\n=== Testing Configuration Validation ===\n")
    
    passed = 0
    failed = 0
    
    test_configs = [
        # Missing required fields
        ({}, False),
        
        # Invalid module name
        ({
            "patterns": {"test": []},
            "module_territories": {"invalid_module": []}
        }, False),
        
        # Invalid pattern type
        ({
            "patterns": {"test": "not_a_list"},
            "module_territories": {}
        }, False),
        
        # Valid minimal config
        ({
            "modules": {
                "file_grepper": {
                    "enabled": True,
                    "priority": 1,
                    "timeout": 30
                }
            },
            "scan_paths": {
                "file_grepper": ["*.txt"]
            },
            "patterns": {}
        }, True),
        
        # Valid complex config
        ({
            "modules": {
                "file_grepper": {
                    "enabled": True,
                    "priority": 1,
                    "timeout": 30
                },
                "dotfile_scanner": {
                    "enabled": True,
                    "priority": 2,
                    "timeout": 30
                }
            },
            "scan_paths": {
                "file_grepper": ["*.txt", "*.log"],
                "dotfile_scanner": ["~/.env", "~/.config/*"]
            },
            "patterns": {
                "api_keys": ["API_KEY=", "api_key:"],
                "passwords": ["password=", "pwd="]
            }
        }, True)
    ]
    
    for config_data, should_pass in test_configs:
        # Write test config
        with open("/tmp/test_config.json", 'w') as f:
            json.dump(config_data, f)
        
        try:
            config = ConfigLoader("/tmp/test_config.json")
            if should_pass:
                log_test(f"✅ PASS: Valid config accepted")
                passed += 1
            else:
                log_test(f"❌ FAIL: Invalid config was accepted")
                failed += 1
        except Exception as e:
            if should_pass:
                log_test(f"❌ FAIL: Valid config rejected: {str(e)}")
                failed += 1
            else:
                log_test(f"✅ PASS: Invalid config correctly rejected")
                passed += 1
    
    # Cleanup
    if os.path.exists("/tmp/test_config.json"):
        os.remove("/tmp/test_config.json")
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def test_module_coordination():
    """Test coordination between different modules"""
    log_test("\n=== Testing Module Coordination ===\n")
    
    config = ConfigLoader("config.json")
    reset_scan_cache()
    scan_cache = get_scan_cache(config)
    
    passed = 0
    failed = 0
    
    # Create test directory structure
    test_dir = tempfile.mkdtemp()
    try:
        # Create a git repository with sensitive files
        repo_dir = os.path.join(test_dir, "repo")
        os.makedirs(repo_dir)
        os.makedirs(os.path.join(repo_dir, ".git"))
        
        test_files = {
            # File that should be scanned by git_scanner and dotfile_scanner only
            os.path.join(repo_dir, ".env"): {
                "content": "API_KEY=secret\nPASSWORD=test123",
                "modules": ["git_scanner", "dotfile_scanner"]  # file_grepper excluded since .env files are owned by dotfile_scanner
            },
            
            # File that should be excluded from all scanning
            os.path.join(repo_dir, "node_modules", "package.json"): {
                "content": '{"name": "test"}',
                "modules": []  # No module should scan node_modules
            },
            
            # File that should be scanned by file_grepper only
            os.path.join(repo_dir, "config.json"): {
                "content": '{"api_key": "test123"}',
                "modules": ["file_grepper"]  # Only file_grepper should scan regular json files
            }
        }
        
        # Create test files
        for file_path, info in test_files.items():
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                f.write(info["content"])
        
        # Test module coordination
        all_modules = ["git_scanner", "dotfile_scanner", "file_grepper"]
        
        for file_path, info in test_files.items():
            for module in all_modules:
                should_scan = module in info["modules"]
                result = scan_cache.should_module_scan_file(module, file_path)
                
                if result == should_scan:
                    log_test(f"✅ PASS: {module} correctly {'scanned' if should_scan else 'ignored'} {os.path.basename(file_path)}")
                    passed += 1
                else:
                    log_test(f"❌ FAIL: {module} incorrectly {'scanned' if result else 'ignored'} {os.path.basename(file_path)}")
                    failed += 1
                    
                    # Debug output for failures
                    if module == "file_grepper":
                        log_test(f"\n🔍 DEBUG: file_grepper scanning {os.path.basename(file_path)}")
                        log_test(f"  Result: {result}")
                        log_test(f"  Expected: {should_scan}")
                        log_test(f"  File path: {file_path}")
                        log_test(f"  Allowed modules: {info['modules']}")
    
    finally:
        # Cleanup
        shutil.rmtree(test_dir)
    
    log_test(f"\n=== Test Results: {passed} passed, {failed} failed ===")
    return failed == 0

def main():
    """Run all tests"""
    # Initialize test environment
    initialize_test_environment()
    
    tests = [
        test_territory_ownership,
        test_pattern_ownership,
        test_cache_functionality,
        test_error_handling,
        test_concurrent_scanning,
        test_memory_limits,
        test_pattern_edge_cases,
        test_filesystem_edge_cases,
        test_config_validation,
        test_module_coordination,
        test_single_case
    ]
    
    total_passed = 0
    total_failed = 0
    
    log_test("\n=== Starting Test Suite ===\n")
    
    for test in tests:
        header = f"\n{'='*20} Running {test.__name__} {'='*20}"
        log_test(header)
        
        try:
            result = test()
            if result:
                msg = f"\n✅ {test.__name__} PASSED"
                log_test(msg)
                total_passed += 1
            else:
                msg = f"\n❌ {test.__name__} FAILED"
                log_test(msg)
                total_failed += 1
        except Exception as e:
            msg = f"\n❌ ERROR: Test {test.__name__} failed with exception:\n  {str(e)}"
            log_test(msg)
            total_failed += 1
        
        footer = f"{'='*60}\n"
        log_test(footer)
    
    summary = f"""
=== Final Test Results ===
Total tests run: {total_passed + total_failed}
Tests passed:    {total_passed}
Tests failed:    {total_failed}
Success rate:    {(total_passed/(total_passed + total_failed))*100:.1f}%

{"="*30}
"""
    log_test(summary)
    
    sys.exit(1 if total_failed > 0 else 0)

if __name__ == "__main__":
    main() 