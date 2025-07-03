#!/usr/bin/env python3
"""
Git Repository Credential Scanner Module

This module searches for credentials and sensitive information in Git repositories.
It's designed to find secrets that may have been accidentally committed to version control,
including credentials in commit history, configuration files, and repository metadata.

Key Features:
- Discovers local Git repositories
- Scans commit history for credential patterns
- Analyzes Git configuration for embedded credentials
- Checks remote URLs for credential information
- Identifies sensitive files in repository history
- Scans commit messages for potential secrets
- Analyzes recently deleted files that might contain credentials

Contributors: This module safely analyzes Git repositories without making network calls.
All Git operations are read-only and include proper error handling.
"""

import os
import re
import subprocess
import glob
from pathlib import Path
from typing import List, Dict, Any, Optional
from modules.utils.logger import get_logger


class GitScanner:
    def __init__(self, config):
        self.config = config
        self.scan_paths = config.get("scan_paths", {}).get("git", [])
        self.patterns = config.get("patterns", {})
        self.logger = get_logger("credfinder.gitscanner")
        
        # Load exclusion settings
        self.exclusions = config.get("exclusions", {})
        self.excluded_dirs = set(self.exclusions.get("directories", []))
        self.excluded_file_patterns = self.exclusions.get("file_patterns", [])
        self.excluded_path_patterns = self.exclusions.get("path_patterns", [])

        
        # Load Git-specific settings from config
        self.git_settings = config.get("module_settings", {}).get("git", {})
        self.max_commits_scan = self.git_settings.get("max_commits_scan", 100)
        self.max_file_size_bytes = self.git_settings.get("max_file_size_bytes", 1048576)  # 1MB
        self.git_command_timeout = self.git_settings.get("git_command_timeout", 10)
        self.context_size = self.git_settings.get("context_size", 50)
        self.skip_binary_files = self.git_settings.get("skip_binary_files", True)
        self.sensitive_file_patterns = self.git_settings.get("sensitive_file_patterns", [
            "*.env*", "*.key", "*.pem", "*.p12", "*.pfx", "*.jks", 
            "*config*", "*secret*", "*credential*", "*password*"
        ])
        
    def scan(self) -> Dict[str, Any]:
        """
        Main scan method that orchestrates all Git-related credential discovery.
        
        Returns:
            Dict containing all Git findings organized by type
        """
        results = {
            "repositories": [],
            "commit_history": [],
            "config_credentials": [],
            "remote_urls": [],
            "sensitive_files": [],
            "recent_deletions": [],
            "scan_stats": {
                "repositories_found": 0,
                "repositories_scanned": 0,
                "commits_scanned": 0,
                "files_analyzed": 0,
                "access_denied": 0,
                "git_errors": 0,
                "other_errors": 0
            }
        }
        
        # Find Git repositories
        repositories = self._find_git_repositories(results["scan_stats"])
        results["repositories"] = repositories
        
        # Scan each repository for credentials
        for repo in repositories:
            try:
                repo_path = repo["path"]
                
                # Scan commit history
                commit_findings = self._scan_commit_history(repo_path, results["scan_stats"])
                results["commit_history"].extend(commit_findings)
                
                # Check Git configuration
                config_findings = self._scan_git_config(repo_path, results["scan_stats"])
                results["config_credentials"].extend(config_findings)
                
                # Analyze remote URLs
                remote_findings = self._scan_remote_urls(repo_path, results["scan_stats"])
                results["remote_urls"].extend(remote_findings)
                
                # Find sensitive files
                sensitive_findings = self._find_sensitive_files(repo_path, results["scan_stats"])
                results["sensitive_files"].extend(sensitive_findings)
                
                # Check recently deleted files
                deletion_findings = self._check_recent_deletions(repo_path, results["scan_stats"])
                results["recent_deletions"].extend(deletion_findings)
                
                results["scan_stats"]["repositories_scanned"] += 1
                
            except Exception as e:
                results["scan_stats"]["other_errors"] += 1
                self.logger.warning(f"Error scanning repository {repo.get('path', 'unknown')}: {e}")
        
        # Log summary statistics
        stats = results["scan_stats"]
        self.logger.info(f"Git scan completed: {stats['repositories_found']} repositories found, "
                        f"{stats['repositories_scanned']} scanned, {stats['commits_scanned']} commits analyzed")
        
        return results
    
    def _find_git_repositories(self, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Find Git repositories in configured scan paths.
        
        Args:
            stats: Statistics dictionary to update during scanning
            
        Returns:
            List of Git repository information
        """
        repositories = []
        
        # Default paths if none configured
        if not self.scan_paths:
            self.scan_paths = [
                "~/",
                "~/projects/",
                "~/work/",
                "~/workspace/",
                "~/Documents/",
                "~/Desktop/"
            ]
        
        for base_path in self.scan_paths:
            try:
                expanded_path = os.path.expanduser(base_path)
                
                # Look for .git directories
                if os.path.exists(expanded_path):
                    for root, dirs, files in os.walk(expanded_path):
                        # Skip excluded directories
                        dirs[:] = [d for d in dirs if not self._should_exclude_path(os.path.join(root, d))]
                        
                        if '.git' in dirs:
                            repo_path = root
                            
                            # Skip if repository path should be excluded
                            if self._should_exclude_path(repo_path):
                                continue
                                
                            repo_info = self._analyze_repository(repo_path)
                            if repo_info:
                                repositories.append(repo_info)
                                stats["repositories_found"] += 1
                            
                            # Don't recurse into .git directories
                            dirs.remove('.git')
                            
            except Exception as e:
                stats["other_errors"] += 1
                self.logger.warning(f"Error searching for repositories in {base_path}: {e}")
        
        return repositories
    
    def _analyze_repository(self, repo_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze basic repository information.
        
        Args:
            repo_path: Path to the Git repository
            
        Returns:
            Repository information dictionary or None if analysis fails
        """
        try:
            # Get basic repository information
            repo_info = {
                "path": repo_path,
                "name": os.path.basename(repo_path),
                "git_dir": os.path.join(repo_path, ".git"),
                "is_bare": False,
                "branch": None,
                "remotes": [],
                "last_commit": None
            }
            
            # Check if it's a bare repository
            if os.path.isfile(os.path.join(repo_path, ".git")):
                # This might be a git worktree or submodule
                try:
                    with open(os.path.join(repo_path, ".git"), 'r') as f:
                        git_content = f.read().strip()
                        if git_content.startswith("gitdir:"):
                            repo_info["git_dir"] = git_content.split(":", 1)[1].strip()
                except Exception:
                    pass
            
            # Get current branch
            try:
                result = self._run_git_command(repo_path, ["branch", "--show-current"])
                if result and result.strip():
                    repo_info["branch"] = result.strip()
            except Exception:
                pass
            
            # Get remote information
            try:
                result = self._run_git_command(repo_path, ["remote", "-v"])
                if result:
                    for line in result.strip().split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                remote_name = parts[0]
                                remote_url = parts[1]
                                if remote_name not in [r["name"] for r in repo_info["remotes"]]:
                                    repo_info["remotes"].append({
                                        "name": remote_name,
                                        "url": remote_url
                                    })
            except Exception:
                pass
            
            # Get last commit info
            try:
                result = self._run_git_command(repo_path, ["log", "-1", "--format=%H|%s|%an|%ad", "--date=short"])
                if result and result.strip():
                    commit_parts = result.strip().split('|', 3)
                    if len(commit_parts) >= 4:
                        repo_info["last_commit"] = {
                            "hash": commit_parts[0],
                            "message": commit_parts[1],
                            "author": commit_parts[2],
                            "date": commit_parts[3]
                        }
            except Exception:
                pass
            
            return repo_info
            
        except Exception as e:
            self.logger.debug(f"Failed to analyze repository {repo_path}: {e}")
            return None
    
    def _scan_commit_history(self, repo_path: str, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Scan commit history for credential patterns.
        
        Args:
            repo_path: Path to the Git repository
            stats: Statistics dictionary to update
            
        Returns:
            List of commits containing potential credentials
        """
        findings = []
        
        try:
            # Get recent commit hashes
            result = self._run_git_command(repo_path, [
                "log", f"--max-count={self.max_commits_scan}", "--format=%H"
            ])
            
            if not result:
                return findings
            
            commit_hashes = [h.strip() for h in result.strip().split('\n') if h.strip()]
            
            for commit_hash in commit_hashes:
                try:
                    # Get commit diff
                    diff_result = self._run_git_command(repo_path, [
                        "show", "--format=%H|%s|%an|%ad", "--date=short", commit_hash
                    ])
                    
                    if diff_result:
                        stats["commits_scanned"] += 1
                        
                        # Check for credential patterns in the diff
                        matches = self._check_credential_patterns(diff_result)
                        
                        if matches:
                            # Parse commit info
                            lines = diff_result.split('\n')
                            commit_info = None
                            
                            if lines and '|' in lines[0]:
                                commit_parts = lines[0].split('|', 3)
                                if len(commit_parts) >= 4:
                                    commit_info = {
                                        "hash": commit_parts[0],
                                        "message": commit_parts[1],
                                        "author": commit_parts[2],
                                        "date": commit_parts[3]
                                    }
                            
                            findings.append({
                                "repository": repo_path,
                                "commit": commit_info or {"hash": commit_hash},
                                "matches": matches,
                                "diff_preview": diff_result[:1000] + "..." if len(diff_result) > 1000 else diff_result
                            })
                            
                except Exception as e:
                    stats["git_errors"] += 1
                    self.logger.debug(f"Error scanning commit {commit_hash}: {e}")
                    
        except Exception as e:
            stats["git_errors"] += 1
            self.logger.warning(f"Error scanning commit history for {repo_path}: {e}")
        
        return findings
    
    def _scan_git_config(self, repo_path: str, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Scan Git configuration files for embedded credentials.
        
        Args:
            repo_path: Path to the Git repository
            stats: Statistics dictionary to update
            
        Returns:
            List of configuration files with credential information
        """
        findings = []
        
        config_files = [
            os.path.join(repo_path, ".git", "config"),
            os.path.join(repo_path, ".gitconfig"),
            os.path.join(repo_path, ".git-credentials")
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    matches = self._check_credential_patterns(content)
                    
                    if matches:
                        findings.append({
                            "repository": repo_path,
                            "config_file": config_file,
                            "type": os.path.basename(config_file),
                            "matches": matches,
                            "content_preview": content[:500] + "..." if len(content) > 500 else content
                        })
                        
                except Exception as e:
                    stats["other_errors"] += 1
                    self.logger.debug(f"Error reading config file {config_file}: {e}")
        
        return findings
    
    def _scan_remote_urls(self, repo_path: str, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Analyze remote URLs for embedded credentials.
        
        Args:
            repo_path: Path to the Git repository
            stats: Statistics dictionary to update
            
        Returns:
            List of remote URLs containing credentials
        """
        findings = []
        
        try:
            result = self._run_git_command(repo_path, ["remote", "-v"])
            
            if result:
                for line in result.strip().split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            remote_name = parts[0]
                            remote_url = parts[1]
                            
                            # Check for credentials in URL
                            if self._has_credentials_in_url(remote_url):
                                findings.append({
                                    "repository": repo_path,
                                    "remote_name": remote_name,
                                    "url": remote_url,
                                    "credential_type": self._identify_url_credential_type(remote_url)
                                })
                                
        except Exception as e:
            stats["git_errors"] += 1
            self.logger.debug(f"Error scanning remote URLs for {repo_path}: {e}")
        
        return findings
    
    def _find_sensitive_files(self, repo_path: str, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Find sensitive files in repository history.
        
        Args:
            repo_path: Path to the Git repository
            stats: Statistics dictionary to update
            
        Returns:
            List of sensitive files found in the repository
        """
        findings = []
        
        try:
            # Get all files ever tracked in the repository
            result = self._run_git_command(repo_path, ["log", "--name-only", "--format=", "--all"])
            
            if result:
                all_files = set()
                for line in result.strip().split('\n'):
                    if line.strip():
                        all_files.add(line.strip())
                
                # Check each file against sensitive patterns
                for file_path in all_files:
                    # Skip excluded files
                    if self._should_exclude_path(file_path):
                        continue
                        
                    if self._is_sensitive_file(file_path):
                        stats["files_analyzed"] += 1
                        
                        # Check if file still exists
                        full_path = os.path.join(repo_path, file_path)
                        exists = os.path.exists(full_path)
                        
                        finding = {
                            "repository": repo_path,
                            "file_path": file_path,
                            "exists": exists,
                            "pattern_matched": self._get_matching_pattern(file_path)
                        }
                        
                        # If file still exists, check its content
                        if exists:
                            try:
                                file_size = os.path.getsize(full_path)
                                if file_size <= self.max_file_size_bytes:
                                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                    
                                    matches = self._check_credential_patterns(content)
                                    if matches:
                                        finding["content_matches"] = matches
                                        finding["content_preview"] = content[:200] + "..." if len(content) > 200 else content
                                        
                            except Exception:
                                pass
                        
                        findings.append(finding)
                        
        except Exception as e:
            stats["git_errors"] += 1
            self.logger.debug(f"Error finding sensitive files for {repo_path}: {e}")
        
        return findings
    
    def _check_recent_deletions(self, repo_path: str, stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """
        Check for recently deleted files that might contain credentials.
        
        Args:
            repo_path: Path to the Git repository
            stats: Statistics dictionary to update
            
        Returns:
            List of recently deleted sensitive files
        """
        findings = []
        
        try:
            # Get recent deletions
            result = self._run_git_command(repo_path, [
                "log", "--diff-filter=D", "--summary", "--format=%H|%s|%an|%ad", 
                "--date=short", f"--max-count={self.max_commits_scan}"
            ])
            
            if result:
                current_commit = None
                
                for line in result.split('\n'):
                    line = line.strip()
                    
                    if '|' in line and len(line.split('|')) >= 4:
                        # This is a commit line
                        commit_parts = line.split('|', 3)
                        current_commit = {
                            "hash": commit_parts[0],
                            "message": commit_parts[1],
                            "author": commit_parts[2],
                            "date": commit_parts[3]
                        }
                    elif line.startswith("delete mode") and current_commit:
                        # This is a deletion line
                        # Format: "delete mode 100644 path/to/file"
                        parts = line.split()
                        if len(parts) >= 4:
                            deleted_file = parts[3]
                            
                            # Skip excluded files
                            if self._should_exclude_path(deleted_file):
                                continue
                            
                            if self._is_sensitive_file(deleted_file):
                                findings.append({
                                    "repository": repo_path,
                                    "deleted_file": deleted_file,
                                    "commit": current_commit,
                                    "pattern_matched": self._get_matching_pattern(deleted_file)
                                })
                                
        except Exception as e:
            stats["git_errors"] += 1
            self.logger.debug(f"Error checking recent deletions for {repo_path}: {e}")
        
        return findings
    
    def _run_git_command(self, repo_path: str, args: List[str]) -> Optional[str]:
        """
        Run a Git command safely with timeout and error handling.
        
        Args:
            repo_path: Path to the Git repository
            args: Git command arguments
            
        Returns:
            Command output or None if command fails
        """
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=self.git_command_timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                self.logger.debug(f"Git command failed: {' '.join(args)}, error: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.debug(f"Git command timed out: {' '.join(args)}")
            return None
        except Exception as e:
            self.logger.debug(f"Error running git command {' '.join(args)}: {e}")
            return None
    
    def _check_credential_patterns(self, content: str) -> List[Dict[str, Any]]:
        """
        Check content against configured credential patterns.
        
        Args:
            content: Content to search
            
        Returns:
            List of pattern matches found
        """
        matches = []
        
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    regex_matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in regex_matches:
                        match_str = str(match)
                        
                        matches.append({
                            "pattern_type": pattern_type,
                            "pattern": pattern,
                            "match": match_str if len(match_str) < 200 else match_str[:200] + "...",
                            "context": self._get_context(content, match_str)
                        })
                except Exception as e:
                    self.logger.debug(f"Error applying pattern {pattern}: {e}")
        
        return matches
    
    def _get_context(self, content: str, match: str) -> str:
        """
        Get context around a match for better analysis.
        
        Args:
            content: Full content
            match: The matched string
            
        Returns:
            Context string around the match
        """
        try:
            match_pos = content.find(match)
            if match_pos == -1:
                return ""
            
            start = max(0, match_pos - self.context_size)
            end = min(len(content), match_pos + len(match) + self.context_size)
            
            context = content[start:end]
            
            # Replace newlines with spaces for better readability
            context = re.sub(r'\s+', ' ', context).strip()
            
            return context
            
        except Exception:
            return ""
    
    def _has_credentials_in_url(self, url: str) -> bool:
        """
        Check if a URL contains embedded credentials.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL contains credentials
        """
        # Get URL credential patterns from config
        url_patterns = self.git_settings.get('url_credential_patterns', [
            '://[^/\\s]+:[^/\\s@]+@'  # Default fallback pattern
        ])
        
        for pattern in url_patterns:
            if re.search(pattern, url):
                return True
        
        return False
    
    def _identify_url_credential_type(self, url: str) -> str:
        """
        Identify the type of credentials in a URL.
        
        Args:
            url: URL containing credentials
            
        Returns:
            Type of credentials identified
        """
        if "token" in url.lower():
            return "token"
        elif "@github.com" in url.lower() or "@gitlab.com" in url.lower():
            return "git_credentials"
        else:
            return "username_password"
    
    def _is_sensitive_file(self, file_path: str) -> bool:
        """
        Check if a file path matches sensitive file patterns.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file is considered sensitive
        """
        for pattern in self.sensitive_file_patterns:
            if self._matches_pattern(file_path, pattern):
                return True
        return False
    

    
    def _get_matching_pattern(self, file_path: str) -> Optional[str]:
        """
        Get the pattern that matches a sensitive file.
        
        Args:
            file_path: Path to check
            
        Returns:
            Matching pattern or None
        """
        for pattern in self.sensitive_file_patterns:
            if self._matches_pattern(file_path, pattern):
                return pattern
        return None
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """
        Check if a file path matches a glob pattern.
        
        Args:
            file_path: File path to check
            pattern: Glob pattern
            
        Returns:
            True if path matches pattern
        """
        import fnmatch
        return fnmatch.fnmatch(file_path.lower(), pattern.lower())
    
    def _should_exclude_path(self, path: str) -> bool:
        """
        Check if a path should be excluded based on exclusion rules.
        
        Args:
            path: Path to check for exclusions
            
        Returns:
            True if path should be excluded
        """
        import fnmatch
        
        # Normalize path for consistent checking
        normalized_path = os.path.normpath(path)
        path_parts = normalized_path.split(os.sep)
        
        # Check directory exclusions
        for part in path_parts:
            if part in self.excluded_dirs:
                return True
        
        # Check path pattern exclusions
        for pattern in self.excluded_path_patterns:
            if fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(path, pattern):
                return True
        
        # Check file pattern exclusions for files
        if os.path.isfile(path):
            filename = os.path.basename(path)
            for pattern in self.excluded_file_patterns:
                if fnmatch.fnmatch(filename, pattern):
                    return True
        
        return False 