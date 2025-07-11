#!/usr/bin/env python3
"""
Advanced Result Deduplication System

This module implements sophisticated deduplication logic to merge duplicate findings
across different scanner modules, reducing false positives and providing cleaner results.

Key Features:
- Cross-module finding deduplication
- Intelligent similarity detection
- Finding consolidation and merging
- Confidence scoring for deduplicated results
- Detailed deduplication statistics
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from difflib import SequenceMatcher
from modules.utils.logger import get_logger


class ResultDeduplicator:
    """Advanced deduplication system for scan findings."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("credfinder.deduplicator")
        
        # Deduplication settings
        self.dedup_config = config.get("module_coordination", {}).get("deduplication", {})
        self.similarity_threshold = self.dedup_config.get("similarity_threshold", 0.85)
        self.exact_match_threshold = self.dedup_config.get("exact_match_threshold", 1.0)
        self.context_weight = self.dedup_config.get("context_weight", 0.3)
        self.location_weight = self.dedup_config.get("location_weight", 0.4)
        self.content_weight = self.dedup_config.get("content_weight", 0.3)
        
        # Statistics
        self.dedup_stats = {
            "total_findings_before": 0,
            "total_findings_after": 0,
            "exact_duplicates_removed": 0,
            "similar_findings_merged": 0,
            "cross_module_duplicates": 0,
            "deduplication_groups": 0
        }
        
        self.logger.info(f"ResultDeduplicator initialized with similarity threshold: {self.similarity_threshold}")
    
    def deduplicate_all_findings(self, module_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive deduplication across all module findings.
        
        Args:
            module_results: Dictionary of module results
            
        Returns:
            Deduplicated module results with merged findings
        """
        self.logger.info("Starting comprehensive result deduplication")
        
        # Extract all findings from all modules
        all_findings = self._extract_all_findings(module_results)
        self.dedup_stats["total_findings_before"] = len(all_findings)
        
        if not all_findings:
            return module_results
        
        # Group findings by similarity
        finding_groups = self._group_similar_findings(all_findings)
        self.dedup_stats["deduplication_groups"] = len(finding_groups)
        
        # Merge findings within each group
        deduplicated_findings = []
        for group in finding_groups:
            if len(group) > 1:
                merged_finding = self._merge_finding_group(group)
                deduplicated_findings.append(merged_finding)
                
                # Update statistics
                if self._are_exact_duplicates(group):
                    self.dedup_stats["exact_duplicates_removed"] += len(group) - 1
                else:
                    self.dedup_stats["similar_findings_merged"] += len(group) - 1
                
                # Check for cross-module duplicates
                modules_in_group = set(f.get('source_module', '') for f in group)
                if len(modules_in_group) > 1:
                    self.dedup_stats["cross_module_duplicates"] += len(group) - 1
            else:
                deduplicated_findings.extend(group)
        
        self.dedup_stats["total_findings_after"] = len(deduplicated_findings)
        
        # Redistribute findings back to modules
        deduplicated_results = self._redistribute_findings(deduplicated_findings, module_results)
        
        self._log_deduplication_summary()
        return deduplicated_results
    
    def _extract_all_findings(self, module_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all findings from module results with source tracking."""
        all_findings = []
        
        for module_name, module_data in module_results.items():
            if not isinstance(module_data, dict):
                continue
            
            # Skip modules with error status
            if module_data.get('_status') in ['failed', 'skipped', 'timeout']:
                continue
            
            findings = self._extract_module_findings(module_name, module_data)
            for finding in findings:
                finding['source_module'] = module_name
                finding['original_index'] = len(all_findings)
                all_findings.append(finding)
        
        self.logger.debug(f"Extracted {len(all_findings)} findings from {len(module_results)} modules")
        return all_findings
    
    def _extract_module_findings(self, module_name: str, module_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from a specific module's data."""
        findings = []
        
        # Handle different module data structures
        if module_name == "ssh":
            findings.extend(self._extract_ssh_findings(module_data))
        elif module_name == "browser":
            findings.extend(self._extract_browser_findings(module_data))
        elif module_name == "keyring":
            findings.extend(self._extract_keyring_findings(module_data))
        elif module_name == "history":
            findings.extend(self._extract_history_findings(module_data))
        elif module_name == "dotfiles":
            findings.extend(self._extract_dotfile_findings(module_data))
        elif module_name == "file_grep":
            findings.extend(self._extract_file_grep_findings(module_data))
        elif module_name == "git":
            findings.extend(self._extract_git_findings(module_data))
        else:
            # Generic extraction for unknown modules
            findings.extend(self._extract_generic_findings(module_data))
        
        return findings
    
    def _extract_ssh_findings(self, ssh_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from SSH scanner data."""
        findings = []
        
        # Private keys
        for key in ssh_data.get("private_keys", []):
            findings.append({
                "type": "ssh_private_key",
                "file": key.get("file", ""),
                "content": key.get("key_type", "") + "_key",
                "location": key.get("file", ""),
                "context": f"SSH private key: {key.get('key_type', 'unknown')}",
                "risk_level": "critical"
            })
        
        # Public keys
        for key in ssh_data.get("public_keys", []):
            findings.append({
                "type": "ssh_public_key",
                "file": key.get("file", ""),
                "content": key.get("key_type", "") + "_public",
                "location": key.get("file", ""),
                "context": f"SSH public key: {key.get('key_type', 'unknown')}",
                "risk_level": "medium"
            })
        
        return findings
    
    def _extract_browser_findings(self, browser_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from browser data."""
        findings = []
        
        for browser_type, browser_info in browser_data.items():
            if isinstance(browser_info, dict) and "passwords" in browser_info:
                for entry in browser_info["passwords"]:
                    findings.append({
                        "type": "browser_credential",
                        "file": browser_type,
                        "content": f"{entry.get('username', '')}@{entry.get('url', '')}",
                        "location": entry.get('profile_path', ''),
                        "context": f"Browser password for {entry.get('url', 'unknown')}",
                        "risk_level": "critical"
                    })
        
        return findings
    
    def _extract_keyring_findings(self, keyring_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from keyring data."""
        findings = []
        
        for keyring_type, keyring_info in keyring_data.items():
            if isinstance(keyring_info, dict) and "items" in keyring_info:
                for item in keyring_info["items"]:
                    service = item.get('attributes', {}).get('service', 'unknown')
                    findings.append({
                        "type": "keyring_credential",
                        "file": keyring_type,
                        "content": service,
                        "location": keyring_type,
                        "context": f"Keyring credential for {service}",
                        "risk_level": "critical"
                    })
        
        return findings
    
    def _extract_history_findings(self, history_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract findings from history data."""
        findings = []
        
        if isinstance(history_data, list):
            for entry in history_data:
                if isinstance(entry, dict):
                    findings.append({
                        "type": "command_history",
                        "file": entry.get("file", ""),
                        "content": entry.get("command", "")[:100],  # Truncate for comparison
                        "location": f"{entry.get('file', '')}:{entry.get('line_number', 0)}",
                        "context": entry.get("command", "")[:200],
                        "risk_level": entry.get("risk_level", "medium")
                    })
        
        return findings
    
    def _extract_dotfile_findings(self, dotfile_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from dotfile data."""
        findings = []
        
        for file_type, file_list in dotfile_data.items():
            if isinstance(file_list, list):
                for file_entry in file_list:
                    if isinstance(file_entry, dict):
                        for match in file_entry.get("pattern_matches", []):
                            findings.append({
                                "type": "dotfile_credential",
                                "file": file_entry.get("file", ""),
                                "content": match.get("match", ""),
                                "location": file_entry.get("file", ""),
                                "context": match.get("context", ""),
                                "risk_level": "medium"
                            })
        
        return findings
    
    def _extract_file_grep_findings(self, file_grep_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from file grep data."""
        findings = []
        
        for match in file_grep_data.get("file_matches", []):
            if isinstance(match, dict):
                for pattern_match in match.get("pattern_matches", []):
                    findings.append({
                        "type": "file_pattern_match",
                        "file": match.get("file", ""),
                        "content": pattern_match.get("match", ""),
                        "location": match.get("file", ""),
                        "context": pattern_match.get("context", ""),
                        "risk_level": "medium"
                    })
        
        return findings
    
    def _extract_git_findings(self, git_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from git data."""
        findings = []
        
        # Commit history findings
        for commit in git_data.get("commit_history", []):
            for match in commit.get("matches", []):
                findings.append({
                    "type": "git_commit_credential",
                    "file": commit.get("repository", ""),
                    "content": match.get("match", ""),
                    "location": f"{commit.get('repository', '')}:{commit.get('commit', {}).get('hash', '')[:8]}",
                    "context": match.get("context", ""),
                    "risk_level": "critical"
                })
        
        # Remote URL credentials
        for remote in git_data.get("remote_urls", []):
            findings.append({
                "type": "git_remote_credential",
                "file": remote.get("repository", ""),
                "content": remote.get("url", ""),
                "location": f"{remote.get('repository', '')}:remote:{remote.get('remote_name', '')}",
                "context": f"Git remote URL: {remote.get('url', '')}",
                "risk_level": "critical"
            })
        
        return findings
    
    def _extract_generic_findings(self, module_data: Any) -> List[Dict[str, Any]]:
        """Generic extraction for unknown module types."""
        findings = []
        
        if isinstance(module_data, list):
            for item in module_data:
                findings.append({
                    "type": "generic_finding",
                    "file": str(item.get("file", "")) if isinstance(item, dict) else "",
                    "content": str(item)[:100],
                    "location": str(item.get("location", "")) if isinstance(item, dict) else "",
                    "context": str(item)[:200],
                    "risk_level": "low"
                })
        elif isinstance(module_data, dict):
            for key, value in module_data.items():
                if isinstance(value, list):
                    findings.extend(self._extract_generic_findings(value))
        
        return findings
    
    def _group_similar_findings(self, findings: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group findings by similarity using multiple comparison methods."""
        groups = []
        processed = set()
        
        for i, finding in enumerate(findings):
            if i in processed:
                continue
            
            # Start a new group with this finding
            group = [finding]
            processed.add(i)
            
            # Find similar findings
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed:
                    continue
                
                similarity = self._calculate_finding_similarity(finding, other_finding)
                if similarity >= self.similarity_threshold:
                    group.append(other_finding)
                    processed.add(j)
            
            groups.append(group)
        
        return groups
    
    def _calculate_finding_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity score between two findings."""
        
        # Content similarity (most important)
        content1 = str(finding1.get('content', '')).lower().strip()
        content2 = str(finding2.get('content', '')).lower().strip()
        content_sim = SequenceMatcher(None, content1, content2).ratio()
        
        # Location similarity
        location1 = str(finding1.get('location', '')).lower()
        location2 = str(finding2.get('location', '')).lower()
        location_sim = SequenceMatcher(None, location1, location2).ratio()
        
        # Context similarity
        context1 = str(finding1.get('context', '')).lower()[:100]  # Limit context length
        context2 = str(finding2.get('context', '')).lower()[:100]
        context_sim = SequenceMatcher(None, context1, context2).ratio()
        
        # Type similarity (exact match for type)
        type_sim = 1.0 if finding1.get('type') == finding2.get('type') else 0.0
        
        # Weighted similarity score
        similarity = (
            content_sim * self.content_weight +
            location_sim * self.location_weight +
            context_sim * self.context_weight +
            type_sim * 0.2  # Small weight for type matching
        )
        
        return min(similarity, 1.0)  # Cap at 1.0
    
    def _are_exact_duplicates(self, group: List[Dict[str, Any]]) -> bool:
        """Check if all findings in a group are exact duplicates."""
        if len(group) <= 1:
            return False
        
        first_finding = group[0]
        for finding in group[1:]:
            if (finding.get('content') != first_finding.get('content') or
                finding.get('location') != first_finding.get('location') or
                finding.get('type') != first_finding.get('type')):
                return False
        
        return True
    
    def _merge_finding_group(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge a group of similar findings into a single consolidated finding."""
        if len(group) == 1:
            return group[0]
        
        # Use the finding with the highest risk level as the base
        base_finding = max(group, key=lambda f: self._risk_level_priority(f.get('risk_level', 'low')))
        
        # Merge information from all findings
        merged_finding = base_finding.copy()
        
        # Collect all source modules
        source_modules = list(set(f.get('source_module', '') for f in group))
        merged_finding['source_modules'] = source_modules
        
        # Collect all locations
        locations = list(set(f.get('location', '') for f in group if f.get('location')))
        if len(locations) > 1:
            merged_finding['all_locations'] = locations
        
        # Merge contexts (take the longest one)
        contexts = [f.get('context', '') for f in group if f.get('context')]
        if contexts:
            merged_finding['context'] = max(contexts, key=len)
        
        # Add deduplication metadata
        merged_finding['deduplication_info'] = {
            'is_merged': True,
            'original_count': len(group),
            'source_modules': source_modules,
            'similarity_method': 'content_location_context'
        }
        
        return merged_finding
    
    def _risk_level_priority(self, risk_level: str) -> int:
        """Convert risk level to priority number for sorting."""
        priorities = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        return priorities.get(risk_level.lower(), 0)
    
    def _redistribute_findings(self, deduplicated_findings: List[Dict[str, Any]], 
                             original_results: Dict[str, Any]) -> Dict[str, Any]:
        """Redistribute deduplicated findings back to their source modules."""
        # Create a copy of original results
        new_results = {}
        
        for module_name, module_data in original_results.items():
            if isinstance(module_data, dict) and module_data.get('_status') not in ['failed', 'skipped', 'timeout']:
                new_results[module_name] = self._clear_module_findings(module_data)
            else:
                new_results[module_name] = module_data
        
        # Redistribute findings to their primary source modules
        for finding in deduplicated_findings:
            primary_module = finding.get('source_module')
            if primary_module and primary_module in new_results:
                self._add_finding_to_module(new_results[primary_module], finding, primary_module)
        
        return new_results
    
    def _clear_module_findings(self, module_data: Dict[str, Any]) -> Dict[str, Any]:
        """Clear existing findings from module data while preserving structure."""
        cleared_data = module_data.copy()
        
        # Clear different data structures based on common patterns
        finding_keys = [
            'private_keys', 'public_keys', 'passwords', 'items', 'file_matches',
            'commit_history', 'config_credentials', 'remote_urls', 'sensitive_files',
            'config_files', 'env_files', 'git_configs', 'aws_configs'
        ]
        
        for key in finding_keys:
            if key in cleared_data:
                if isinstance(cleared_data[key], list):
                    cleared_data[key] = []
                elif isinstance(cleared_data[key], dict):
                    cleared_data[key] = {}
        
        return cleared_data
    
    def _add_finding_to_module(self, module_data: Dict[str, Any], finding: Dict[str, Any], module_name: str) -> None:
        """Add a deduplicated finding back to its module's data structure."""
        finding_type = finding.get('type', '')
        
        # Convert back to module-specific format
        if module_name == "ssh":
            if finding_type == "ssh_private_key":
                if 'private_keys' not in module_data:
                    module_data['private_keys'] = []
                module_data['private_keys'].append(self._convert_to_ssh_format(finding))
            elif finding_type == "ssh_public_key":
                if 'public_keys' not in module_data:
                    module_data['public_keys'] = []
                module_data['public_keys'].append(self._convert_to_ssh_format(finding))
        
        elif module_name == "history":
            if 'history_findings' not in module_data:
                module_data['history_findings'] = []
            module_data['history_findings'].append(self._convert_to_history_format(finding))
        
        # Add more module-specific conversions as needed
        else:
            # Generic format for unknown modules
            if 'deduplicated_findings' not in module_data:
                module_data['deduplicated_findings'] = []
            module_data['deduplicated_findings'].append(finding)
    
    def _convert_to_ssh_format(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Convert finding back to SSH module format."""
        return {
            'file': finding.get('file', ''),
            'key_type': finding.get('content', '').replace('_key', '').replace('_public', ''),
            'deduplication_info': finding.get('deduplication_info', {})
        }
    
    def _convert_to_history_format(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Convert finding back to history module format."""
        return {
            'file': finding.get('file', ''),
            'command': finding.get('content', ''),
            'risk_level': finding.get('risk_level', 'medium'),
            'deduplication_info': finding.get('deduplication_info', {})
        }
    
    def _log_deduplication_summary(self) -> None:
        """Log summary of deduplication results."""
        stats = self.dedup_stats
        reduction_count = stats["total_findings_before"] - stats["total_findings_after"]
        reduction_percent = (reduction_count / stats["total_findings_before"] * 100) if stats["total_findings_before"] > 0 else 0
        
        self.logger.info(f"Deduplication complete: {stats['total_findings_before']} → {stats['total_findings_after']} "
                        f"({reduction_count} removed, {reduction_percent:.1f}% reduction)")
        self.logger.info(f"Exact duplicates removed: {stats['exact_duplicates_removed']}")
        self.logger.info(f"Similar findings merged: {stats['similar_findings_merged']}")
        self.logger.info(f"Cross-module duplicates: {stats['cross_module_duplicates']}")
    
    def get_deduplication_statistics(self) -> Dict[str, Any]:
        """Get detailed deduplication statistics."""
        stats = self.dedup_stats.copy()
        
        if stats["total_findings_before"] > 0:
            stats["reduction_percentage"] = round(
                (stats["total_findings_before"] - stats["total_findings_after"]) / 
                stats["total_findings_before"] * 100, 2
            )
        else:
            stats["reduction_percentage"] = 0.0
        
        return stats 