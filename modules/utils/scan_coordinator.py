#!/usr/bin/env python3
"""
Central Scan Coordinator - Priority 3 Architecture Enhancement
Orchestrates all modules, manages shared result cache, and provides performance monitoring.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import json
import os

from .logger import get_logger
from .scan_cache import get_scan_cache
from .result_deduplicator import ResultDeduplicator
from .smart_exclusions import SmartExclusions


@dataclass
class ScanPlan:
    """Represents a coordinated scan execution plan."""
    modules: List[str]
    execution_order: List[str]
    parallel_groups: List[List[str]]
    dependencies: Dict[str, List[str]]
    estimated_duration: float
    resource_requirements: Dict[str, Any]


@dataclass
class ModuleMetrics:
    """Detailed metrics for a module execution."""
    module_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    execution_time: float = 0.0
    status: str = "pending"  # pending, running, completed, failed
    findings_count: int = 0
    files_processed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    error_message: Optional[str] = None
    performance_score: float = 0.0


class PerformanceMonitor:
    """Advanced performance monitoring and analytics."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("credfinder.performance_monitor")
        
        # Performance tracking
        self.scan_start_time = None
        self.scan_end_time = None
        self.module_metrics: Dict[str, ModuleMetrics] = {}
        self.system_metrics = {
            "peak_memory_mb": 0.0,
            "peak_cpu_percent": 0.0,
            "total_files_processed": 0,
            "total_cache_hits": 0,
            "total_cache_misses": 0,
            "coordination_overhead_ms": 0.0,
            "deduplication_time_ms": 0.0
        }
        
        # Performance thresholds
        self.performance_thresholds = {
            "slow_module_threshold_s": 60.0,
            "high_memory_threshold_mb": 500.0,
            "high_cpu_threshold_percent": 80.0,
            "low_cache_hit_rate_percent": 20.0
        }
        
        # Historical performance data
        self.historical_data = []
        self.load_historical_data()
        
    def start_scan_monitoring(self):
        """Start monitoring a scan execution."""
        self.scan_start_time = datetime.now()
        self.logger.info("Performance monitoring started")
        
    def end_scan_monitoring(self):
        """End monitoring and calculate final metrics."""
        self.scan_end_time = datetime.now()
        self.logger.info("Performance monitoring completed")
        
        # Calculate overall performance metrics
        self._calculate_performance_scores()
        self._save_historical_data()
        
    def start_module_monitoring(self, module_name: str) -> ModuleMetrics:
        """Start monitoring a specific module."""
        metrics = ModuleMetrics(
            module_name=module_name,
            start_time=datetime.now(),
            status="running"
        )
        self.module_metrics[module_name] = metrics
        return metrics
        
    def end_module_monitoring(self, module_name: str, findings_count: int = 0, 
                             files_processed: int = 0, error: Optional[str] = None):
        """End monitoring for a specific module."""
        if module_name not in self.module_metrics:
            return
            
        metrics = self.module_metrics[module_name]
        metrics.end_time = datetime.now()
        metrics.execution_time = (metrics.end_time - metrics.start_time).total_seconds()
        metrics.findings_count = findings_count
        metrics.files_processed = files_processed
        metrics.status = "failed" if error else "completed"
        metrics.error_message = error
        
        # Update system totals
        self.system_metrics["total_files_processed"] += files_processed
        
        self.logger.info(f"Module {module_name} monitoring complete: "
                        f"{metrics.execution_time:.2f}s, {findings_count} findings")
        
    def update_cache_metrics(self, module_name: str, cache_hits: int, cache_misses: int):
        """Update cache performance metrics for a module."""
        if module_name in self.module_metrics:
            self.module_metrics[module_name].cache_hits = cache_hits
            self.module_metrics[module_name].cache_misses = cache_misses
            
        self.system_metrics["total_cache_hits"] += cache_hits
        self.system_metrics["total_cache_misses"] += cache_misses
        
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        total_time = 0.0
        if self.scan_start_time and self.scan_end_time:
            total_time = (self.scan_end_time - self.scan_start_time).total_seconds()
            
        # Calculate cache hit rate
        total_cache_ops = self.system_metrics["total_cache_hits"] + self.system_metrics["total_cache_misses"]
        cache_hit_rate = 0.0
        if total_cache_ops > 0:
            cache_hit_rate = (self.system_metrics["total_cache_hits"] / total_cache_ops) * 100
            
        # Identify performance issues
        performance_issues = self._identify_performance_issues()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        return {
            "scan_overview": {
                "total_execution_time_s": total_time,
                "modules_executed": len(self.module_metrics),
                "total_findings": sum(m.findings_count for m in self.module_metrics.values()),
                "total_files_processed": self.system_metrics["total_files_processed"],
                "cache_hit_rate_percent": round(cache_hit_rate, 2)
            },
            "module_performance": {
                name: {
                    "execution_time_s": metrics.execution_time,
                    "findings_count": metrics.findings_count,
                    "files_processed": metrics.files_processed,
                    "cache_hit_rate_percent": round(
                        (metrics.cache_hits / (metrics.cache_hits + metrics.cache_misses)) * 100
                        if (metrics.cache_hits + metrics.cache_misses) > 0 else 0.0, 2
                    ),
                    "performance_score": metrics.performance_score,
                    "status": metrics.status
                }
                for name, metrics in self.module_metrics.items()
            },
            "system_metrics": self.system_metrics,
            "performance_issues": performance_issues,
            "recommendations": recommendations,
            "historical_comparison": self._compare_with_historical_data()
        }
        
    def _calculate_performance_scores(self):
        """Calculate performance scores for each module."""
        for metrics in self.module_metrics.values():
            score = 100.0
            
            # Time penalty (slower = lower score)
            if metrics.execution_time > 30:
                score -= min(30, metrics.execution_time - 30)
                
            # Cache hit rate bonus
            cache_ops = metrics.cache_hits + metrics.cache_misses
            if cache_ops > 0:
                hit_rate = metrics.cache_hits / cache_ops
                score += hit_rate * 20  # Up to 20 bonus points
                
            # Findings efficiency bonus
            if metrics.files_processed > 0:
                efficiency = metrics.findings_count / metrics.files_processed
                score += min(10, efficiency * 100)  # Up to 10 bonus points
                
            metrics.performance_score = max(0, min(100, score))
            
    def _identify_performance_issues(self) -> List[Dict[str, Any]]:
        """Identify performance issues and bottlenecks."""
        issues = []
        
        # Slow modules
        for name, metrics in self.module_metrics.items():
            if metrics.execution_time > self.performance_thresholds["slow_module_threshold_s"]:
                issues.append({
                    "type": "slow_module",
                    "module": name,
                    "execution_time": metrics.execution_time,
                    "severity": "high" if metrics.execution_time > 120 else "medium"
                })
                
        # Low cache hit rate
        total_cache_ops = self.system_metrics["total_cache_hits"] + self.system_metrics["total_cache_misses"]
        if total_cache_ops > 0:
            hit_rate = (self.system_metrics["total_cache_hits"] / total_cache_ops) * 100
            if hit_rate < self.performance_thresholds["low_cache_hit_rate_percent"]:
                issues.append({
                    "type": "low_cache_efficiency",
                    "hit_rate_percent": round(hit_rate, 2),
                    "severity": "medium"
                })
                
        return issues
        
    def _generate_recommendations(self) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []
        
        # Analyze module performance
        slow_modules = [name for name, metrics in self.module_metrics.items() 
                       if metrics.execution_time > 60]
        if slow_modules:
            recommendations.append(f"Consider optimizing slow modules: {', '.join(slow_modules)}")
            
        # Cache efficiency
        total_cache_ops = self.system_metrics["total_cache_hits"] + self.system_metrics["total_cache_misses"]
        if total_cache_ops > 0:
            hit_rate = (self.system_metrics["total_cache_hits"] / total_cache_ops) * 100
            if hit_rate < 50:
                recommendations.append("Consider increasing cache size or optimizing cache key strategies")
                
        # Parallel execution optimization
        if len(self.module_metrics) > 1:
            avg_time = sum(m.execution_time for m in self.module_metrics.values()) / len(self.module_metrics)
            max_time = max(m.execution_time for m in self.module_metrics.values())
            if max_time > avg_time * 2:
                recommendations.append("Consider rebalancing parallel execution groups")
                
        return recommendations
        
    def load_historical_data(self):
        """Load historical performance data."""
        try:
            history_file = os.path.join(self.config.get("output", {}).get("output_dir", "./reports"), 
                                      "performance_history.json")
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    self.historical_data = json.load(f)
                    # Keep only last 30 entries
                    self.historical_data = self.historical_data[-30:]
        except Exception as e:
            self.logger.warning(f"Could not load historical performance data: {e}")
            
    def _save_historical_data(self):
        """Save current performance data to history."""
        try:
            history_file = os.path.join(self.config.get("output", {}).get("output_dir", "./reports"), 
                                      "performance_history.json")
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(history_file), exist_ok=True)
            
            current_data = {
                "timestamp": datetime.now().isoformat(),
                "total_time": (self.scan_end_time - self.scan_start_time).total_seconds() if self.scan_end_time else 0,
                "modules_count": len(self.module_metrics),
                "total_findings": sum(m.findings_count for m in self.module_metrics.values()),
                "cache_hit_rate": (self.system_metrics["total_cache_hits"] / 
                                 (self.system_metrics["total_cache_hits"] + self.system_metrics["total_cache_misses"]) * 100)
                                if (self.system_metrics["total_cache_hits"] + self.system_metrics["total_cache_misses"]) > 0 else 0
            }
            
            self.historical_data.append(current_data)
            
            with open(history_file, 'w') as f:
                json.dump(self.historical_data, f, indent=2)
                
        except Exception as e:
            self.logger.warning(f"Could not save historical performance data: {e}")
            
    def _compare_with_historical_data(self) -> Dict[str, Any]:
        """Compare current performance with historical data."""
        if not self.historical_data:
            return {"status": "no_historical_data"}
            
        recent_data = self.historical_data[-5:]  # Last 5 runs
        if not recent_data:
            return {"status": "insufficient_data"}
            
        current_time = (self.scan_end_time - self.scan_start_time).total_seconds() if self.scan_end_time else 0
        avg_historical_time = sum(d["total_time"] for d in recent_data) / len(recent_data)
        
        performance_trend = "stable"
        if current_time > avg_historical_time * 1.2:
            performance_trend = "declining"
        elif current_time < avg_historical_time * 0.8:
            performance_trend = "improving"
            
        return {
            "status": "available",
            "current_time": current_time,
            "average_historical_time": avg_historical_time,
            "performance_trend": performance_trend,
            "time_difference_percent": round(((current_time - avg_historical_time) / avg_historical_time) * 100, 2)
        }


class ScanCoordinator:
    """Central coordinator for all scan operations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("credfinder.scan_coordinator")
        
        # Initialize components
        self.scan_cache = get_scan_cache(config)
        self.performance_monitor = PerformanceMonitor(config)
        self.result_deduplicator = ResultDeduplicator(config)
        self.smart_exclusions = SmartExclusions(config)
        
        # Coordination state
        self.active_modules: Dict[str, threading.Thread] = {}
        self.module_results: Dict[str, Any] = {}
        self.coordination_lock = threading.Lock()
        
        # Module dependencies and execution planning
        self.module_dependencies = self._load_module_dependencies()
        self.execution_strategies = self._load_execution_strategies()
        
        self.logger.info("ScanCoordinator initialized with advanced orchestration capabilities")
        
    def _load_module_dependencies(self) -> Dict[str, List[str]]:
        """Load module dependencies from configuration."""
        dependencies = self.config.get("module_coordination", {}).get("dependencies", {})
        
        # Default dependencies based on logical scan order
        default_dependencies = {
            "ssh": [],  # No dependencies, fast startup
            "dotfiles": [],  # No dependencies, fast startup
            "history": [],  # No dependencies, fast startup
            "git": ["dotfiles"],  # May benefit from dotfile cache
            "browser": ["dotfiles"],  # May benefit from config cache
            "keyring": ["dotfiles"],  # May benefit from config cache
            "file_grep": ["dotfiles", "git"]  # Benefits from exclusions learned by other modules
        }
        
        # Merge with configuration
        return {**default_dependencies, **dependencies}
        
    def _load_execution_strategies(self) -> Dict[str, Any]:
        """Load execution strategies from configuration."""
        return self.config.get("module_coordination", {}).get("execution_strategies", {
            "parallel_groups": [
                ["ssh", "dotfiles", "history"],  # Fast, independent modules
                ["git", "browser", "keyring"],   # Medium modules that can benefit from cache
                ["file_grep"]                    # Slowest, runs last to benefit from all optimizations
            ],
            "max_parallel_per_group": 3,
            "inter_group_delay_ms": 500,
            "resource_management": {
                "memory_limit_mb": 1000,
                "cpu_limit_percent": 80,
                "io_limit_mbps": 100
            }
        })
        
    def create_scan_plan(self, requested_modules: List[str]) -> ScanPlan:
        """Create an optimized scan execution plan."""
        self.logger.info(f"Creating scan plan for modules: {requested_modules}")
        
        # Filter requested modules based on availability and dependencies
        available_modules = set(requested_modules)
        
        # Resolve dependencies
        execution_order = self._resolve_dependencies(available_modules)
        
        # Create parallel execution groups
        parallel_groups = self._create_parallel_groups(execution_order)
        
        # Estimate execution time
        estimated_duration = self._estimate_execution_time(execution_order)
        
        # Calculate resource requirements
        resource_requirements = self._calculate_resource_requirements(execution_order)
        
        plan = ScanPlan(
            modules=list(available_modules),
            execution_order=execution_order,
            parallel_groups=parallel_groups,
            dependencies=self.module_dependencies,
            estimated_duration=estimated_duration,
            resource_requirements=resource_requirements
        )
        
        self.logger.info(f"Scan plan created: {len(plan.modules)} modules, "
                        f"estimated duration: {plan.estimated_duration:.1f}s, "
                        f"{len(plan.parallel_groups)} execution groups")
        
        return plan
        
    def _resolve_dependencies(self, requested_modules: set) -> List[str]:
        """Resolve module dependencies and create execution order."""
        resolved = []
        remaining = set(requested_modules)
        
        while remaining:
            # Find modules with no unresolved dependencies
            ready_modules = []
            for module in remaining:
                dependencies = self.module_dependencies.get(module, [])
                if all(dep in resolved or dep not in requested_modules for dep in dependencies):
                    ready_modules.append(module)
                    
            if not ready_modules:
                # Break circular dependencies by picking the first remaining module
                ready_modules = [next(iter(remaining))]
                self.logger.warning(f"Breaking potential circular dependency with module: {ready_modules[0]}")
                
            # Add ready modules to execution order
            resolved.extend(ready_modules)
            remaining -= set(ready_modules)
            
        return resolved
        
    def _create_parallel_groups(self, execution_order: List[str]) -> List[List[str]]:
        """Create optimized parallel execution groups."""
        parallel_groups = []
        
        # Use configured parallel groups as a template
        configured_groups = self.execution_strategies.get("parallel_groups", [])
        
        for group_template in configured_groups:
            group = [module for module in group_template if module in execution_order]
            if group:
                parallel_groups.append(group)
                
        # Add any remaining modules to their own groups
        all_grouped = set()
        for group in parallel_groups:
            all_grouped.update(group)
            
        remaining = [module for module in execution_order if module not in all_grouped]
        for module in remaining:
            parallel_groups.append([module])
            
        return parallel_groups
        
    def _estimate_execution_time(self, execution_order: List[str]) -> float:
        """Estimate total execution time based on historical data."""
        # Default execution time estimates (in seconds)
        default_times = {
            "ssh": 15,
            "dotfiles": 20,
            "history": 25,
            "git": 45,
            "browser": 60,
            "keyring": 40,
            "file_grep": 90
        }
        
        # Use historical data if available
        if self.performance_monitor.historical_data:
            # This is a simplified estimation - in practice, you'd want more sophisticated modeling
            recent_avg = sum(d["total_time"] for d in self.performance_monitor.historical_data[-3:]) / 3
            return recent_avg
            
        # Estimate based on parallel groups
        total_time = 0
        for group in self._create_parallel_groups(execution_order):
            group_time = max(default_times.get(module, 30) for module in group)
            total_time += group_time
            
        return total_time
        
    def _calculate_resource_requirements(self, execution_order: List[str]) -> Dict[str, Any]:
        """Calculate resource requirements for the scan plan."""
        # Default resource requirements per module
        default_resources = {
            "ssh": {"memory_mb": 20, "cpu_percent": 10, "io_intensive": False},
            "dotfiles": {"memory_mb": 30, "cpu_percent": 15, "io_intensive": True},
            "history": {"memory_mb": 25, "cpu_percent": 20, "io_intensive": True},
            "git": {"memory_mb": 50, "cpu_percent": 30, "io_intensive": True},
            "browser": {"memory_mb": 80, "cpu_percent": 25, "io_intensive": True},
            "keyring": {"memory_mb": 40, "cpu_percent": 20, "io_intensive": False},
            "file_grep": {"memory_mb": 60, "cpu_percent": 40, "io_intensive": True}
        }
        
        total_memory = sum(default_resources.get(module, {}).get("memory_mb", 30) for module in execution_order)
        max_cpu = max(default_resources.get(module, {}).get("cpu_percent", 20) for module in execution_order)
        io_intensive_count = sum(1 for module in execution_order 
                               if default_resources.get(module, {}).get("io_intensive", False))
        
        return {
            "estimated_memory_mb": total_memory,
            "estimated_cpu_percent": max_cpu,
            "io_intensive_modules": io_intensive_count,
            "parallel_safety_score": min(100, max(0, 100 - (io_intensive_count * 20)))
        }
        
    def execute_scan_plan(self, scan_plan: ScanPlan, module_runner) -> Dict[str, Any]:
        """Execute the scan plan with coordination and monitoring."""
        self.logger.info(f"Executing scan plan with {len(scan_plan.modules)} modules")
        
        # Start performance monitoring
        self.performance_monitor.start_scan_monitoring()
        
        try:
            # Execute modules according to plan
            all_results = {}
            
            for group_index, module_group in enumerate(scan_plan.parallel_groups):
                self.logger.info(f"Executing group {group_index + 1}/{len(scan_plan.parallel_groups)}: {module_group}")
                
                # Execute group in parallel
                group_results = self._execute_module_group(module_group, module_runner)
                all_results.update(group_results)
                
                # Inter-group delay for resource management
                if group_index < len(scan_plan.parallel_groups) - 1:
                    delay_ms = self.execution_strategies.get("inter_group_delay_ms", 500)
                    time.sleep(delay_ms / 1000.0)
                    
            # Apply post-processing
            processed_results = self._post_process_results(all_results)
            
            # End performance monitoring
            self.performance_monitor.end_scan_monitoring()
            
            return processed_results
            
        except Exception as e:
            self.logger.error(f"Scan plan execution failed: {e}")
            self.performance_monitor.end_scan_monitoring()
            raise
            
    def _execute_module_group(self, module_group: List[str], module_runner) -> Dict[str, Any]:
        """Execute a group of modules in parallel with coordination."""
        if len(module_group) == 1:
            # Single module execution
            return self._execute_single_module(module_group[0], module_runner)
        else:
            # Parallel execution
            return self._execute_parallel_modules(module_group, module_runner)
            
    def _execute_single_module(self, module_name: str, module_runner) -> Dict[str, Any]:
        """Execute a single module with monitoring."""
        metrics = self.performance_monitor.start_module_monitoring(module_name)
        
        try:
            # Execute module
            result = module_runner.run_module_safe(module_name)
            
            # Update metrics
            findings_count = self._count_findings(result.data) if result.status == 'success' else 0
            self.performance_monitor.end_module_monitoring(
                module_name, findings_count, 0, result.error
            )
            
            return {module_name: result}
            
        except Exception as e:
            self.performance_monitor.end_module_monitoring(module_name, 0, 0, str(e))
            raise
            
    def _execute_parallel_modules(self, module_group: List[str], module_runner) -> Dict[str, Any]:
        """Execute multiple modules in parallel with coordination."""
        import concurrent.futures
        
        results = {}
        max_workers = min(len(module_group), self.execution_strategies.get("max_parallel_per_group", 3))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Start all modules
            future_to_module = {}
            for module_name in module_group:
                metrics = self.performance_monitor.start_module_monitoring(module_name)
                future = executor.submit(module_runner.run_module_safe, module_name)
                future_to_module[future] = module_name
                
            # Collect results
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    result = future.result()
                    results[module_name] = result
                    
                    # Update metrics
                    findings_count = self._count_findings(result.data) if result.status == 'success' else 0
                    self.performance_monitor.end_module_monitoring(
                        module_name, findings_count, 0, result.error
                    )
                    
                except Exception as e:
                    self.performance_monitor.end_module_monitoring(module_name, 0, 0, str(e))
                    results[module_name] = type('ModuleResult', (), {
                        'status': 'failed', 
                        'error': str(e), 
                        'data': {}
                    })()
                    
        return results
        
    def _post_process_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Apply post-processing to scan results."""
        self.logger.info("Applying post-processing to scan results")
        
        # Extract successful results
        processed_results = {}
        for module_name, result in results.items():
            if hasattr(result, 'status') and result.status == 'success':
                processed_results[module_name] = result.data
            else:
                processed_results[module_name] = {
                    '_status': 'failed',
                    '_error': getattr(result, 'error', 'Unknown error')
                }
                
        # Apply deduplication
        deduplication_config = self.config.get("module_coordination", {}).get("deduplication", {})
        if deduplication_config.get("enabled", True):
            self.logger.info("Applying coordinated result deduplication")
            processed_results = self.result_deduplicator.deduplicate_all_findings(processed_results)
            
        return processed_results
        
    def _count_findings(self, result) -> int:
        """Count findings in module result."""
        try:
            if isinstance(result, list):
                return len(result)
            elif isinstance(result, dict):
                count = 0
                for key, value in result.items():
                    if key.startswith('_') or key in ['scan_stats', 'metadata']:
                        continue
                    if isinstance(value, list):
                        count += len(value)
                    elif isinstance(value, dict) and 'items' in value:
                        count += len(value['items'])
                return count
            else:
                return 1 if result else 0
        except Exception:
            return 0
            
    def get_coordination_statistics(self) -> Dict[str, Any]:
        """Get comprehensive coordination and performance statistics."""
        stats = {
            "coordination_overview": {
                "modules_coordinated": len(self.performance_monitor.module_metrics),
                "active_modules": len(self.active_modules),
                "cache_enabled": self.scan_cache is not None,
                "deduplication_enabled": self.config.get("module_coordination", {}).get("deduplication", {}).get("enabled", True),
                "smart_exclusions_enabled": self.config.get("smart_exclusions", {}).get("enabled", True)
            },
            "performance_monitoring": self.performance_monitor.get_performance_report(),
            "cache_statistics": self.scan_cache.get_cache_statistics() if self.scan_cache else {},
            "deduplication_statistics": self.result_deduplicator.get_deduplication_statistics(),
            "exclusion_statistics": self.smart_exclusions.get_exclusion_statistics()
        }
        
        return stats
        
    def cleanup(self):
        """Clean up coordinator resources."""
        self.logger.info("Cleaning up ScanCoordinator resources")
        
        if self.scan_cache:
            self.scan_cache.cleanup_cache()
            
        # Clear active modules
        self.active_modules.clear()
        self.module_results.clear()


# Global coordinator instance
_scan_coordinator = None
_coordinator_lock = threading.Lock()


def get_scan_coordinator(config: Dict[str, Any]) -> ScanCoordinator:
    """Get or create the global scan coordinator instance."""
    global _scan_coordinator
    
    with _coordinator_lock:
        if _scan_coordinator is None:
            _scan_coordinator = ScanCoordinator(config)
        return _scan_coordinator


def reset_scan_coordinator():
    """Reset the global scan coordinator instance."""
    global _scan_coordinator
    
    with _coordinator_lock:
        if _scan_coordinator:
            _scan_coordinator.cleanup()
        _scan_coordinator = None 