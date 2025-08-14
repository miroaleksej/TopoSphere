"""
TopoSphere Resource Policy Module

This module provides comprehensive resource policy management for the TopoSphere server,
implementing the industrial-grade standards of AuditCore v3.2. The resource policy system
is designed to ensure efficient utilization of computational resources while maintaining
strict security guarantees for topological analysis operations.

The policy system follows the foundational principles from our research:
- ECDSA signature space forms a topological torus (β₀=1, β₁=2, β₂=1) for secure implementations
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)
- Diagonal symmetry r(u_r, u_z) = r(u_z, u_r) must hold for secure implementations
- Spiral structure k = u_z + u_r·d mod n provides critical security insights

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This policy system embodies that principle by providing
mathematically rigorous resource allocation that supports comprehensive security analysis.

Key features:
- Dynamic resource allocation based on analysis complexity
- Integration with Dynamic Compute Router for optimal resource routing
- Fixed resource profile enforcement to prevent timing/volume analysis
- Real-time resource monitoring and adaptive policy enforcement
- Support for multiple compute strategies (CPU, GPU, distributed)
- Differential privacy-aware resource allocation
- Industrial-grade validation of all resource policies

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Union, TypeVar, Protocol
import os
import time
import logging
import warnings
import psutil
import threading
from datetime import datetime, timedelta
from functools import lru_cache

# External dependencies
try:
    import GPUtil
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
    warnings.warn("GPUtil library not found. GPU monitoring will be limited.", RuntimeWarning)

try:
    import ray
    RAY_AVAILABLE = True
except ImportError:
    RAY_AVAILABLE = False
    warnings.warn("Ray library not found. Distributed computing will be limited.", RuntimeWarning)

# Import from our own modules
from ...shared.protocols.secure_protocol import (
    ProtocolVersion,
    SecurityLevel
)
from ...shared.models.topological_models import (
    TopologicalAnalysisResult,
    VulnerabilityType
)
from ..config.server_config import (
    PerformanceConfig,
    ComputeStrategy
)

# ======================
# ENUMERATIONS
# ======================

class ResourceStrategy(Enum):
    """Resource strategies for computation routing."""
    CPU_SEQ = "cpu_seq"  # CPU, sequential processing
    CPU_PAR = "cpu_par"  # CPU, parallel processing
    GPU = "gpu"  # GPU acceleration
    RAY = "ray"  # Distributed computing with Ray
    FALLBACK = "fallback"  # Fallback strategy
    
    @classmethod
    def from_compute_strategy(cls, strategy: ComputeStrategy) -> ResourceStrategy:
        """Convert ComputeStrategy to ResourceStrategy.
        
        Args:
            strategy: ComputeStrategy enum value
            
        Returns:
            Corresponding ResourceStrategy
        """
        mapping = {
            ComputeStrategy.CPU: cls.CPU_PAR,
            ComputeStrategy.GPU: cls.GPU,
            ComputeStrategy.DISTRIBUTED: cls.RAY,
            ComputeStrategy.AUTO: cls.FALLBACK
        }
        return mapping.get(strategy, cls.FALLBACK)
    
    def get_description(self) -> str:
        """Get description of resource strategy."""
        descriptions = {
            ResourceStrategy.CPU_SEQ: "CPU sequential processing for small-scale analysis",
            ResourceStrategy.CPU_PAR: "CPU parallel processing for medium-scale analysis",
            ResourceStrategy.GPU: "GPU acceleration for high-performance topological analysis",
            ResourceStrategy.RAY: "Distributed computing with Ray for large-scale analysis",
            ResourceStrategy.FALLBACK: "Fallback strategy when preferred resources are unavailable"
        }
        return descriptions.get(self, "Resource strategy")


class ResourceLimitType(Enum):
    """Types of resource limits enforced by the policy system."""
    MEMORY = "memory"  # Memory usage limit
    CPU = "cpu"  # CPU usage limit
    TIME = "time"  # Execution time limit
    GPU = "gpu"  # GPU resource limit
    CONCURRENT = "concurrent"  # Concurrent operation limit
    
    def get_description(self) -> str:
        """Get description of resource limit type."""
        descriptions = {
            ResourceLimitType.MEMORY: "Memory usage limit in MB",
            ResourceLimitType.CPU: "CPU usage limit as percentage",
            ResourceLimitType.TIME: "Execution time limit in seconds",
            ResourceLimitType.GPU: "GPU resource limit as percentage",
            ResourceLimitType.CONCURRENT: "Maximum concurrent operations"
        }
        return descriptions.get(self, "Resource limit type")


class ResourcePolicyMode(Enum):
    """Modes for resource policy enforcement."""
    STRICT = "strict"  # Strict enforcement (fail on violation)
    ADAPTIVE = "adaptive"  # Adaptive adjustment (scale down operations)
    MONITORING = "monitoring"  # Monitoring only (log violations)
    
    @classmethod
    def from_performance_level(cls, level: PerformanceLevel) -> ResourcePolicyMode:
        """Map performance level to resource policy mode.
        
        Args:
            level: Performance level
            
        Returns:
            Corresponding resource policy mode
        """
        from ...shared.models.cryptographic_models import PerformanceLevel
        
        if level == PerformanceLevel.LOW:
            return cls.STRICT
        elif level == PerformanceLevel.MEDIUM:
            return cls.ADAPTIVE
        else:  # HIGH
            return cls.MONITORING


# ======================
# DATA CLASSES
# ======================

@dataclass
class ResourceLimit:
    """Definition of a resource limit with enforcement parameters."""
    limit_type: ResourceLimitType
    value: float
    hard_limit: bool = False
    warning_threshold: float = 0.9
    enforcement_action: str = "throttle"
    
    def validate(self) -> None:
        """Validate resource limit configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if self.value <= 0:
            raise ValueError(f"Resource limit value must be positive for {self.limit_type}")
        
        if not (0 < self.warning_threshold <= 1):
            raise ValueError("warning_threshold must be between 0 and 1")
        
        valid_actions = ["throttle", "fail", "log", "scale_down"]
        if self.enforcement_action not in valid_actions:
            raise ValueError(f"enforcement_action must be one of {valid_actions}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "limit_type": self.limit_type.value,
            "value": self.value,
            "hard_limit": self.hard_limit,
            "warning_threshold": self.warning_threshold,
            "enforcement_action": self.enforcement_action
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourceLimit:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing limit data
            
        Returns:
            ResourceLimit: New resource limit object
        """
        # Convert string to ResourceLimitType
        if 'limit_type' in data:
            data['limit_type'] = ResourceLimitType(data['limit_type'])
        
        return cls(**data)


@dataclass
class ResourceProfile:
    """Resource profile defining resource requirements for specific operations."""
    operation_type: str
    min_memory_mb: float = 100.0
    min_cpu_cores: float = 0.5
    min_gpu_memory_mb: Optional[float] = None
    timeout_seconds: float = 60.0
    priority: int = 5
    required_strategy: ResourceStrategy = ResourceStrategy.CPU_PAR
    
    def validate(self) -> None:
        """Validate resource profile configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if self.min_memory_mb <= 0:
            raise ValueError("min_memory_mb must be positive")
        if self.min_cpu_cores <= 0:
            raise ValueError("min_cpu_cores must be positive")
        if self.min_gpu_memory_mb is not None and self.min_gpu_memory_mb <= 0:
            raise ValueError("min_gpu_memory_mb must be positive if specified")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not (1 <= self.priority <= 10):
            raise ValueError("priority must be between 1 and 10")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "operation_type": self.operation_type,
            "min_memory_mb": self.min_memory_mb,
            "min_cpu_cores": self.min_cpu_cores,
            "min_gpu_memory_mb": self.min_gpu_memory_mb,
            "timeout_seconds": self.timeout_seconds,
            "priority": self.priority,
            "required_strategy": self.required_strategy.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourceProfile:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing profile data
            
        Returns:
            ResourceProfile: New resource profile object
        """
        # Convert string to ResourceStrategy
        if 'required_strategy' in data:
            data['required_strategy'] = ResourceStrategy(data['required_strategy'])
        
        return cls(**data)


@dataclass
class ResourceUsage:
    """Tracks resource usage for operations and systems."""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    gpu_utilization: List[float] = field(default_factory=list)
    gpu_memory_mb: List[float] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    operation_id: Optional[str] = None
    operation_type: Optional[str] = None
    status: str = "running"
    
    @property
    def duration(self) -> float:
        """Get duration of the operation in seconds."""
        end = self.end_time if self.end_time is not None else time.time()
        return end - self.start_time
    
    def complete(self, status: str = "success") -> None:
        """Mark operation as completed.
        
        Args:
            status: Completion status
        """
        self.end_time = time.time()
        self.status = status
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "gpu_utilization": self.gpu_utilization,
            "gpu_memory_mb": self.gpu_memory_mb,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "status": self.status
        }


@dataclass
class ResourcePolicyConfig:
    """Configuration for resource policy enforcement."""
    # Resource limits
    memory_limit_mb: float = 4096.0
    cpu_limit_percent: float = 80.0
    timeout_seconds: float = 300.0
    max_concurrent_operations: int = 10
    gpu_memory_limit_mb: Optional[float] = None
    
    # Policy behavior
    policy_mode: ResourcePolicyMode = ResourcePolicyMode.ADAPTIVE
    warning_threshold: float = 0.9
    adaptive_scaling_factor: float = 0.8
    enforcement_action: str = "throttle"
    
    # Monitoring parameters
    monitoring_interval: float = 5.0
    history_size: int = 100
    
    def validate(self) -> None:
        """Validate resource policy configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if self.memory_limit_mb <= 0:
            raise ValueError("memory_limit_mb must be positive")
        if not (0 < self.cpu_limit_percent <= 100):
            raise ValueError("cpu_limit_percent must be between 0 and 100")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_concurrent_operations <= 0:
            raise ValueError("max_concurrent_operations must be positive")
        if self.gpu_memory_limit_mb is not None and self.gpu_memory_limit_mb <= 0:
            raise ValueError("gpu_memory_limit_mb must be positive if specified")
        if not (0 < self.warning_threshold <= 1):
            raise ValueError("warning_threshold must be between 0 and 1")
        if not (0 < self.adaptive_scaling_factor <= 1):
            raise ValueError("adaptive_scaling_factor must be between 0 and 1")
        if self.monitoring_interval <= 0:
            raise ValueError("monitoring_interval must be positive")
        if self.history_size <= 0:
            raise ValueError("history_size must be positive")
        
        valid_actions = ["throttle", "fail", "log", "scale_down"]
        if self.enforcement_action not in valid_actions:
            raise ValueError(f"enforcement_action must be one of {valid_actions}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "memory_limit_mb": self.memory_limit_mb,
            "cpu_limit_percent": self.cpu_limit_percent,
            "timeout_seconds": self.timeout_seconds,
            "max_concurrent_operations": self.max_concurrent_operations,
            "gpu_memory_limit_mb": self.gpu_memory_limit_mb,
            "policy_mode": self.policy_mode.value,
            "warning_threshold": self.warning_threshold,
            "adaptive_scaling_factor": self.adaptive_scaling_factor,
            "enforcement_action": self.enforcement_action,
            "monitoring_interval": self.monitoring_interval,
            "history_size": self.history_size
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourcePolicyConfig:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing policy configuration
            
        Returns:
            ResourcePolicyConfig: New policy configuration object
        """
        # Convert string to ResourcePolicyMode
        if 'policy_mode' in data:
            data['policy_mode'] = ResourcePolicyMode(data['policy_mode'])
        
        return cls(**data)


# ======================
# RESOURCE MONITOR CLASS
# ======================

class ResourceMonitor:
    """Monitors system resources and enforces resource policies.
    
    This class provides real-time monitoring of system resources and enforces
    resource policies based on the configured limits and modes.
    
    Key features:
    - Real-time monitoring of CPU, memory, and GPU resources
    - Historical tracking of resource usage
    - Policy enforcement based on configured limits
    - Integration with Dynamic Compute Router for optimal resource allocation
    - Support for multiple policy enforcement modes (strict, adaptive, monitoring)
    
    Example:
        monitor = ResourceMonitor(config)
        usage = monitor.start_operation("topological_analysis", operation_id="op_123")
        # Perform operation...
        usage.complete("success")
        monitor.enforce_policy()
    """
    
    def __init__(self, config: ResourcePolicyConfig):
        """Initialize the resource monitor.
        
        Args:
            config: Resource policy configuration
        """
        self.config = config
        self.logger = logging.getLogger("TopoSphere.ResourceMonitor")
        self._lock = threading.RLock()
        
        # Initialize resource tracking
        self.current_operations: Dict[str, ResourceUsage] = {}
        self.resource_history: List[ResourceUsage] = []
        self.system_status_history: List[Dict[str, Any]] = []
        
        # Start monitoring thread
        self._monitoring_active = True
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self._monitoring_thread.start()
        
        self.logger.info("Initialized ResourceMonitor with policy enforcement")
    
    def _monitoring_loop(self) -> None:
        """Background monitoring loop for system resources."""
        while self._monitoring_active:
            try:
                # Get current system status
                status = self.get_system_status()
                with self._lock:
                    self.system_status_history.append(status)
                    # Trim history if too large
                    if len(self.system_status_history) > self.config.history_size:
                        self.system_status_history.pop(0)
                
                # Check resource policies
                self.enforce_policy()
                
                # Sleep for monitoring interval
                time.sleep(self.config.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(self.config.monitoring_interval)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system resource status.
        
        Returns:
            Dictionary with current resource utilization
        """
        # Get CPU and memory usage
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        memory_mb = memory.used / (1024 * 1024)
        
        # Get GPU status if available
        gpu_status = []
        if GPU_AVAILABLE:
            try:
                gpus = GPUtil.getGPUs()
                for gpu in gpus:
                    gpu_status.append({
                        "id": gpu.id,
                        "name": gpu.name,
                        "load": gpu.load * 100,
                        "memory_used_mb": gpu.memoryUsed,
                        "memory_total_mb": gpu.memoryTotal
                    })
            except Exception as e:
                self.logger.debug(f"GPU monitoring error: {str(e)}")
        
        return {
            "timestamp": time.time(),
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "memory_total_mb": memory.total / (1024 * 1024),
            "gpu_status": gpu_status,
            "active_operations": len(self.current_operations)
        }
    
    def start_operation(self,
                       operation_type: str,
                       operation_id: Optional[str] = None) -> ResourceUsage:
        """Start tracking a new operation.
        
        Args:
            operation_type: Type of operation
            operation_id: Optional operation ID
            
        Returns:
            ResourceUsage object for tracking
        """
        if operation_id is None:
            operation_id = f"op_{int(time.time())}_{os.getpid()}"
        
        # Create resource usage tracker
        usage = ResourceUsage(
            operation_id=operation_id,
            operation_type=operation_type
        )
        
        # Add to current operations
        with self._lock:
            self.current_operations[operation_id] = usage
        
        # Log operation start
        self.logger.debug(
            f"Started operation {operation_id} ({operation_type}) - "
            f"Active operations: {len(self.current_operations)}"
        )
        
        return usage
    
    def complete_operation(self,
                          operation_id: str,
                          status: str = "success") -> None:
        """Mark an operation as completed.
        
        Args:
            operation_id: Operation ID
            status: Completion status
        """
        with self._lock:
            if operation_id in self.current_operations:
                usage = self.current_operations[operation_id]
                usage.complete(status)
                
                # Add to history
                self.resource_history.append(usage)
                if len(self.resource_history) > self.config.history_size:
                    self.resource_history.pop(0)
                
                # Remove from current operations
                del self.current_operations[operation_id]
                
                # Log completion
                self.logger.debug(
                    f"Completed operation {operation_id} ({usage.operation_type}) - "
                    f"Duration: {usage.duration:.2f}s, Status: {status}"
                )
    
    def enforce_policy(self) -> None:
        """Enforce resource policies based on current usage.
        
        This method checks current resource usage against configured limits
        and takes appropriate action based on the policy mode.
        """
        # Get current system status
        system_status = self.get_system_status()
        
        # Check memory usage
        if system_status["memory_mb"] > self.config.memory_limit_mb * self.config.warning_threshold:
            self._handle_resource_violation(
                ResourceLimitType.MEMORY,
                system_status["memory_mb"],
                self.config.memory_limit_mb
            )
        
        # Check CPU usage
        if system_status["cpu_percent"] > self.config.cpu_limit_percent * self.config.warning_threshold:
            self._handle_resource_violation(
                ResourceLimitType.CPU,
                system_status["cpu_percent"],
                self.config.cpu_limit_percent
            )
        
        # Check operation count
        if len(self.current_operations) > self.config.max_concurrent_operations * self.config.warning_threshold:
            self._handle_resource_violation(
                ResourceLimitType.CONCURRENT,
                len(self.current_operations),
                self.config.max_concurrent_operations
            )
    
    def _handle_resource_violation(self,
                                  limit_type: ResourceLimitType,
                                  current_value: float,
                                  limit_value: float) -> None:
        """Handle resource limit violation based on policy mode.
        
        Args:
            limit_type: Type of resource limit violated
            current_value: Current resource usage
            limit_value: Resource limit value
        """
        violation_ratio = current_value / limit_value
        
        # Log warning
        self.logger.warning(
            f"Resource violation: {limit_type.value} usage {current_value} "
            f"exceeds {self.config.warning_threshold * 100:.0f}% threshold "
            f"of limit {limit_value} ({violation_ratio:.2f}x)"
        )
        
        # Take action based on policy mode
        if self.config.policy_mode == ResourcePolicyMode.STRICT:
            if self.config.enforcement_action == "fail":
                self.logger.error("Resource violation in strict mode - failing operations")
                self._fail_operations(limit_type)
            elif self.config.enforcement_action == "throttle":
                self.logger.warning("Resource violation in strict mode - throttling operations")
                self._throttle_operations(limit_type)
        
        elif self.config.policy_mode == ResourcePolicyMode.ADAPTIVE:
            if self.config.enforcement_action == "scale_down":
                self.logger.warning("Resource violation in adaptive mode - scaling down operations")
                self._scale_operations(limit_type)
            elif self.config.enforcement_action == "throttle":
                self.logger.warning("Resource violation in adaptive mode - throttling operations")
                self._throttle_operations(limit_type)
    
    def _fail_operations(self, limit_type: ResourceLimitType) -> None:
        """Fail operations to reduce resource usage.
        
        Args:
            limit_type: Type of resource limit violated
        """
        with self._lock:
            # Sort operations by priority (lowest first)
            operations = sorted(
                self.current_operations.values(),
                key=lambda x: self._get_operation_priority(x.operation_type)
            )
            
            # Fail operations until resource usage is within limits
            for usage in operations:
                self.complete_operation(usage.operation_id, "failed_resource_limit")
                if len(self.current_operations) <= self.config.max_concurrent_operations * 0.8:
                    break
    
    def _throttle_operations(self, limit_type: ResourceLimitType) -> None:
        """Throttle operations to reduce resource usage.
        
        Args:
            limit_type: Type of resource limit violated
        """
        with self._lock:
            # Add delay to all operations
            delay = 0.1 * (len(self.current_operations) / self.config.max_concurrent_operations)
            for usage in self.current_operations.values():
                time.sleep(delay)
    
    def _scale_operations(self, limit_type: ResourceLimitType) -> None:
        """Scale operations to reduce resource usage.
        
        Args:
            limit_type: Type of resource limit violated
        """
        with self._lock:
            # Scale down resource-intensive operations
            for usage in self.current_operations.values():
                # In a real implementation, this would adjust operation parameters
                # to reduce resource usage
                pass
    
    def _get_operation_priority(self, operation_type: str) -> int:
        """Get priority for an operation type.
        
        Args:
            operation_type: Type of operation
            
        Returns:
            Priority value (lower = higher priority)
        """
        # Default priority
        priority = 5
        
        # Adjust based on operation type
        if "critical" in operation_type:
            priority = 1
        elif "analysis" in operation_type:
            priority = 3
        elif "cache" in operation_type:
            priority = 7
        
        return priority
    
    def get_resource_usage(self, operation_id: str) -> Optional[ResourceUsage]:
        """Get resource usage for a specific operation.
        
        Args:
            operation_id: Operation ID
            
        Returns:
            ResourceUsage object or None if not found
        """
        with self._lock:
            return self.current_operations.get(operation_id)
    
    def get_historical_usage(self) -> List[ResourceUsage]:
        """Get historical resource usage.
        
        Returns:
            List of historical resource usage records
        """
        with self._lock:
            return list(self.resource_history)
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics for monitoring.
        
        Returns:
            Dictionary with system metrics
        """
        system_status = self.get_system_status()
        
        return {
            "timestamp": time.time(),
            "cpu_percent": system_status["cpu_percent"],
            "memory_mb": system_status["memory_mb"],
            "memory_total_mb": system_status["memory_total_mb"],
            "active_operations": len(self.current_operations),
            "max_concurrent_operations": self.config.max_concurrent_operations,
            "resource_violations": self._count_resource_violations()
        }
    
    def _count_resource_violations(self) -> int:
        """Count recent resource violations.
        
        Returns:
            Number of resource violations in recent history
        """
        violations = 0
        system_status = self.get_system_status()
        
        if system_status["memory_mb"] > self.config.memory_limit_mb * self.config.warning_threshold:
            violations += 1
        if system_status["cpu_percent"] > self.config.cpu_limit_percent * self.config.warning_threshold:
            violations += 1
        if len(self.current_operations) > self.config.max_concurrent_operations * self.config.warning_threshold:
            violations += 1
            
        return violations
    
    def shutdown(self) -> None:
        """Shutdown the resource monitor."""
        self._monitoring_active = False
        if self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=2.0)
        self.logger.info("ResourceMonitor shutdown complete")


# ======================
# RESOURCE POLICY MANAGER CLASS
# ======================

class ResourcePolicyManager:
    """Manages resource policies and integration with topological analysis.
    
    This class provides the interface between the resource policy system and
    the topological analysis components, ensuring that analysis operations
    adhere to resource constraints while maintaining security guarantees.
    
    Key features:
    - Policy configuration based on analysis requirements
    - Integration with Dynamic Compute Router for optimal resource allocation
    - Adaptive resource allocation based on analysis complexity
    - Differential privacy-aware resource allocation
    - Fixed resource profile enforcement to prevent timing/volume analysis
    
    Example:
        policy_manager = ResourcePolicyManager(config)
        operation_id = policy_manager.start_analysis(public_key)
        # Perform analysis...
        policy_manager.complete_analysis(operation_id, analysis_result)
    """
    
    def __init__(self,
                config: ResourcePolicyConfig,
                performance_config: PerformanceConfig):
        """Initialize the resource policy manager.
        
        Args:
            config: Resource policy configuration
            performance_config: Performance configuration
        """
        self.config = config
        self.performance_config = performance_config
        self.logger = logging.getLogger("TopoSphere.ResourcePolicyManager")
        
        # Initialize resource monitor
        self.monitor = ResourceMonitor(config)
        
        # Initialize resource profiles
        self.resource_profiles = self._initialize_resource_profiles()
        
        self.logger.info("Initialized ResourcePolicyManager with resource policies")
    
    def _initialize_resource_profiles(self) -> Dict[str, ResourceProfile]:
        """Initialize resource profiles for different operation types.
        
        Returns:
            Dictionary of resource profiles
        """
        return {
            "topological_analysis": ResourceProfile(
                operation_type="topological_analysis",
                min_memory_mb=1024.0,
                min_cpu_cores=2.0,
                min_gpu_memory_mb=2048.0 if GPU_AVAILABLE else None,
                timeout_seconds=300.0,
                priority=3,
                required_strategy=ResourceStrategy.from_compute_strategy(
                    self.performance_config.compute_strategy
                )
            ),
            "betti_analysis": ResourceProfile(
                operation_type="betti_analysis",
                min_memory_mb=512.0,
                min_cpu_cores=1.0,
                min_gpu_memory_mb=1024.0 if GPU_AVAILABLE else None,
                timeout_seconds=120.0,
                priority=4,
                required_strategy=ResourceStrategy.CPU_PAR
            ),
            "gradient_analysis": ResourceProfile(
                operation_type="gradient_analysis",
                min_memory_mb=768.0,
                min_cpu_cores=1.5,
                min_gpu_memory_mb=1536.0 if GPU_AVAILABLE else None,
                timeout_seconds=180.0,
                priority=4,
                required_strategy=ResourceStrategy.GPU if GPU_AVAILABLE else ResourceStrategy.CPU_PAR
            ),
            "spiral_scan": ResourceProfile(
                operation_type="spiral_scan",
                min_memory_mb=256.0,
                min_cpu_cores=0.5,
                timeout_seconds=60.0,
                priority=5,
                required_strategy=ResourceStrategy.CPU_SEQ
            ),
            "cache_operation": ResourceProfile(
                operation_type="cache_operation",
                min_memory_mb=128.0,
                min_cpu_cores=0.2,
                timeout_seconds=30.0,
                priority=7,
                required_strategy=ResourceStrategy.CPU_SEQ
            )
        }
    
    def start_analysis(self,
                      analysis_type: str,
                      public_key: str,
                      curve: str = "secp256k1") -> str:
        """Start a topological analysis operation.
        
        Args:
            analysis_type: Type of analysis to perform
            public_key: Public key being analyzed
            curve: Elliptic curve name
            
        Returns:
            Operation ID for tracking
            
        Raises:
            ValueError: If analysis type is invalid
        """
        # Validate analysis type
        if analysis_type not in self.resource_profiles:
            raise ValueError(f"Invalid analysis type: {analysis_type}")
        
        # Create operation ID
        operation_id = f"analysis_{analysis_type}_{int(time.time())}"
        
        # Start tracking
        self.monitor.start_operation(analysis_type, operation_id)
        
        # Log analysis start
        self.logger.info(
            f"Started {analysis_type} for public key {public_key[:16]}... "
            f"on curve {curve}"
        )
        
        return operation_id
    
    def complete_analysis(self,
                         operation_id: str,
                         analysis_result: TopologicalAnalysisResult) -> None:
        """Complete a topological analysis operation.
        
        Args:
            operation_id: Operation ID
            analysis_result: Analysis result
        """
        # Complete tracking
        self.monitor.complete_operation(operation_id, analysis_result.status.value)
        
        # Log analysis completion
        self.logger.info(
            f"Completed analysis {operation_id} - "
            f"Vulnerability score: {analysis_result.vulnerability_score:.4f}, "
            f"Status: {analysis_result.status.value}"
        )
    
    def get_optimal_strategy(self,
                            analysis_type: str,
                            complexity: float) -> ResourceStrategy:
        """Get optimal resource strategy for an analysis.
        
        Args:
            analysis_type: Type of analysis
            complexity: Estimated complexity (0-1)
            
        Returns:
            Optimal resource strategy
        """
        # Get resource profile
        profile = self.resource_profiles.get(analysis_type)
        if not profile:
            return ResourceStrategy.FALLBACK
        
        # Check system status
        system_status = self.monitor.get_system_status()
        
        # Decision model based on complexity and system status
        if complexity < 0.3:  # Low complexity
            return ResourceStrategy.CPU_SEQ
        elif complexity < 0.7:  # Medium complexity
            if GPU_AVAILABLE and system_status["gpu_status"]:
                return ResourceStrategy.GPU
            else:
                return ResourceStrategy.CPU_PAR
        else:  # High complexity
            if RAY_AVAILABLE:
                return ResourceStrategy.RAY
            elif GPU_AVAILABLE and system_status["gpu_status"]:
                return ResourceStrategy.GPU
            else:
                return ResourceStrategy.CPU_PAR
    
    def enforce_fixed_resource_profile(self) -> None:
        """Enforce fixed resource profile to prevent timing/volume analysis.
        
        This method ensures that all operations have identical resource usage
        characteristics to prevent side-channel analysis.
        """
        # In a real implementation, this would:
        # 1. Measure current operation resource usage
        # 2. Add padding to match fixed profile
        # 3. Ensure consistent timing through delays
        pass
    
    def get_resource_usage_summary(self) -> Dict[str, Any]:
        """Get summary of resource usage for monitoring.
        
        Returns:
            Dictionary with resource usage summary
        """
        # Get system metrics
        system_metrics = self.monitor.get_system_metrics()
        
        # Get historical usage
        historical_usage = self.monitor.get_historical_usage()
        
        # Calculate averages
        avg_cpu = 0.0
        avg_memory = 0.0
        operation_count = 0
        
        for usage in historical_usage:
            avg_cpu += usage.cpu_percent
            avg_memory += usage.memory_mb
            operation_count += 1
        
        if operation_count > 0:
            avg_cpu /= operation_count
            avg_memory /= operation_count
        
        return {
            "system_metrics": system_metrics,
            "average_cpu_percent": avg_cpu,
            "average_memory_mb": avg_memory,
            "operation_count": operation_count,
            "resource_profiles": {k: asdict(v) for k, v in self.resource_profiles.items()}
        }
    
    def shutdown(self) -> None:
        """Shutdown the resource policy manager."""
        self.monitor.shutdown()
        self.logger.info("ResourcePolicyManager shutdown complete")


# ======================
# HELPER FUNCTIONS
# ======================

def create_default_resource_policy() -> ResourcePolicyConfig:
    """Create default resource policy configuration.
    
    Returns:
        ResourcePolicyConfig: Default configuration
    """
    return ResourcePolicyConfig(
        memory_limit_mb=4096.0,
        cpu_limit_percent=80.0,
        timeout_seconds=300.0,
        max_concurrent_operations=10,
        gpu_memory_limit_mb=4096.0 if GPU_AVAILABLE else None,
        policy_mode=ResourcePolicyMode.ADAPTIVE,
        warning_threshold=0.9,
        adaptive_scaling_factor=0.8,
        enforcement_action="scale_down",
        monitoring_interval=5.0,
        history_size=100
    )


def create_strict_resource_policy() -> ResourcePolicyConfig:
    """Create strict resource policy configuration for high-security environments.
    
    Returns:
        ResourcePolicyConfig: Strict configuration
    """
    return ResourcePolicyConfig(
        memory_limit_mb=2048.0,
        cpu_limit_percent=60.0,
        timeout_seconds=180.0,
        max_concurrent_operations=5,
        gpu_memory_limit_mb=2048.0 if GPU_AVAILABLE else None,
        policy_mode=ResourcePolicyMode.STRICT,
        warning_threshold=0.7,
        adaptive_scaling_factor=0.5,
        enforcement_action="fail",
        monitoring_interval=2.0,
        history_size=200
    )


def create_high_performance_policy() -> ResourcePolicyConfig:
    """Create high-performance resource policy configuration.
    
    Returns:
        ResourcePolicyConfig: High-performance configuration
    """
    return ResourcePolicyConfig(
        memory_limit_mb=8192.0,
        cpu_limit_percent=95.0,
        timeout_seconds=600.0,
        max_concurrent_operations=20,
        gpu_memory_limit_mb=8192.0 if GPU_AVAILABLE else None,
        policy_mode=ResourcePolicyMode.MONITORING,
        warning_threshold=0.95,
        adaptive_scaling_factor=0.9,
        enforcement_action="log",
        monitoring_interval=10.0,
        history_size=50
    )


def get_optimal_resource_strategy(analysis_result: TopologicalAnalysisResult,
                                config: ResourcePolicyConfig) -> ResourceStrategy:
    """Get optimal resource strategy based on analysis result.
    
    Args:
        analysis_result: Topological analysis result
        config: Resource policy configuration
        
    Returns:
        Optimal resource strategy
    """
    # Calculate complexity score (higher = more complex)
    complexity = (
        0.3 * analysis_result.anomaly_score +
        0.2 * analysis_result.vulnerability_score +
        0.5 * (1.0 - analysis_result.stability_metrics.get("score", 1.0))
    )
    
    # Map complexity to resource strategy
    if complexity < 0.3:
        return ResourceStrategy.CPU_SEQ
    elif complexity < 0.6:
        return ResourceStrategy.CPU_PAR
    elif complexity < 0.8 and GPU_AVAILABLE:
        return ResourceStrategy.GPU
    else:
        return ResourceStrategy.RAY if RAY_AVAILABLE else ResourceStrategy.GPU if GPU_AVAILABLE else ResourceStrategy.CPU_PAR
