"""
TopoSphere Server Configuration Module

This module provides comprehensive configuration management for the TopoSphere server,
implementing the industrial-grade standards of AuditCore v3.2. The configuration system
is designed to ensure rigorous mathematical analysis while maintaining performance and
security guarantees.

The configuration follows the foundational principles from our research:
- ECDSA signature space forms a topological torus (β₀=1, β₁=2, β₂=1) for secure implementations
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)
- Diagonal symmetry r(u_r, u_z) = r(u_z, u_r) must hold for secure implementations
- Spiral structure k = u_z + u_r·d mod n provides critical security insights

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This configuration embodies that principle by providing
mathematically rigorous parameters for security analysis.

Key features:
- Industrial-grade validation of all configuration parameters
- Seamless integration with AuditCore v3.2 analysis framework
- Resource-aware configuration for performance optimization
- Security-focused parameter defaults based on topological analysis
- Support for multiple elliptic curves and analysis scenarios
- Comprehensive documentation of all configuration parameters

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Union, TypeVar, Protocol
import json
import os
import logging
from pathlib import Path
import hashlib
import warnings
from datetime import datetime
import time

# External dependencies
try:
    from fastecdsa.curve import Curve, secp256k1
    EC_LIBS_AVAILABLE = True
except ImportError as e:
    EC_LIBS_AVAILABLE = False
    warnings.warn(f"fastecdsa library not found: {e}. Some features will be limited.", 
                 RuntimeWarning)

# Import from our own modules
from ...shared.models.topological_models import (
    BettiNumbers,
    TopologicalPattern,
    VulnerabilityType
)
from ...shared.protocols.secure_protocol import (
    ProtocolVersion,
    SecurityLevel
)

# ======================
# ENUMERATIONS
# ======================

class PerformanceLevel(Enum):
    """Performance levels for server operations."""
    LOW = "low"  # Maximum security, minimum performance
    MEDIUM = "medium"  # Balanced security and performance
    HIGH = "high"  # Maximum performance, minimum security
    
    @classmethod
    def from_int(cls, level: int) -> PerformanceLevel:
        """Convert integer level to PerformanceLevel."""
        if level <= 1:
            return cls.LOW
        elif level == 2:
            return cls.MEDIUM
        else:
            return cls.HIGH


class CompressionStrategy(Enum):
    """Strategies for data compression in topological analysis."""
    TOPOLOGICAL = "topological"  # Topological compression (lossless)
    ALGEBRAIC = "algebraic"  # Algebraic compression (lossy)
    SPECTRAL = "spectral"  # Spectral compression (lossy)
    HYBRID = "hybrid"  # Hybrid compression (combines all methods)
    
    def get_description(self) -> str:
        """Get description of compression strategy."""
        descriptions = {
            CompressionStrategy.TOPOLOGICAL: "Lossless topological compression preserving all topological features",
            CompressionStrategy.ALGEBRAIC: "Algebraic compression based on sampling rate and line resolution",
            CompressionStrategy.SPECTRAL: "Spectral compression using frequency domain analysis",
            CompressionStrategy.HYBRID: "Hybrid approach combining topological, algebraic, and spectral methods"
        }
        return descriptions.get(self, "Compression strategy")


class ComputeStrategy(Enum):
    """Strategies for dynamic compute routing."""
    CPU = "cpu"  # CPU-based computation
    GPU = "gpu"  # GPU-accelerated computation
    DISTRIBUTED = "distributed"  # Distributed computation (Ray/Spark)
    AUTO = "auto"  # Automatic strategy selection
    
    def get_description(self) -> str:
        """Get description of compute strategy."""
        descriptions = {
            ComputeStrategy.CPU: "CPU-based computation for general-purpose analysis",
            ComputeStrategy.GPU: "GPU-accelerated computation for high-performance topological analysis",
            ComputeStrategy.DISTRIBUTED: "Distributed computation using Ray/Spark for large-scale analysis",
            ComputeStrategy.AUTO: "Automatic strategy selection based on resource availability and analysis complexity"
        }
        return descriptions.get(self, "Compute strategy")


# ======================
# CONFIGURATION CLASSES
# ======================

@dataclass
class PerformanceConfig:
    """Configuration for performance-related parameters."""
    performance_level: PerformanceLevel = PerformanceLevel.MEDIUM
    max_memory_mb: int = 1024  # Maximum memory usage in MB
    max_cpu_cores: int = 4  # Maximum CPU cores to use
    timeout_seconds: int = 300  # Timeout for analysis operations
    parallel_processing: bool = True  # Whether to use parallel processing
    num_workers: int = 4  # Number of worker processes/threads
    gpu_acceleration: bool = True  # Whether to use GPU acceleration
    distributed_computing: bool = False  # Whether to use distributed computing
    resource_monitoring_interval: float = 5.0  # Resource monitoring interval in seconds
    
    def validate(self) -> None:
        """Validate performance configuration parameters."""
        if self.max_memory_mb <= 0:
            raise ValueError("max_memory_mb must be positive")
        if self.max_cpu_cores <= 0:
            raise ValueError("max_cpu_cores must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.num_workers <= 0:
            raise ValueError("num_workers must be positive")
        if self.resource_monitoring_interval <= 0:
            raise ValueError("resource_monitoring_interval must be positive")


@dataclass
class SecurityConfig:
    """Configuration for security-related parameters."""
    # Betti number thresholds
    betti_secure_values: Dict[str, float] = field(
        default_factory=lambda: {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0}
    )
    betti_deviation_threshold: float = 0.3  # Maximum acceptable deviation
    
    # Entropy thresholds
    topological_entropy_threshold: float = 0.5  # Minimum acceptable entropy
    quantum_entropy_threshold: float = 0.5  # Minimum acceptable quantum entropy
    
    # Symmetry thresholds
    symmetry_violation_threshold: float = 0.01  # Maximum acceptable violation rate
    
    # Spiral pattern thresholds
    spiral_consistency_threshold: float = 0.7  # Minimum acceptable consistency
    
    # Vulnerability thresholds
    vulnerability_score_threshold: float = 0.2  # Maximum acceptable score
    critical_vulnerability_threshold: float = 0.7  # Critical vulnerability threshold
    
    # Address rotation parameters
    lambda_param: float = 0.01  # Exponential decay parameter
    risk_threshold: float = 0.05  # Maximum acceptable risk probability
    
    def validate(self) -> None:
        """Validate security configuration parameters."""
        if not (0 <= self.betti_deviation_threshold <= 1):
            raise ValueError("betti_deviation_threshold must be between 0 and 1")
        if not (0 <= self.topological_entropy_threshold <= 1):
            raise ValueError("topological_entropy_threshold must be between 0 and 1")
        if not (0 <= self.quantum_entropy_threshold <= 1):
            raise ValueError("quantum_entropy_threshold must be between 0 and 1")
        if not (0 <= self.symmetry_violation_threshold <= 1):
            raise ValueError("symmetry_violation_threshold must be between 0 and 1")
        if not (0 <= self.spiral_consistency_threshold <= 1):
            raise ValueError("spiral_consistency_threshold must be between 0 and 1")
        if not (0 <= self.vulnerability_score_threshold <= 1):
            raise ValueError("vulnerability_score_threshold must be between 0 and 1")
        if not (0 <= self.critical_vulnerability_threshold <= 1):
            raise ValueError("critical_vulnerability_threshold must be between 0 and 1")
        if self.lambda_param <= 0:
            raise ValueError("lambda_param must be positive")
        if not (0 <= self.risk_threshold <= 1):
            raise ValueError("risk_threshold must be between 0 and 1")


@dataclass
class TopologicalConfig:
    """Configuration for topological analysis parameters."""
    # Basic analysis parameters
    sample_size: int = 5000  # Number of samples for analysis
    sampling_rate: float = 0.01  # Rate of sampling for large datasets
    max_dimension: int = 2  # Maximum homology dimension to compute
    
    # Epsilon parameters for persistent homology
    min_epsilon: float = 0.01  # Minimum epsilon value
    max_epsilon: float = 0.1  # Maximum epsilon value
    epsilon_steps: int = 10  # Number of epsilon steps
    
    # Pattern detection thresholds
    spiral_pattern_threshold: float = 0.7
    star_pattern_threshold: float = 0.6
    symmetry_threshold: float = 0.8
    diagonal_periodicity_threshold: float = 0.75
    
    # Stability parameters
    stability_threshold: float = 0.7  # Minimum acceptable stability
    stability_window: float = 5  # Window for stability calculation (number of scales)
    nerve_stability_weight: float = 0.7  # Weight for nerve stability
    smoothing_weight: float = 0.6  # Weight for smoothing
    
    # Security parameters
    min_uniformity_score: float = 0.7
    max_fractal_dimension: float = 2.2
    min_entropy: float = 4.0
    anomaly_score_threshold: float = 0.3
    betti1_anomaly_threshold: float = 2.5
    betti2_anomaly_threshold: float = 1.5
    
    def validate(self, n: int) -> None:
        """Validate topological configuration parameters.
        
        Args:
            n: Curve order for validation
            
        Raises:
            ValueError: If parameters are invalid
        """
        if self.sample_size <= 0:
            raise ValueError("sample_size must be positive")
        if not (0 < self.sampling_rate <= 1):
            raise ValueError("sampling_rate must be between 0 and 1")
        if self.max_dimension < 0:
            raise ValueError("max_dimension must be non-negative")
        if self.min_epsilon <= 0:
            raise ValueError("min_epsilon must be positive")
        if self.max_epsilon <= self.min_epsilon:
            raise ValueError("max_epsilon must be greater than min_epsilon")
        if self.epsilon_steps <= 0:
            raise ValueError("epsilon_steps must be positive")
        if not (0 <= self.spiral_pattern_threshold <= 1):
            raise ValueError("spiral_pattern_threshold must be between 0 and 1")
        if not (0 <= self.star_pattern_threshold <= 1):
            raise ValueError("star_pattern_threshold must be between 0 and 1")
        if not (0 <= self.symmetry_threshold <= 1):
            raise ValueError("symmetry_threshold must be between 0 and 1")
        if not (0 <= self.diagonal_periodicity_threshold <= 1):
            raise ValueError("diagonal_periodicity_threshold must be between 0 and 1")
        if not (0 <= self.stability_threshold <= 1):
            raise ValueError("stability_threshold must be between 0 and 1")
        if self.stability_window <= 0:
            raise ValueError("stability_window must be positive")
        if not (0 <= self.nerve_stability_weight <= 1):
            raise ValueError("nerve_stability_weight must be between 0 and 1")
        if not (0 <= self.smoothing_weight <= 1):
            raise ValueError("smoothing_weight must be between 0 and 1")
        if not (0 <= self.min_uniformity_score <= 1):
            raise ValueError("min_uniformity_score must be between 0 and 1")
        if self.max_fractal_dimension <= 0:
            raise ValueError("max_fractal_dimension must be positive")
        if self.min_entropy <= 0:
            raise ValueError("min_entropy must be positive")
        if not (0 <= self.anomaly_score_threshold <= 1):
            raise ValueError("anomaly_score_threshold must be between 0 and 1")
        if self.betti1_anomaly_threshold <= 0:
            raise ValueError("betti1_anomaly_threshold must be positive")
        if self.betti2_anomaly_threshold <= 0:
            raise ValueError("betti2_anomaly_threshold must be positive")


@dataclass
class TconConfig:
    """Configuration for TCON (Topological Conformance) verification."""
    # Basic parameters
    n: int = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    curve_name: str = "secp256k1"
    model_version: str = "v1.0"
    api_version: str = ProtocolVersion.V1_2.value
    
    # Topological parameters
    homology_dimensions: List[int] = field(default_factory=lambda: [0, 1, 2])
    persistence_threshold: float = 100.0
    betti0_expected: float = 1.0
    betti1_expected: float = 2.0
    betti2_expected: float = 1.0
    
    # Stability parameters
    stability_threshold: float = 0.7
    nerve_stability_threshold: float = 0.75
    max_analysis_time: float = 300.0
    max_memory_usage: float = 0.8
    
    def validate(self) -> None:
        """Validate TCON configuration parameters."""
        if self.n <= 0:
            raise ValueError("n must be positive")
        if not self.curve_name:
            raise ValueError("curve_name cannot be empty")
        if not self.model_version:
            raise ValueError("model_version cannot be empty")
        if not self.api_version:
            raise ValueError("api_version cannot be empty")
        if self.persistence_threshold <= 0:
            raise ValueError("persistence_threshold must be positive")
        if not (0 <= self.stability_threshold <= 1):
            raise ValueError("stability_threshold must be between 0 and 1")
        if not (0 <= self.nerve_stability_threshold <= 1):
            raise ValueError("nerve_stability_threshold must be between 0 and 1")
        if self.max_analysis_time <= 0:
            raise ValueError("max_analysis_time must be positive")
        if not (0 < self.max_memory_usage <= 1):
            raise ValueError("max_memory_usage must be between 0 and 1")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "n": self.n,
            "curve_name": self.curve_name,
            "model_version": self.model_version,
            "api_version": self.api_version,
            "homology_dimensions": self.homology_dimensions,
            "persistence_threshold": self.persistence_threshold,
            "betti0_expected": self.betti0_expected,
            "betti1_expected": self.betti1_expected,
            "betti2_expected": self.betti2_expected,
            "stability_threshold": self.stability_threshold,
            "nerve_stability_threshold": self.nerve_stability_threshold,
            "max_analysis_time": self.max_analysis_time,
            "max_memory_usage": self.max_memory_usage
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TconConfig:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing configuration data
            
        Returns:
            TconConfig: New configuration object
        """
        # Handle homology_dimensions if it's a string (JSON serialization issue)
        if 'homology_dimensions' in data and isinstance(data['homology_dimensions'], str):
            data['homology_dimensions'] = json.loads(data['homology_dimensions'])
        
        return cls(**data)
    
    def _config_hash(self) -> str:
        """Generate a hash of the configuration for reproducibility."""
        config_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:8]


@dataclass
class HyperCoreConfig:
    """Configuration for HyperCore Transformer with Nerve integration."""
    # Basic parameters
    n: int = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    curve_name: str = "secp256k1"
    grid_size: int = 1000
    
    # Topological parameters
    homology_dimensions: List[int] = field(default_factory=lambda: [0, 1, 2])
    persistence_threshold: float = 100.0
    betti0_expected: float = 1.0
    betti1_expected: float = 2.0
    betti2_expected: float = 1.0
    
    # Stability parameters
    stability_threshold: float = 0.7
    nerve_stability_threshold: float = 0.75
    max_analysis_time: float = 300.0
    max_memory_usage: float = 0.8
    
    def validate(self) -> None:
        """Validate HyperCore configuration parameters."""
        if self.n <= 0:
            raise ValueError("n must be positive")
        if not self.curve_name:
            raise ValueError("curve_name cannot be empty")
        if self.grid_size <= 0:
            raise ValueError("grid_size must be positive")
        if not (0 <= self.stability_threshold <= 1):
            raise ValueError("stability_threshold must be between 0 and 1")
        if not (0 <= self.nerve_stability_threshold <= 1):
            raise ValueError("nerve_stability_threshold must be between 0 and 1")
        if self.max_analysis_time <= 0:
            raise ValueError("max_analysis_time must be positive")
        if not (0 < self.max_memory_usage <= 1):
            raise ValueError("max_memory_usage must be between 0 and 1")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "n": self.n,
            "curve_name": self.curve_name,
            "grid_size": self.grid_size,
            "homology_dimensions": self.homology_dimensions,
            "persistence_threshold": self.persistence_threshold,
            "betti0_expected": self.betti0_expected,
            "betti1_expected": self.betti1_expected,
            "betti2_expected": self.betti2_expected,
            "stability_threshold": self.stability_threshold,
            "nerve_stability_threshold": self.nerve_stability_threshold,
            "max_analysis_time": self.max_analysis_time,
            "max_memory_usage": self.max_memory_usage
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HyperCoreConfig:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing configuration data
            
        Returns:
            HyperCoreConfig: New configuration object
        """
        # Handle homology_dimensions if it's a string (JSON serialization issue)
        if 'homology_dimensions' in data and isinstance(data['homology_dimensions'], str):
            data['homology_dimensions'] = json.loads(data['homology_dimensions'])
        
        return cls(**data)
    
    def _config_hash(self) -> str:
        """Generate a hash of the configuration for reproducibility."""
        config_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:8]


@dataclass
class ComputeRouterConfig:
    """Configuration for Dynamic Compute Router."""
    # Basic parameters
    n: int = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    curve_name: str = "secp256k1"
    api_version: str = ProtocolVersion.V1_2.value
    default_strategy: ComputeStrategy = ComputeStrategy.AUTO
    
    # Stability parameters
    nerve_stability_threshold: float = 0.75
    max_analysis_time: float = 300.0
    max_memory_usage: float = 0.8
    
    def validate(self) -> None:
        """Validate compute router configuration parameters."""
        if self.n <= 0:
            raise ValueError("n must be positive")
        if not self.curve_name:
            raise ValueError("curve_name cannot be empty")
        if not self.api_version:
            raise ValueError("api_version cannot be empty")
        if not (0 <= self.nerve_stability_threshold <= 1):
            raise ValueError("nerve_stability_threshold must be between 0 and 1")
        if self.max_analysis_time <= 0:
            raise ValueError("max_analysis_time must be positive")
        if not (0 < self.max_memory_usage <= 1):
            raise ValueError("max_memory_usage must be between 0 and 1")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "n": self.n,
            "curve_name": self.curve_name,
            "api_version": self.api_version,
            "default_strategy": self.default_strategy.value,
            "nerve_stability_threshold": self.nerve_stability_threshold,
            "max_analysis_time": self.max_analysis_time,
            "max_memory_usage": self.max_memory_usage
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ComputeRouterConfig:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing configuration data
            
        Returns:
            ComputeRouterConfig: New configuration object
        """
        # Convert string to ComputeStrategy
        if 'default_strategy' in data:
            data['default_strategy'] = ComputeStrategy(data['default_strategy'])
        
        return cls(**data)


@dataclass
class CompressionConfig:
    """Configuration for compression parameters."""
    # Topological compression
    topological_sample_size: int = 100
    
    # Algebraic compression
    algebraic_sampling_rate: float = 0.1
    algebraic_line_resolution: int = 100
    
    # Spectral compression
    spectral_threshold_percentile: float = 95
    spectral_psnr_target: float = 40
    
    # Hybrid compression
    hybrid_compression_ratio: float = 700.0
    
    def validate(self) -> None:
        """Validate compression configuration parameters."""
        if self.topological_sample_size <= 0:
            raise ValueError("topological_sample_size must be positive")
        if not (0 < self.algebraic_sampling_rate <= 1):
            raise ValueError("algebraic_sampling_rate must be between 0 and 1")
        if self.algebraic_line_resolution <= 0:
            raise ValueError("algebraic_line_resolution must be positive")
        if not (50 <= self.spectral_threshold_percentile <= 99):
            raise ValueError("spectral_threshold_percentile must be between 50 and 99")
        if self.spectral_psnr_target <= 0:
            raise ValueError("spectral_psnr_target must be positive")
        if self.hybrid_compression_ratio <= 1:
            raise ValueError("hybrid_compression_ratio must be greater than 1")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "topological_sample_size": self.topological_sample_size,
            "algebraic_sampling_rate": self.algebraic_sampling_rate,
            "algebraic_line_resolution": self.algebraic_line_resolution,
            "spectral_threshold_percentile": self.spectral_threshold_percentile,
            "spectral_psnr_target": self.spectral_psnr_target,
            "hybrid_compression_ratio": self.hybrid_compression_ratio
        }


@dataclass
class ServerConfig:
    """Main configuration class for TopoSphere server.
    
    This class manages all configuration parameters for the TopoSphere server,
    including validation, serialization, and default values.
    
    Example:
        config = ServerConfig(
            server_url="https://api.toposphere.security",
            api_key="your_api_key_here",
            curve=secp256k1
        )
        config.save("~/.toposphere/config.json")
    """
    # Basic server configuration
    server_url: str = "http://localhost:8000"
    api_key: str = ""
    server_id: str = field(default_factory=lambda: f"server_{secrets.token_hex(8)}")
    curve: str = "secp256k1"
    
    # Performance configuration
    performance_config: PerformanceConfig = field(default_factory=PerformanceConfig)
    
    # Security configuration
    security_config: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Topological configuration
    topological_config: TopologicalConfig = field(default_factory=TopologicalConfig)
    
    # TCON configuration
    tcon_config: TconConfig = field(default_factory=TconConfig)
    
    # HyperCore configuration
    hypercore_config: HyperCoreConfig = field(default_factory=HyperCoreConfig)
    
    # Compute router configuration
    compute_router_config: ComputeRouterConfig = field(default_factory=ComputeRouterConfig)
    
    # Compression configuration
    compression_config: CompressionConfig = field(default_factory=CompressionConfig)
    
    # Additional configuration
    log_level: str = "INFO"
    data_dir: str = "/var/lib/toposphere"
    max_cache_size: int = 1024  # MB
    cache_ttl: int = 86400  # seconds (1 day)
    enable_metrics: bool = True
    metrics_interval: float = 5.0  # seconds
    
    # Internal fields
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_modified: str = field(default_factory=lambda: datetime.now().isoformat())
    config_version: str = "1.0.0"
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self.validate()
        self.last_modified = datetime.now().isoformat()
    
    def validate(self) -> None:
        """Validate the entire configuration.
        
        Raises:
            ValueError: If any configuration parameter is invalid
        """
        # Validate performance config
        self.performance_config.validate()
        
        # Validate security config
        self.security_config.validate()
        
        # Validate topological config (using secp256k1 order as n)
        self.topological_config.validate(115792089237316195423570985008687907852837564279074904382605163141518161494337)
        
        # Validate TCON config
        self.tcon_config.validate()
        
        # Validate HyperCore config
        self.hypercore_config.validate()
        
        # Validate compute router config
        self.compute_router_config.validate()
        
        # Validate compression config
        self.compression_config.validate()
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_log_levels:
            raise ValueError(f"log_level must be one of {valid_log_levels}")
        
        # Validate cache parameters
        if self.max_cache_size <= 0:
            raise ValueError("max_cache_size must be positive")
        if self.cache_ttl <= 0:
            raise ValueError("cache_ttl must be positive")
        if self.metrics_interval <= 0:
            raise ValueError("metrics_interval must be positive")
    
    def update(self, **kwargs) -> None:
        """Update configuration with new values.
        
        Args:
            **kwargs: Configuration parameters to update
            
        Example:
            config.update(
                server_url="https://new-api.toposphere.security",
                performance_level=PerformanceLevel.HIGH
            )
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                # Check if it's a nested parameter
                parts = key.split('.')
                if len(parts) == 2 and hasattr(self, parts[0]):
                    nested_obj = getattr(self, parts[0])
                    if hasattr(nested_obj, parts[1]):
                        setattr(nested_obj, parts[1], value)
                    else:
                        raise ValueError(f"Invalid configuration parameter: {key}")
                else:
                    raise ValueError(f"Invalid configuration parameter: {key}")
        
        # Revalidate after update
        self.validate()
        self.last_modified = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization.
        
        Returns:
            Dictionary representation of the configuration
        """
        return {
            "server_url": self.server_url,
            "api_key": self.api_key,
            "server_id": self.server_id,
            "curve": self.curve,
            "performance_config": asdict(self.performance_config),
            "security_config": asdict(self.security_config),
            "topological_config": asdict(self.topological_config),
            "tcon_config": self.tcon_config.to_dict(),
            "hypercore_config": self.hypercore_config.to_dict(),
            "compute_router_config": self.compute_router_config.to_dict(),
            "compression_config": self.compression_config.to_dict(),
            "log_level": self.log_level,
            "data_dir": self.data_dir,
            "max_cache_size": self.max_cache_size,
            "cache_ttl": self.cache_ttl,
            "enable_metrics": self.enable_metrics,
            "metrics_interval": self.metrics_interval,
            "created_at": self.created_at,
            "last_modified": self.last_modified,
            "config_version": self.config_version
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ServerConfig:
        """Create configuration from dictionary.
        
        Args:
            data: Dictionary containing configuration data
            
        Returns:
            ServerConfig: New configuration object
        """
        # Create nested objects
        performance_config = PerformanceConfig(**data.get("performance_config", {}))
        security_config = SecurityConfig(**data.get("security_config", {}))
        topological_config = TopologicalConfig(**data.get("topological_config", {}))
        tcon_config = TconConfig.from_dict(data.get("tcon_config", {}))
        hypercore_config = HyperCoreConfig.from_dict(data.get("hypercore_config", {}))
        compute_router_config = ComputeRouterConfig.from_dict(data.get("compute_router_config", {}))
        compression_config = CompressionConfig(**data.get("compression_config", {}))
        
        # Create main config
        return cls(
            server_url=data.get("server_url", "http://localhost:8000"),
            api_key=data.get("api_key", ""),
            server_id=data.get("server_id", f"server_{secrets.token_hex(8)}"),
            curve=data.get("curve", "secp256k1"),
            performance_config=performance_config,
            security_config=security_config,
            topological_config=topological_config,
            tcon_config=tcon_config,
            hypercore_config=hypercore_config,
            compute_router_config=compute_router_config,
            compression_config=compression_config,
            log_level=data.get("log_level", "INFO"),
            data_dir=data.get("data_dir", "/var/lib/toposphere"),
            max_cache_size=data.get("max_cache_size", 1024),
            cache_ttl=data.get("cache_ttl", 86400),
            enable_metrics=data.get("enable_metrics", True),
            metrics_interval=data.get("metrics_interval", 5.0),
            created_at=data.get("created_at", datetime.now().isoformat()),
            last_modified=data.get("last_modified", datetime.now().isoformat()),
            config_version=data.get("config_version", "1.0.0")
        )
    
    def save(self, path: Union[str, Path]) -> None:
        """Save configuration to file.
        
        Args:
            path: Path to save configuration file
            
        Example:
            config.save("~/.toposphere/config.json")
        """
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Union[str, Path]) -> ServerConfig:
        """Load configuration from file.
        
        Args:
            path: Path to load configuration from
            
        Returns:
            ServerConfig: Loaded configuration
            
        Example:
            config = ServerConfig.load("~/.toposphere/config.json")
        """
        path = Path(path).expanduser()
        
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        
        with open(path, "r") as f:
            data = json.load(f)
            return cls.from_dict(data)
    
    def get_config_hash(self) -> str:
        """Generate a hash of the configuration for reproducibility.
        
        Returns:
            str: SHA-256 hash of the configuration
        """
        config_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def get_security_profile(self) -> Dict[str, Any]:
        """Get the security profile based on configuration.
        
        Returns:
            Dictionary containing security profile information
        """
        return {
            "betti_secure_values": self.security_config.betti_secure_values,
            "betti_deviation_threshold": self.security_config.betti_deviation_threshold,
            "topological_entropy_threshold": self.security_config.topological_entropy_threshold,
            "symmetry_violation_threshold": self.security_config.symmetry_violation_threshold,
            "spiral_consistency_threshold": self.security_config.spiral_consistency_threshold,
            "vulnerability_score_threshold": self.security_config.vulnerability_score_threshold,
            "risk_threshold": self.security_config.risk_threshold,
            "lambda_param": self.security_config.lambda_param
        }
    
    def get_analysis_profile(self) -> Dict[str, Any]:
        """Get the analysis profile based on configuration.
        
        Returns:
            Dictionary containing analysis profile information
        """
        return {
            "sample_size": self.topological_config.sample_size,
            "sampling_rate": self.topological_config.sampling_rate,
            "max_dimension": self.topological_config.max_dimension,
            "min_epsilon": self.topological_config.min_epsilon,
            "max_epsilon": self.topological_config.max_epsilon,
            "epsilon_steps": self.topological_config.epsilon_steps,
            "spiral_pattern_threshold": self.topological_config.spiral_pattern_threshold,
            "star_pattern_threshold": self.topological_config.star_pattern_threshold,
            "symmetry_threshold": self.topological_config.symmetry_threshold,
            "diagonal_periodicity_threshold": self.topological_config.diagonal_periodicity_threshold,
            "stability_threshold": self.topological_config.stability_threshold,
            "stability_window": self.topological_config.stability_window
        }
    
    def get_compression_profile(self) -> Dict[str, Any]:
        """Get the compression profile based on configuration.
        
        Returns:
            Dictionary containing compression profile information
        """
        return {
            "topological_sample_size": self.compression_config.topological_sample_size,
            "algebraic_sampling_rate": self.compression_config.algebraic_sampling_rate,
            "algebraic_line_resolution": self.compression_config.algebraic_line_resolution,
            "spectral_threshold_percentile": self.compression_config.spectral_threshold_percentile,
            "spectral_psnr_target": self.compression_config.spectral_psnr_target,
            "hybrid_compression_ratio": self.compression_config.hybrid_compression_ratio
        }
    
    def configure_for_target_size(self, target_size_gb: float) -> None:
        """Configure parameters to achieve target compressed size.
        
        Args:
            target_size_gb: Target size in GB
            
        Example:
            config.configure_for_target_size(0.01)  # 10 MB target
        """
        # Calculate scaling factor
        current_size_gb = self.performance_config.max_memory_mb / 1024
        scaling_factor = target_size_gb / current_size_gb
        
        # Adjust parameters proportionally
        self.topological_config.sample_size = max(
            10, 
            int(self.topological_config.sample_size * scaling_factor)
        )
        self.topological_config.sampling_rate = max(
            0.001, 
            min(1.0, self.topological_config.sampling_rate * scaling_factor)
        )
        self.compression_config.spectral_threshold_percentile = max(
            50,
            min(99, 95 - int((1 - scaling_factor) * 45))
        )
        
        # Update performance config
        self.performance_config.max_memory_mb = int(target_size_gb * 1024)
        self.last_modified = datetime.now().isoformat()
    
    def get_tcon_parameters(self) -> Dict[str, Any]:
        """Get TCON parameters for verification.
        
        Returns:
            Dictionary containing TCON parameters
        """
        return {
            "betti0_expected": self.tcon_config.betti0_expected,
            "betti1_expected": self.tcon_config.betti1_expected,
            "betti2_expected": self.tcon_config.betti2_expected,
            "stability_threshold": self.tcon_config.stability_threshold,
            "nerve_stability_threshold": self.tcon_config.nerve_stability_threshold
        }
    
    def get_hypercore_parameters(self) -> Dict[str, Any]:
        """Get HyperCore parameters for transformation.
        
        Returns:
            Dictionary containing HyperCore parameters
        """
        return {
            "grid_size": self.hypercore_config.grid_size,
            "persistence_threshold": self.hypercore_config.persistence_threshold,
            "stability_threshold": self.hypercore_config.stability_threshold
        }
    
    def get_compute_router_parameters(self) -> Dict[str, Any]:
        """Get Dynamic Compute Router parameters.
        
        Returns:
            Dictionary containing compute router parameters
        """
        return {
            "default_strategy": self.compute_router_config.default_strategy.value,
            "nerve_stability_threshold": self.compute_router_config.nerve_stability_threshold,
            "max_analysis_time": self.compute_router_config.max_analysis_time,
            "max_memory_usage": self.compute_router_config.max_memory_usage
        }


# ======================
# HELPER FUNCTIONS
# ======================

def get_default_config() -> ServerConfig:
    """Get default server configuration.
    
    Returns:
        ServerConfig: Default configuration
    """
    return ServerConfig()


def get_secure_config() -> ServerConfig:
    """Get secure server configuration (prioritizing security over performance).
    
    Returns:
        ServerConfig: Secure configuration
    """
    config = ServerConfig(
        performance_config=PerformanceConfig(
            performance_level=PerformanceLevel.LOW,
            max_memory_mb=2048,
            max_cpu_cores=8,
            timeout_seconds=600,
            parallel_processing=True,
            num_workers=8,
            gpu_acceleration=True,
            distributed_computing=True
        ),
        security_config=SecurityConfig(
            betti_deviation_threshold=0.1,
            topological_entropy_threshold=0.7,
            quantum_entropy_threshold=0.7,
            symmetry_violation_threshold=0.005,
            spiral_consistency_threshold=0.9,
            vulnerability_score_threshold=0.1,
            critical_vulnerability_threshold=0.5,
            lambda_param=0.005,
            risk_threshold=0.01
        ),
        topological_config=TopologicalConfig(
            sample_size=10000,
            sampling_rate=0.05,
            spiral_pattern_threshold=0.8,
            star_pattern_threshold=0.7,
            symmetry_threshold=0.9,
            diagonal_periodicity_threshold=0.85,
            stability_threshold=0.8
        ),
        tcon_config=TconConfig(
            stability_threshold=0.8,
            nerve_stability_threshold=0.85,
            max_analysis_time=600.0,
            max_memory_usage=0.9
        ),
        hypercore_config=HyperCoreConfig(
            stability_threshold=0.8,
            nerve_stability_threshold=0.85,
            max_analysis_time=600.0,
            max_memory_usage=0.9
        ),
        compute_router_config=ComputeRouterConfig(
            nerve_stability_threshold=0.85,
            max_analysis_time=600.0,
            max_memory_usage=0.9
        )
    )
    return config


def get_high_performance_config() -> ServerConfig:
    """Get high-performance server configuration (prioritizing speed over security).
    
    Returns:
        ServerConfig: High-performance configuration
    """
    config = ServerConfig(
        performance_config=PerformanceConfig(
            performance_level=PerformanceLevel.HIGH,
            max_memory_mb=512,
            max_cpu_cores=2,
            timeout_seconds=150,
            parallel_processing=False,
            num_workers=1,
            gpu_acceleration=False,
            distributed_computing=False
        ),
        security_config=SecurityConfig(
            betti_deviation_threshold=0.5,
            topological_entropy_threshold=0.3,
            quantum_entropy_threshold=0.3,
            symmetry_violation_threshold=0.05,
            spiral_consistency_threshold=0.5,
            vulnerability_score_threshold=0.3,
            critical_vulnerability_threshold=0.8,
            lambda_param=0.02,
            risk_threshold=0.1
        ),
        topological_config=TopologicalConfig(
            sample_size=2000,
            sampling_rate=0.001,
            spiral_pattern_threshold=0.6,
            star_pattern_threshold=0.5,
            symmetry_threshold=0.7,
            diagonal_periodicity_threshold=0.65,
            stability_threshold=0.6
        ),
        tcon_config=TconConfig(
            stability_threshold=0.6,
            nerve_stability_threshold=0.65,
            max_analysis_time=150.0,
            max_memory_usage=0.5
        ),
        hypercore_config=HyperCoreConfig(
            stability_threshold=0.6,
            nerve_stability_threshold=0.65,
            max_analysis_time=150.0,
            max_memory_usage=0.5
        ),
        compute_router_config=ComputeRouterConfig(
            nerve_stability_threshold=0.65,
            max_analysis_time=150.0,
            max_memory_usage=0.5
        )
    )
    return config


def setup_logging(config: ServerConfig) -> logging.Logger:
    """Set up logging based on server configuration.
    
    Args:
        config: Server configuration
        
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger("TopoSphere.Server")
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Set log level
    log_level = getattr(logging, config.log_level, logging.INFO)
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if data directory is specified
    try:
        log_dir = Path(config.data_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not set up file logging: {e}")
    
    return logger
