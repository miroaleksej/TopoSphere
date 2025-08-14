"""
TopoSphere Client Configuration Module

This module provides the configuration management system for the TopoSphere client.
The configuration handles all parameters related to topological analysis, security
assessment, and communication with the server.

The configuration is designed around these core principles:
- **Security First**: Default values prioritize security over performance
- **Resource Awareness**: Configuration adapts to available computational resources
- **Differential Privacy**: All parameters include noise configurations to prevent
  algorithm recovery
- **Fixed Resource Profile**: Ensures all requests have identical size and timing
  characteristics to prevent analysis

Key components:
- ClientConfig: Main configuration class with validation and serialization
- ResourceConstraints: Configuration for resource limitations
- SecurityParameters: Configuration for security thresholds
- AnalysisParameters: Configuration for topological analysis
- ProtocolParameters: Configuration for secure communication

This module works in conjunction with the secure_protocol.py module, ensuring that
all configuration parameters align with the security guarantees of the system.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union, TypeVar, Protocol
import json
import os
import logging
from enum import Enum
from pathlib import Path
import hashlib
import warnings
from datetime import datetime

# Import from our own modules
from ...shared.models.topological_models import TopologicalStructure
from ...shared.models.cryptographic_models import ECDSACurve
from ...shared.protocols.secure_protocol import ProtocolVersion

# ======================
# ENUMERATIONS
# ======================

class PerformanceLevel(Enum):
    """Performance levels for client operations."""
    LOW = "low"  # Maximum security, minimum performance
    MEDIUM = "medium"  # Balanced security and performance
    HIGH = "high"  # Maximum performance, minimum security (not recommended)
    
    @classmethod
    def from_int(cls, level: int) -> PerformanceLevel:
        """Convert integer level to PerformanceLevel."""
        if level <= 1:
            return cls.LOW
        elif level == 2:
            return cls.MEDIUM
        else:
            return cls.HIGH


class VulnerabilityLevel(Enum):
    """Vulnerability levels for security assessment."""
    SECURE = "secure"  # No detected vulnerabilities
    LOW = "low"  # Minor issues, low risk
    MEDIUM = "medium"  # Significant issues, moderate risk
    HIGH = "high"  # Critical issues, high risk
    CRITICAL = "critical"  # Immediate key recovery risk


# ======================
# CONFIGURATION CLASSES
# ======================

@dataclass
class ResourceConstraints:
    """Configuration for resource limitations."""
    max_time: float = 30.0  # Maximum processing time in seconds
    max_memory: float = 1.0  # Maximum memory in GB
    max_cpu: float = 0.8  # Maximum CPU usage (0.0-1.0)
    max_requests_per_minute: int = 60  # Maximum requests per minute
    target_size_gb: float = 0.1  # Target compressed size in GB
    request_timeout: float = 10.0  # Request timeout in seconds
    
    def validate(self) -> None:
        """Validate resource constraints configuration."""
        if self.max_time <= 0:
            raise ValueError("max_time must be positive")
        if self.max_memory <= 0:
            raise ValueError("max_memory must be positive")
        if not (0 <= self.max_cpu <= 1):
            raise ValueError("max_cpu must be between 0 and 1")
        if self.max_requests_per_minute <= 0:
            raise ValueError("max_requests_per_minute must be positive")
        if self.target_size_gb <= 0:
            raise ValueError("target_size_gb must be positive")
        if self.request_timeout <= 0:
            raise ValueError("request_timeout must be positive")


@dataclass
class SecurityParameters:
    """Configuration for security thresholds and parameters."""
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
        """Validate security parameters configuration."""
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
class AnalysisParameters:
    """Configuration for topological analysis parameters."""
    # Basic analysis parameters
    sample_size: int = 1000  # Number of samples for analysis
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
    stability_window: float = 0.1  # Window for stability calculation
    
    # Noise parameters for differential privacy
    min_noise_level: float = 0.01
    max_noise_level: float = 0.1
    noise_decay_factor: float = 0.95
    
    def validate(self, n: int) -> None:
        """Validate analysis parameters configuration.
        
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
        if not (0 <= self.min_noise_level <= self.max_noise_level <= 1):
            raise ValueError("noise levels must be between 0 and 1 with min <= max")
        if not (0 <= self.noise_decay_factor <= 1):
            raise ValueError("noise_decay_factor must be between 0 and 1")


@dataclass
class ProtocolParameters:
    """Configuration for secure protocol parameters."""
    protocol_version: str = ProtocolVersion.V1_2.value
    message_size: int = 1024  # Fixed size for all messages in bytes
    min_noise_level: float = 0.01
    max_noise_level: float = 0.1
    noise_decay_factor: float = 0.95
    timing_delay_min: float = 0.1  # Minimum random delay in seconds
    timing_delay_max: float = 0.5  # Maximum random delay in seconds
    heartbeat_interval: int = 300  # Heartbeat interval in seconds
    session_duration: int = 3600  # Session duration in seconds
    
    def validate(self) -> None:
        """Validate protocol parameters configuration."""
        if self.message_size <= 0:
            raise ValueError("message_size must be positive")
        if not (0 <= self.min_noise_level <= self.max_noise_level <= 1):
            raise ValueError("noise levels must be between 0 and 1 with min <= max")
        if not (0 <= self.noise_decay_factor <= 1):
            raise ValueError("noise_decay_factor must be between 0 and 1")
        if self.timing_delay_min < 0:
            raise ValueError("timing_delay_min must be non-negative")
        if self.timing_delay_max < self.timing_delay_min:
            raise ValueError("timing_delay_max must be greater than timing_delay_min")
        if self.heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")
        if self.session_duration <= 0:
            raise ValueError("session_duration must be positive")


@dataclass
class CompressionParameters:
    """Configuration for compression parameters."""
    # Topological compression
    topological_sample_size: int = 100
    
    # Algebraic compression
    algebraic_sampling_rate: float = 0.1
    
    # Spectral compression
    spectral_threshold_percentile: float = 95
    spectral_psnr_target: float = 40
    
    # Hybrid compression
    hybrid_compression_ratio: float = 700.0
    
    def validate(self) -> None:
        """Validate compression parameters configuration."""
        if self.topological_sample_size <= 0:
            raise ValueError("topological_sample_size must be positive")
        if not (0 < self.algebraic_sampling_rate <= 1):
            raise ValueError("algebraic_sampling_rate must be between 0 and 1")
        if not (50 <= self.spectral_threshold_percentile <= 99):
            raise ValueError("spectral_threshold_percentile must be between 50 and 99")
        if self.spectral_psnr_target <= 0:
            raise ValueError("spectral_psnr_target must be positive")
        if self.hybrid_compression_ratio <= 1:
            raise ValueError("hybrid_compression_ratio must be greater than 1")


@dataclass
class ClientConfig:
    """Main configuration class for TopoSphere client.
    
    This class manages all configuration parameters for the TopoSphere client,
    including validation, serialization, and default values.
    
    Example:
        config = ClientConfig(
            server_url="https://api.toposphere.security",
            api_key="your_api_key_here",
            curve=ECDSACurve.SECP256K1
        )
        config.save("~/.toposphere/config.json")
    """
    # Basic client configuration
    server_url: str = "https://api.toposphere.security"
    api_key: str = ""
    client_id: str = field(default_factory=lambda: f"client_{secrets.token_hex(8)}")
    curve: ECDSACurve = ECDSACurve.SECP256K1
    
    # Performance configuration
    performance_level: PerformanceLevel = PerformanceLevel.MEDIUM
    
    # Resource constraints
    resource_constraints: ResourceConstraints = field(default_factory=ResourceConstraints)
    
    # Security parameters
    security_parameters: SecurityParameters = field(default_factory=SecurityParameters)
    
    # Analysis parameters
    analysis_parameters: AnalysisParameters = field(default_factory=AnalysisParameters)
    
    # Protocol parameters
    protocol_parameters: ProtocolParameters = field(default_factory=ProtocolParameters)
    
    # Compression parameters
    compression_parameters: CompressionParameters = field(default_factory=CompressionParameters)
    
    # Additional configuration
    log_level: str = "INFO"
    cache_dir: str = "~/.toposphere/cache"
    max_cache_size: int = 1024  # MB
    cache_ttl: int = 86400  # seconds (1 day)
    verify_ssl: bool = True
    
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
        # Validate resource constraints
        self.resource_constraints.validate()
        
        # Validate security parameters
        self.security_parameters.validate()
        
        # Validate analysis parameters (using secp256k1 order as n)
        self.analysis_parameters.validate(115792089237316195423570985008687907852837564279074904382605163141518161494337)
        
        # Validate protocol parameters
        self.protocol_parameters.validate()
        
        # Validate compression parameters
        self.compression_parameters.validate()
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_log_levels:
            raise ValueError(f"log_level must be one of {valid_log_levels}")
        
        # Validate cache parameters
        if self.max_cache_size <= 0:
            raise ValueError("max_cache_size must be positive")
        if self.cache_ttl <= 0:
            raise ValueError("cache_ttl must be positive")
    
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
            "client_id": self.client_id,
            "curve": self.curve.value,
            "performance_level": self.performance_level.value,
            "resource_constraints": asdict(self.resource_constraints),
            "security_parameters": asdict(self.security_parameters),
            "analysis_parameters": asdict(self.analysis_parameters),
            "protocol_parameters": asdict(self.protocol_parameters),
            "compression_parameters": asdict(self.compression_parameters),
            "log_level": self.log_level,
            "cache_dir": self.cache_dir,
            "max_cache_size": self.max_cache_size,
            "cache_ttl": self.cache_ttl,
            "verify_ssl": self.verify_ssl,
            "created_at": self.created_at,
            "last_modified": self.last_modified,
            "config_version": self.config_version
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ClientConfig:
        """Create configuration from dictionary.
        
        Args:
            data: Dictionary containing configuration data
            
        Returns:
            ClientConfig: New configuration object
        """
        # Convert curve value to ECDSACurve
        curve_value = data.get("curve", ECDSACurve.SECP256K1.value)
        try:
            curve = ECDSACurve(curve_value)
        except ValueError:
            curve = ECDSACurve.SECP256K1
            warnings.warn(f"Invalid curve value '{curve_value}', using default", RuntimeWarning)
        
        # Convert performance level
        perf_level_value = data.get("performance_level", PerformanceLevel.MEDIUM.value)
        try:
            performance_level = PerformanceLevel(perf_level_value)
        except ValueError:
            performance_level = PerformanceLevel.MEDIUM
            warnings.warn(f"Invalid performance level '{perf_level_value}', using default", RuntimeWarning)
        
        # Create nested objects
        resource_constraints = ResourceConstraints(**data.get("resource_constraints", {}))
        security_parameters = SecurityParameters(**data.get("security_parameters", {}))
        analysis_parameters = AnalysisParameters(**data.get("analysis_parameters", {}))
        protocol_parameters = ProtocolParameters(**data.get("protocol_parameters", {}))
        compression_parameters = CompressionParameters(**data.get("compression_parameters", {}))
        
        # Create main config
        return cls(
            server_url=data.get("server_url", "https://api.toposphere.security"),
            api_key=data.get("api_key", ""),
            client_id=data.get("client_id", f"client_{secrets.token_hex(8)}"),
            curve=curve,
            performance_level=performance_level,
            resource_constraints=resource_constraints,
            security_parameters=security_parameters,
            analysis_parameters=analysis_parameters,
            protocol_parameters=protocol_parameters,
            compression_parameters=compression_parameters,
            log_level=data.get("log_level", "INFO"),
            cache_dir=data.get("cache_dir", "~/.toposphere/cache"),
            max_cache_size=data.get("max_cache_size", 1024),
            cache_ttl=data.get("cache_ttl", 86400),
            verify_ssl=data.get("verify_ssl", True),
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
    def load(cls, path: Union[str, Path]) -> ClientConfig:
        """Load configuration from file.
        
        Args:
            path: Path to load configuration from
            
        Returns:
            ClientConfig: Loaded configuration
            
        Example:
            config = ClientConfig.load("~/.toposphere/config.json")
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
            "betti_secure_values": self.security_parameters.betti_secure_values,
            "betti_deviation_threshold": self.security_parameters.betti_deviation_threshold,
            "topological_entropy_threshold": self.security_parameters.topological_entropy_threshold,
            "symmetry_violation_threshold": self.security_parameters.symmetry_violation_threshold,
            "spiral_consistency_threshold": self.security_parameters.spiral_consistency_threshold,
            "vulnerability_score_threshold": self.security_parameters.vulnerability_score_threshold,
            "risk_threshold": self.security_parameters.risk_threshold,
            "lambda_param": self.security_parameters.lambda_param
        }
    
    def get_analysis_profile(self) -> Dict[str, Any]:
        """Get the analysis profile based on configuration.
        
        Returns:
            Dictionary containing analysis profile information
        """
        return {
            "sample_size": self.analysis_parameters.sample_size,
            "sampling_rate": self.analysis_parameters.sampling_rate,
            "max_dimension": self.analysis_parameters.max_dimension,
            "min_epsilon": self.analysis_parameters.min_epsilon,
            "max_epsilon": self.analysis_parameters.max_epsilon,
            "epsilon_steps": self.analysis_parameters.epsilon_steps,
            "spiral_pattern_threshold": self.analysis_parameters.spiral_pattern_threshold,
            "star_pattern_threshold": self.analysis_parameters.star_pattern_threshold,
            "symmetry_threshold": self.analysis_parameters.symmetry_threshold,
            "diagonal_periodicity_threshold": self.analysis_parameters.diagonal_periodicity_threshold,
            "stability_threshold": self.analysis_parameters.stability_threshold,
            "stability_window": self.analysis_parameters.stability_window
        }
    
    def get_protocol_profile(self) -> Dict[str, Any]:
        """Get the protocol profile based on configuration.
        
        Returns:
            Dictionary containing protocol profile information
        """
        return {
            "protocol_version": self.protocol_parameters.protocol_version,
            "message_size": self.protocol_parameters.message_size,
            "min_noise_level": self.protocol_parameters.min_noise_level,
            "max_noise_level": self.protocol_parameters.max_noise_level,
            "noise_decay_factor": self.protocol_parameters.noise_decay_factor,
            "timing_delay_min": self.protocol_parameters.timing_delay_min,
            "timing_delay_max": self.protocol_parameters.timing_delay_max,
            "heartbeat_interval": self.protocol_parameters.heartbeat_interval,
            "session_duration": self.protocol_parameters.session_duration
        }
    
    def get_compression_profile(self) -> Dict[str, Any]:
        """Get the compression profile based on configuration.
        
        Returns:
            Dictionary containing compression profile information
        """
        return {
            "topological_sample_size": self.compression_parameters.topological_sample_size,
            "algebraic_sampling_rate": self.compression_parameters.algebraic_sampling_rate,
            "spectral_threshold_percentile": self.compression_parameters.spectral_threshold_percentile,
            "spectral_psnr_target": self.compression_parameters.spectral_psnr_target,
            "hybrid_compression_ratio": self.compression_parameters.hybrid_compression_ratio
        }
    
    def configure_for_target_size(self, target_size_gb: float) -> None:
        """Configure parameters to achieve target compressed size.
        
        Args:
            target_size_gb: Target size in GB
            
        Example:
            config.configure_for_target_size(0.01)  # 10 MB target
        """
        # Calculate scaling factor
        current_size_gb = self.resource_constraints.target_size_gb
        scaling_factor = target_size_gb / current_size_gb
        
        # Adjust parameters proportionally
        self.analysis_parameters.sample_size = max(
            10, 
            int(self.analysis_parameters.sample_size * scaling_factor)
        )
        self.analysis_parameters.sampling_rate = max(
            0.001, 
            min(1.0, self.analysis_parameters.sampling_rate * scaling_factor)
        )
        self.compression_parameters.spectral_threshold_percentile = max(
            50,
            min(99, 95 - int((1 - scaling_factor) * 45))
        )
        
        # Update resource constraints
        self.resource_constraints.target_size_gb = target_size_gb
        self.last_modified = datetime.now().isoformat()


# ======================
# HELPER FUNCTIONS
# ======================

def get_default_config() -> ClientConfig:
    """Get default client configuration.
    
    Returns:
        ClientConfig: Default configuration
    """
    return ClientConfig()


def get_secure_config() -> ClientConfig:
    """Get secure client configuration (prioritizing security over performance).
    
    Returns:
        ClientConfig: Secure configuration
    """
    config = ClientConfig(
        performance_level=PerformanceLevel.LOW,
        security_parameters=SecurityParameters(
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
        analysis_parameters=AnalysisParameters(
            sample_size=5000,
            sampling_rate=0.05,
            spiral_pattern_threshold=0.8,
            star_pattern_threshold=0.7,
            symmetry_threshold=0.9,
            diagonal_periodicity_threshold=0.85,
            stability_threshold=0.8
        ),
        protocol_parameters=ProtocolParameters(
            min_noise_level=0.05,
            max_noise_level=0.1,
            noise_decay_factor=0.9,
            timing_delay_min=0.3,
            timing_delay_max=0.5
        )
    )
    return config


def get_high_performance_config() -> ClientConfig:
    """Get high-performance client configuration (prioritizing speed over security).
    
    Returns:
        ClientConfig: High-performance configuration
    """
    config = ClientConfig(
        performance_level=PerformanceLevel.HIGH,
        security_parameters=SecurityParameters(
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
        analysis_parameters=AnalysisParameters(
            sample_size=500,
            sampling_rate=0.001,
            spiral_pattern_threshold=0.6,
            star_pattern_threshold=0.5,
            symmetry_threshold=0.7,
            diagonal_periodicity_threshold=0.65,
            stability_threshold=0.6
        ),
        protocol_parameters=ProtocolParameters(
            min_noise_level=0.01,
            max_noise_level=0.01,
            noise_decay_factor=0.99,
            timing_delay_min=0.0,
            timing_delay_max=0.1
        )
    )
    return config


def setup_logging(config: ClientConfig) -> logging.Logger:
    """Set up logging based on client configuration.
    
    Args:
        config: Client configuration
        
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger("TopoSphere.Client")
    
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
    
    # Create file handler if cache directory is specified
    try:
        log_dir = Path(config.cache_dir).expanduser() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not set up file logging: {e}")
    
    return logger
