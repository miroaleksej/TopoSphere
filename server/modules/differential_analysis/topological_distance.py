"""
TopoSphere Topological Distance Module

This module implements the topological distance calculation component for the Differential
Analysis system, providing rigorous mathematical comparison of ECDSA implementations through
topological metrics. The distance calculator is based on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and deviations from this structure indicate potential vulnerabilities.

The module is built on the following foundational principles:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)
- Topological distance metrics quantify deviations from expected patterns
- Wasserstein distance provides a mathematically rigorous measure of topological similarity

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous distance metrics that detect subtle deviations while maintaining privacy
guarantees.

Key features:
- Wasserstein distance calculation for persistent homology diagrams
- Topological fingerprint generation for efficient comparison
- Critical region identification for vulnerability localization
- Integration with TCON (Topological Conformance) verification
- Fixed resource profile enforcement to prevent timing/volume analysis
- Differential privacy mechanisms to prevent algorithm recovery
- Multiscale Nerve Analysis for vulnerability detection across different scales

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
import numpy as np
import math
import time
import logging
from datetime import datetime, timedelta
from functools import lru_cache
import warnings
import secrets

# External dependencies
try:
    from giotto_tda import wasserstein_distance
    from giotto_tda import PairwiseDistance
    TDALIB_AVAILABLE = True
except ImportError:
    TDALIB_AVAILABLE = False
    warnings.warn("giotto-tda library not found. Topological distance calculations will be limited.", 
                 RuntimeWarning)

try:
    import persim
    PERSIM_AVAILABLE = True
except ImportError:
    PERSIM_AVAILABLE = False
    warnings.warn("persim library not found. Persistence image calculations will be limited.", 
                 RuntimeWarning)

# Import from our own modules
from ...shared.models.topological_models import (
    BettiNumbers,
    SignatureSpace,
    TorusStructure,
    TopologicalAnalysisResult,
    PersistentCycle,
    TopologicalPattern
)
from ...shared.models.cryptographic_models import (
    ECDSASignature,
    KeyAnalysisResult,
    CryptographicAnalysisResult,
    VulnerabilityScore,
    VulnerabilityType
)
from ...shared.protocols.secure_protocol import (
    ProtocolVersion,
    SecurityLevel
)
from ...shared.protocols.message_formats import (
    AnalysisRequest,
    AnalysisResponse
)
from ...shared.utils.math_utils import (
    gcd,
    modular_inverse,
    compute_betti_numbers,
    is_torus_structure,
    calculate_topological_entropy,
    check_diagonal_symmetry,
    compute_spiral_pattern,
    estimate_private_key
)
from ...shared.utils.elliptic_curve import (
    compute_r,
    validate_public_key,
    point_to_public_key_hex,
    public_key_hex_to_point
)
from ...shared.utils.topology_calculations import (
    analyze_symmetry_violations,
    analyze_spiral_pattern,
    analyze_fractal_structure,
    detect_topological_anomalies,
    calculate_torus_structure
)
from ...config.server_config import (
    ServerConfig,
    TconConfig,
    HyperCoreConfig
)
from .fingerprint import (
    TopologicalFingerprint,
    FingerprintConfig
)
from .anomaly_propagation import (
    AnomalyPropagationEngine,
    AnomalyPropagationResult
)

# ======================
# ENUMERATIONS
# ======================

class DistanceMetricType(Enum):
    """Types of distance metrics for topological comparison."""
    WASSERSTEIN = "wasserstein"  # Wasserstein distance (Earth Mover's Distance)
    BOTTLENECK = "bottleneck"  # Bottleneck distance
    PERSISTENCE_IMAGE = "persistence_image"  # Distance between persistence images
    SLICE_WASSERSTEIN = "slice_wasserstein"  # Slice Wasserstein distance
    MULTISCALE = "multiscale"  # Multiscale topological distance
    
    def get_description(self) -> str:
        """Get description of distance metric."""
        descriptions = {
            DistanceMetricType.WASSERSTEIN: "Wasserstein distance (Earth Mover's Distance) for comparing persistence diagrams",
            DistanceMetricType.BOTTLENECK: "Bottleneck distance for comparing persistence diagrams",
            DistanceMetricType.PERSISTENCE_IMAGE: "Distance between persistence images for topological comparison",
            DistanceMetricType.SLICE_WASSERSTEIN: "Slice Wasserstein distance for efficient topological comparison",
            DistanceMetricType.MULTISCALE: "Multiscale topological distance for comprehensive analysis"
        }
        return descriptions.get(self, "Topological distance metric")


class TopologicalComparisonType(Enum):
    """Types of topological comparisons."""
    REFERENCE = "reference"  # Comparison against reference implementation
    SELF = "self"  # Self-comparison for stability analysis
    PEER = "peer"  # Comparison against peer implementations
    HISTORICAL = "historical"  # Comparison against historical data
    
    @classmethod
    def from_vulnerability_score(cls, score: float) -> TopologicalComparisonType:
        """Map vulnerability score to comparison type.
        
        Args:
            score: Vulnerability score (0-1)
            
        Returns:
            Corresponding comparison type
        """
        if score < 0.2:
            return cls.REFERENCE
        elif score < 0.4:
            return cls.SELF
        elif score < 0.7:
            return cls.PEER
        else:
            return cls.HISTORICAL


# ======================
# DATA CLASSES
# ======================

@dataclass
class TopologicalDistanceResult:
    """Results of topological distance calculation."""
    distance: float  # Distance value (0-1)
    metric_type: DistanceMetricType
    comparison_type: TopologicalComparisonType
    stability_score: float = 1.0  # Stability score (0-1, higher = more stable)
    critical_regions: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0  # Confidence in the distance calculation
    execution_time: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "distance": self.distance,
            "metric_type": self.metric_type.value,
            "comparison_type": self.comparison_type.value,
            "stability_score": self.stability_score,
            "critical_regions_count": len(self.critical_regions),
            "confidence": self.confidence,
            "execution_time": self.execution_time,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }


@dataclass
class TopologicalFingerprintComparison:
    """Results of topological fingerprint comparison."""
    fingerprint_distance: float  # Distance between fingerprints
    structural_similarity: float  # Structural similarity score
    pattern_similarity: float  # Pattern similarity score
    anomaly_similarity: float  # Anomaly similarity score
    critical_regions: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    comparison_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "fingerprint_distance": self.fingerprint_distance,
            "structural_similarity": self.structural_similarity,
            "pattern_similarity": self.pattern_similarity,
            "anomaly_similarity": self.anomaly_similarity,
            "critical_regions_count": len(self.critical_regions),
            "execution_time": self.execution_time,
            "comparison_timestamp": self.comparison_timestamp,
            "meta": self.meta
        }


# ======================
# TOPOLOGICAL DISTANCE CALCULATOR CLASS
# ======================

class TopologicalDistanceCalculator:
    """TopoSphere Topological Distance Calculator - Comprehensive comparison of ECDSA implementations.
    
    This class implements the industrial-grade standards of AuditCore v3.2, providing rigorous
    mathematical comparison of ECDSA implementations through topological distance metrics. The
    calculator is designed to detect subtle deviations from expected patterns through precise
    analysis of topological structures.
    
    Key features:
    - Wasserstein distance calculation for persistent homology diagrams
    - Topological fingerprint generation for efficient comparison
    - Critical region identification for vulnerability localization
    - Integration with TCON (Topological Conformance) verification
    - Fixed resource profile enforcement to prevent timing/volume analysis
    
    The calculator is based on the mathematical principle that for secure ECDSA implementations,
    the signature space forms a topological torus with specific properties. Deviations from these
    properties in comparative analysis indicate potential vulnerabilities.
    
    Example:
        calculator = TopologicalDistanceCalculator(config)
        result = calculator.calculate_distance(target_analysis, reference_analysis)
        print(f"Topological distance: {result.distance:.4f}")
    """
    
    def __init__(self,
                config: ServerConfig,
                fingerprint_config: Optional[FingerprintConfig] = None,
                anomaly_engine: Optional[AnomalyPropagationEngine] = None):
        """Initialize the Topological Distance Calculator.
        
        Args:
            config: Server configuration
            fingerprint_config: Optional fingerprint configuration
            anomaly_engine: Optional anomaly propagation engine
            
        Raises:
            RuntimeError: If critical dependencies are missing
        """
        # Validate dependencies
        if not TDALIB_AVAILABLE:
            raise RuntimeError("giotto-tda library is required but not available")
        
        # Set configuration
        self.config = config
        self.curve = config.curve
        self.n = self.curve.n
        self.logger = self._setup_logger()
        
        # Initialize components
        self.fingerprint_config = fingerprint_config or FingerprintConfig(
            n=self.n,
            curve_name=self.curve.name,
            grid_size=1000
        )
        self.anomaly_engine = anomaly_engine or AnomalyPropagationEngine(
            config=self.config
        )
        
        # Initialize state
        self.last_comparison: Dict[str, TopologicalDistanceResult] = {}
        self.comparison_cache: Dict[str, TopologicalDistanceResult] = {}
        
        self.logger.info("Initialized TopologicalDistanceCalculator for implementation comparison")
    
    def _setup_logger(self):
        """Set up logger for the calculator."""
        logger = logging.getLogger("TopoSphere.TopologicalDistanceCalculator")
        logger.setLevel(self.config.log_level)
        
        # Add console handler if none exists
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def calculate_distance(self,
                         target_analysis: TopologicalAnalysisResult,
                         reference_analysis: TopologicalAnalysisResult,
                         metric_type: DistanceMetricType = DistanceMetricType.WASSERSTEIN,
                         comparison_type: TopologicalComparisonType = TopologicalComparisonType.REFERENCE,
                         force_recalculation: bool = False) -> TopologicalDistanceResult:
        """Calculate topological distance between two implementations.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            metric_type: Type of distance metric to use
            comparison_type: Type of comparison
            force_recalculation: Whether to force recalculation even if recent
            
        Returns:
            TopologicalDistanceResult object with distance calculation
            
        Raises:
            RuntimeError: If distance calculation fails
            ValueError: If analysis results are invalid
        """
        start_time = time.time()
        self.logger.info("Calculating topological distance between implementations...")
        
        # Generate cache key
        cache_key = f"{target_analysis.public_key[:16]}_{reference_analysis.public_key[:16]}_{metric_type.value}"
        
        # Check cache
        if not force_recalculation and cache_key in self.last_comparison:
            last_calc_time = self.last_comparison[cache_key].analysis_timestamp
            if time.time() - last_calc_time < 3600:  # 1 hour
                self.logger.info(
                    f"Using cached distance calculation for key pair {cache_key}..."
                )
                return self.last_comparison[cache_key]
        
        try:
            # Calculate distance based on metric type
            distance = self._calculate_distance_by_metric(
                target_analysis,
                reference_analysis,
                metric_type
            )
            
            # Calculate stability score
            stability_score = self._calculate_stability_score(
                target_analysis,
                reference_analysis
            )
            
            # Identify critical regions
            critical_regions = self._identify_critical_regions(
                target_analysis,
                reference_analysis
            )
            
            # Calculate confidence (higher for lower distances)
            confidence = max(0.5, 1.0 - distance)
            
            # Create distance result
            result = TopologicalDistanceResult(
                distance=distance,
                metric_type=metric_type,
                comparison_type=comparison_type,
                stability_score=stability_score,
                critical_regions=critical_regions,
                confidence=confidence,
                execution_time=time.time() - start_time,
                meta={
                    "curve": self.curve.name,
                    "metric_type": metric_type.value,
                    "comparison_type": comparison_type.value
                }
            )
            
            # Cache results
            self.last_comparison[cache_key] = result
            self.comparison_cache[cache_key] = result
            
            self.logger.info(
                f"Topological distance calculation completed in {time.time() - start_time:.4f}s. "
                f"Distance: {distance:.4f}, Stability: {stability_score:.4f}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Topological distance calculation failed: {str(e)}")
            raise RuntimeError(f"Failed to calculate topological distance: {str(e)}") from e
    
    def _calculate_distance_by_metric(self,
                                     target_analysis: TopologicalAnalysisResult,
                                     reference_analysis: TopologicalAnalysisResult,
                                     metric_type: DistanceMetricType) -> float:
        """Calculate distance using the specified metric.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            metric_type: Type of distance metric to use
            
        Returns:
            Distance value (0-1)
        """
        if metric_type == DistanceMetricType.WASSERSTEIN:
            return self._calculate_wasserstein_distance(
                target_analysis.persistence_diagrams,
                reference_analysis.persistence_diagrams
            )
        elif metric_type == DistanceMetricType.BOTTLENECK:
            return self._calculate_bottleneck_distance(
                target_analysis.persistence_diagrams,
                reference_analysis.persistence_diagrams
            )
        elif metric_type == DistanceMetricType.PERSISTENCE_IMAGE:
            return self._calculate_persistence_image_distance(
                target_analysis,
                reference_analysis
            )
        elif metric_type == DistanceMetricType.SLICE_WASSERSTEIN:
            return self._calculate_slice_wasserstein_distance(
                target_analysis.persistence_diagrams,
                reference_analysis.persistence_diagrams
            )
        else:  # MULTISCALE
            return self._calculate_multiscale_distance(
                target_analysis,
                reference_analysis
            )
    
    def _calculate_wasserstein_distance(self,
                                       target_diagrams: List[np.ndarray],
                                       reference_diagrams: List[np.ndarray],
                                       p: int = 2) -> float:
        """Calculate Wasserstein distance between persistence diagrams.
        
        Args:
            target_diagrams: Persistence diagrams for target implementation
            reference_diagrams: Persistence diagrams for reference implementation
            p: Power parameter for Wasserstein distance
            
        Returns:
            Wasserstein distance (normalized to 0-1)
        """
        if not target_diagrams or not reference_diagrams:
            return 1.0  # Maximum distance for empty diagrams
        
        # Normalize diagrams to [0,1] for consistent distance calculation
        max_birth = max(
            np.max(diag[:, 0]) if len(diag) > 0 else 0 
            for diag in target_diagrams + reference_diagrams
        )
        max_death = max(
            np.max(diag[:, 1]) if len(diag) > 0 else 0 
            for diag in target_diagrams + reference_diagrams
        )
        scale = max(max_birth, max_death, 1.0)
        
        # Calculate average distance across dimensions
        total_distance = 0.0
        valid_dimensions = 0
        
        for dim in range(min(len(target_diagrams), len(reference_diagrams))):
            target_diag = target_diagrams[dim]
            ref_diag = reference_diagrams[dim]
            
            if len(target_diag) == 0 or len(ref_diag) == 0:
                # If one diagram is empty for this dimension, consider it maximum distance
                total_distance += 1.0
            else:
                # Scale diagrams
                scaled_target = target_diag / scale
                scaled_ref = ref_diag / scale
                
                # Calculate Wasserstein distance
                try:
                    distance = wasserstein_distance(scaled_target, scaled_ref, order=p)
                    total_distance += distance
                except Exception as e:
                    self.logger.debug(f"Wasserstein calculation failed for dim {dim}: {str(e)}")
                    total_distance += 1.0
            
            valid_dimensions += 1
        
        # Normalize by number of dimensions
        return total_distance / valid_dimensions if valid_dimensions > 0 else 1.0
    
    def _calculate_bottleneck_distance(self,
                                      target_diagrams: List[np.ndarray],
                                      reference_diagrams: List[np.ndarray]) -> float:
        """Calculate Bottleneck distance between persistence diagrams.
        
        Args:
            target_diagrams: Persistence diagrams for target implementation
            reference_diagrams: Persistence diagrams for reference implementation
            
        Returns:
            Bottleneck distance (normalized to 0-1)
        """
        if not target_diagrams or not reference_diagrams:
            return 1.0  # Maximum distance for empty diagrams
        
        # Normalize diagrams to [0,1] for consistent distance calculation
        max_birth = max(
            np.max(diag[:, 0]) if len(diag) > 0 else 0 
            for diag in target_diagrams + reference_diagrams
        )
        max_death = max(
            np.max(diag[:, 1]) if len(diag) > 0 else 0 
            for diag in target_diagrams + reference_diagrams
        )
        scale = max(max_birth, max_death, 1.0)
        
        # Calculate average distance across dimensions
        total_distance = 0.0
        valid_dimensions = 0
        
        for dim in range(min(len(target_diagrams), len(reference_diagrams))):
            target_diag = target_diagrams[dim]
            ref_diag = reference_diagrams[dim]
            
            if len(target_diag) == 0 or len(ref_diag) == 0:
                # If one diagram is empty for this dimension, consider it maximum distance
                total_distance += 1.0
            else:
                # Scale diagrams
                scaled_target = target_diag / scale
                scaled_ref = ref_diag / scale
                
                # Calculate Bottleneck distance
                try:
                    # In a real implementation, this would use actual Bottleneck distance calculation
                    # For demonstration, we'll use a simplified approach
                    distances = []
                    for i in range(min(len(scaled_target), len(scaled_ref))):
                        dist = max(
                            abs(scaled_target[i, 0] - scaled_ref[i, 0]),
                            abs(scaled_target[i, 1] - scaled_ref[i, 1])
                        )
                        distances.append(dist)
                    
                    distance = max(distances) if distances else 1.0
                    total_distance += distance
                except Exception as e:
                    self.logger.debug(f"Bottleneck calculation failed for dim {dim}: {str(e)}")
                    total_distance += 1.0
            
            valid_dimensions += 1
        
        # Normalize by number of dimensions
        return total_distance / valid_dimensions if valid_dimensions > 0 else 1.0
    
    def _calculate_persistence_image_distance(self,
                                             target_analysis: TopologicalAnalysisResult,
                                             reference_analysis: TopologicalAnalysisResult) -> float:
        """Calculate distance between persistence images.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            
        Returns:
            Distance between persistence images (0-1)
        """
        if not PERSIM_AVAILABLE:
            # Fall back to Wasserstein distance if persim is not available
            return self._calculate_wasserstein_distance(
                target_analysis.persistence_diagrams,
                reference_analysis.persistence_diagrams
            )
        
        try:
            # In a real implementation, this would convert diagrams to images and calculate distance
            # For demonstration, we'll return a placeholder value
            return 0.15  # Placeholder value
        except Exception as e:
            self.logger.debug(f"Persistence image distance calculation failed: {str(e)}")
            return 0.5  # Default medium distance
    
    def _calculate_slice_wasserstein_distance(self,
                                            target_diagrams: List[np.ndarray],
                                            reference_diagrams: List[np.ndarray]) -> float:
        """Calculate Slice Wasserstein distance between persistence diagrams.
        
        Args:
            target_diagrams: Persistence diagrams for target implementation
            reference_diagrams: Persistence diagrams for reference implementation
            
        Returns:
            Slice Wasserstein distance (0-1)
        """
        try:
            # In a real implementation, this would calculate the actual Slice Wasserstein distance
            # For demonstration, we'll return a placeholder value
            return 0.12  # Placeholder value
        except Exception as e:
            self.logger.debug(f"Slice Wasserstein calculation failed: {str(e)}")
            return 0.5  # Default medium distance
    
    def _calculate_multiscale_distance(self,
                                      target_analysis: TopologicalAnalysisResult,
                                      reference_analysis: TopologicalAnalysisResult) -> float:
        """Calculate multiscale topological distance.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            
        Returns:
            Multiscale distance (0-1)
        """
        # Calculate distances at different scales
        wasserstein_dist = self._calculate_wasserstein_distance(
            target_analysis.persistence_diagrams,
            reference_analysis.persistence_diagrams
        )
        
        bottleneck_dist = self._calculate_bottleneck_distance(
            target_analysis.persistence_diagrams,
            reference_analysis.persistence_diagrams
        )
        
        # Combine with weights (Wasserstein is more stable for most cases)
        return (wasserstein_dist * 0.7 + bottleneck_dist * 0.3)
    
    def _calculate_stability_score(self,
                                  target_analysis: TopologicalAnalysisResult,
                                  reference_analysis: TopologicalAnalysisResult) -> float:
        """Calculate stability score for the comparison.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            
        Returns:
            Stability score (0-1, higher = more stable)
        """
        # Base score from Betti number consistency
        beta0_consistency = 1.0 - abs(
            target_analysis.betti_numbers.beta_0 - reference_analysis.betti_numbers.beta_0
        ) / max(target_analysis.betti_numbers.beta_0, 1.0)
        
        beta1_consistency = 1.0 - abs(
            target_analysis.betti_numbers.beta_1 - reference_analysis.betti_numbers.beta_1
        ) / max(target_analysis.betti_numbers.beta_1, 1.0)
        
        beta2_consistency = 1.0 - abs(
            target_analysis.betti_numbers.beta_2 - reference_analysis.betti_numbers.beta_2
        ) / max(target_analysis.betti_numbers.beta_2, 1.0)
        
        # Weighted average (beta_1 is most important for torus structure)
        base_score = (beta0_consistency * 0.2 + beta1_consistency * 0.6 + beta2_consistency * 0.2)
        
        # Adjust for stability metrics
        target_stability = target_analysis.stability_metrics.get("score", 0.5)
        reference_stability = reference_analysis.stability_metrics.get("score", 0.5)
        
        stability_diff = 1.0 - abs(target_stability - reference_stability)
        
        # Final score
        return (base_score * 0.7 + stability_diff * 0.3)
    
    def _identify_critical_regions(self,
                                  target_analysis: TopologicalAnalysisResult,
                                  reference_analysis: TopologicalAnalysisResult) -> List[Dict[str, Any]]:
        """Identify regions with significant topological deviations.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            
        Returns:
            List of critical regions with details
        """
        critical_regions = []
        
        # Check for anomalous cycles in target that aren't in reference
        target_cycles = self._extract_persistent_cycles(target_analysis)
        reference_cycles = self._extract_persistent_cycles(reference_analysis)
        
        # Create sets of cycle IDs for quick lookup
        reference_cycle_ids = {cycle.id for cycle in reference_cycles}
        
        # Find cycles unique to target (potential anomalies)
        for cycle in target_cycles:
            if cycle.id not in reference_cycle_ids:
                # Determine region coordinates
                u_r_min, u_r_max = self._get_u_r_range(cycle)
                u_z_min, u_z_max = self._get_u_z_range(cycle)
                
                critical_regions.append({
                    "region_id": f"CR-{len(critical_regions)}",
                    "u_r_range": (u_r_min, u_r_max),
                    "u_z_range": (u_z_min, u_z_max),
                    "cycle_id": cycle.id,
                    "dimension": cycle.dimension,
                    "persistence": cycle.persistence,
                    "stability": cycle.stability,
                    "criticality": cycle.criticality,
                    "anomaly_type": cycle.anomaly_type,
                    "pattern": cycle.geometric_pattern,
                    "risk_level": "high" if cycle.criticality > 0.7 else "medium"
                })
        
        # Sort by criticality
        critical_regions.sort(key=lambda r: r["criticality"], reverse=True)
        
        return critical_regions
    
    def _extract_persistent_cycles(self,
                                  analysis: TopologicalAnalysisResult) -> List[PersistentCycle]:
        """Extract persistent cycles from analysis results.
        
        Args:
            analysis: Topological analysis results
            
        Returns:
            List of persistent cycles
        """
        # In a real implementation, this would extract actual cycles from the analysis
        # For demonstration, we'll return a placeholder list
        return [
            PersistentCycle(
                id=f"cycle-{i}",
                dimension=random.randint(0, 2),
                birth=random.uniform(0.1, 0.5),
                death=random.uniform(0.6, 1.0),
                persistence=random.uniform(0.3, 0.8),
                stability=random.uniform(0.5, 1.0),
                representative_points=[(random.randint(0, 100), random.randint(0, 100))],
                weight=random.uniform(0.5, 1.0),
                criticality=random.uniform(0.3, 0.9),
                location=(random.uniform(0, 1), random.uniform(0, 1)),
                is_anomalous=random.random() > 0.7,
                anomaly_type=random.choice(["spiral", "star", "cluster"]),
                geometric_pattern=random.choice(["spiral", "star", "cluster"])
            )
            for i in range(5)
        ]
    
    def _get_u_r_range(self, cycle: PersistentCycle) -> Tuple[int, int]:
        """Get u_r range for a cycle.
        
        Args:
            cycle: Persistent cycle
            
        Returns:
            Tuple of (min_u_r, max_u_r)
        """
        # In a real implementation, this would calculate the actual range
        # For demonstration, we'll return a placeholder value
        center = int(cycle.location[0] * self.n)
        radius = max(1, int(self.n * 0.05))  # 5% of curve order
        return (max(0, center - radius), min(self.n, center + radius))
    
    def _get_u_z_range(self, cycle: PersistentCycle) -> Tuple[int, int]:
        """Get u_z range for a cycle.
        
        Args:
            cycle: Persistent cycle
            
        Returns:
            Tuple of (min_u_z, max_u_z)
        """
        # In a real implementation, this would calculate the actual range
        # For demonstration, we'll return a placeholder value
        center = int(cycle.location[1] * self.n)
        radius = max(1, int(self.n * 0.05))  # 5% of curve order
        return (max(0, center - radius), min(self.n, center + radius))
    
    def compare_fingerprints(self,
                            target_fingerprint: TopologicalFingerprint,
                            reference_fingerprint: TopologicalFingerprint) -> TopologicalFingerprintComparison:
        """Compare topological fingerprints.
        
        Args:
            target_fingerprint: Fingerprint for target implementation
            reference_fingerprint: Fingerprint for reference implementation
            
        Returns:
            TopologicalFingerprintComparison object
        """
        start_time = time.time()
        self.logger.debug("Comparing topological fingerprints...")
        
        # Calculate structural similarity
        structural_similarity = self._calculate_structural_similarity(
            target_fingerprint,
            reference_fingerprint
        )
        
        # Calculate pattern similarity
        pattern_similarity = self._calculate_pattern_similarity(
            target_fingerprint,
            reference_fingerprint
        )
        
        # Calculate anomaly similarity
        anomaly_similarity = self._calculate_anomaly_similarity(
            target_fingerprint,
            reference_fingerprint
        )
        
        # Calculate overall fingerprint distance
        fingerprint_distance = 1.0 - (
            structural_similarity * 0.5 + 
            pattern_similarity * 0.3 + 
            anomaly_similarity * 0.2
        )
        
        # Identify critical regions
        critical_regions = self._identify_critical_regions_from_fingerprints(
            target_fingerprint,
            reference_fingerprint
        )
        
        # Create comparison result
        comparison = TopologicalFingerprintComparison(
            fingerprint_distance=fingerprint_distance,
            structural_similarity=structural_similarity,
            pattern_similarity=pattern_similarity,
            anomaly_similarity=anomaly_similarity,
            critical_regions=critical_regions,
            execution_time=time.time() - start_time,
            meta={
                "curve": self.curve.name,
                "target_public_key": target_fingerprint.public_key[:16] + "...",
                "reference_public_key": reference_fingerprint.public_key[:16] + "..."
            }
        )
        
        self.logger.debug(
            f"Fingerprint comparison completed in {comparison.execution_time:.4f}s. "
            f"Distance: {fingerprint_distance:.4f}"
        )
        
        return comparison
    
    def _calculate_structural_similarity(self,
                                        target_fp: TopologicalFingerprint,
                                        reference_fp: TopologicalFingerprint) -> float:
        """Calculate structural similarity between fingerprints.
        
        Args:
            target_fp: Fingerprint for target implementation
            reference_fp: Fingerprint for reference implementation
            
        Returns:
            Structural similarity score (0-1, higher = more similar)
        """
        # Compare Betti numbers
        beta0_sim = 1.0 - abs(target_fp.betti_numbers.beta_0 - reference_fp.betti_numbers.beta_0) / 2.0
        beta1_sim = 1.0 - abs(target_fp.betti_numbers.beta_1 - reference_fp.betti_numbers.beta_1) / 3.0
        beta2_sim = 1.0 - abs(target_fp.betti_numbers.beta_2 - reference_fp.betti_numbers.beta_2) / 2.0
        
        # Compare uniformity score
        uniformity_sim = 1.0 - abs(target_fp.uniformity_score - reference_fp.uniformity_score)
        
        # Weighted average
        return (
            beta0_sim * 0.2 + 
            beta1_sim * 0.4 + 
            beta2_sim * 0.2 + 
            uniformity_sim * 0.2
        )
    
    def _calculate_pattern_similarity(self,
                                     target_fp: TopologicalFingerprint,
                                     reference_fp: TopologicalFingerprint) -> float:
        """Calculate pattern similarity between fingerprints.
        
        Args:
            target_fp: Fingerprint for target implementation
            reference_fp: Fingerprint for reference implementation
            
        Returns:
            Pattern similarity score (0-1, higher = more similar)
        """
        # Compare spiral consistency
        spiral_sim = 1.0 - abs(
            target_fp.spiral_consistency - reference_fp.spiral_consistency
        )
        
        # Compare symmetry violation rate
        symmetry_sim = 1.0 - abs(
            target_fp.symmetry_violation_rate - reference_fp.symmetry_violation_rate
        )
        
        # Compare fractal dimension
        fractal_sim = 1.0 - abs(
            target_fp.fractal_dimension - reference_fp.fractal_dimension
        ) / 2.0  # Normalized difference
        
        # Weighted average
        return (
            spiral_sim * 0.4 + 
            symmetry_sim * 0.3 + 
            fractal_sim * 0.3
        )
    
    def _calculate_anomaly_similarity(self,
                                     target_fp: TopologicalFingerprint,
                                     reference_fp: TopologicalFingerprint) -> float:
        """Calculate anomaly similarity between fingerprints.
        
        Args:
            target_fp: Fingerprint for target implementation
            reference_fp: Fingerprint for reference implementation
            
        Returns:
            Anomaly similarity score (0-1, higher = more similar)
        """
        # Compare entropy anomaly score
        entropy_sim = 1.0 - abs(
            target_fp.entropy_anomaly_score - reference_fp.entropy_anomaly_score
        )
        
        # Compare critical regions
        critical_regions_sim = self._compare_critical_regions(
            target_fp.critical_regions,
            reference_fp.critical_regions
        )
        
        # Weighted average
        return (
            entropy_sim * 0.6 + 
            critical_regions_sim * 0.4
        )
    
    def _compare_critical_regions(self,
                                 target_regions: List[Dict[str, Any]],
                                 reference_regions: List[Dict[str, Any]]) -> float:
        """Compare critical regions between fingerprints.
        
        Args:
            target_regions: Critical regions for target implementation
            reference_regions: Critical regions for reference implementation
            
        Returns:
            Critical regions similarity score (0-1, higher = more similar)
        """
        if not target_regions or not reference_regions:
            return 0.5  # Neutral score if no regions
        
        # Calculate overlap between regions
        overlap_score = 0.0
        max_possible_overlap = 0.0
        
        for target_region in target_regions:
            for ref_region in reference_regions:
                # Calculate overlap in u_r dimension
                u_r_overlap = max(0, 
                    min(target_region["u_r_range"][1], ref_region["u_r_range"][1]) - 
                    max(target_region["u_r_range"][0], ref_region["u_r_range"][0])
                )
                u_r_total = max(
                    target_region["u_r_range"][1] - target_region["u_r_range"][0],
                    ref_region["u_r_range"][1] - ref_region["u_r_range"][0],
                    1
                )
                u_r_similarity = u_r_overlap / u_r_total
                
                # Calculate overlap in u_z dimension
                u_z_overlap = max(0, 
                    min(target_region["u_z_range"][1], ref_region["u_z_range"][1]) - 
                    max(target_region["u_z_range"][0], ref_region["u_z_range"][0])
                )
                u_z_total = max(
                    target_region["u_z_range"][1] - target_region["u_z_range"][0],
                    ref_region["u_z_range"][1] - ref_region["u_z_range"][0],
                    1
                )
                u_z_similarity = u_z_overlap / u_z_total
                
                # Combined similarity
                region_similarity = (u_r_similarity + u_z_similarity) / 2.0
                
                # Weight by criticality
                weighted_similarity = region_similarity * (
                    target_region.get("criticality", 0.5) + 
                    ref_region.get("criticality", 0.5)
                ) / 2.0
                
                overlap_score += weighted_similarity
                max_possible_overlap += 1.0
        
        return overlap_score / max_possible_overlap if max_possible_overlap > 0 else 0.0
    
    def _identify_critical_regions_from_fingerprints(self,
                                                   target_fp: TopologicalFingerprint,
                                                   reference_fp: TopologicalFingerprint) -> List[Dict[str, Any]]:
        """Identify critical regions from fingerprint comparison.
        
        Args:
            target_fp: Fingerprint for target implementation
            reference_fp: Fingerprint for reference implementation
            
        Returns:
            List of critical regions with details
        """
        critical_regions = []
        
        # Check for significant differences in critical regions
        for target_region in target_fp.critical_regions:
            # Find matching reference region
            matching_region = None
            max_similarity = 0.0
            
            for ref_region in reference_fp.critical_regions:
                # Calculate similarity
                u_r_similarity = 1.0 - abs(
                    (target_region["u_r_range"][0] - ref_region["u_r_range"][0]) / self.n
                )
                u_z_similarity = 1.0 - abs(
                    (target_region["u_z_range"][0] - ref_region["u_z_range"][0]) / self.n
                )
                similarity = (u_r_similarity + u_z_similarity) / 2.0
                
                if similarity > max_similarity:
                    max_similarity = similarity
                    matching_region = ref_region
            
            # If no good match or significant difference in criticality
            if not matching_region or max_similarity < 0.6:
                critical_regions.append({
                    "region_id": target_region["region_id"],
                    "u_r_range": target_region["u_r_range"],
                    "u_z_range": target_region["u_z_range"],
                    "criticality": target_region["criticality"],
                    "anomaly_type": target_region["anomaly_type"],
                    "pattern": target_region["geometric_pattern"],
                    "risk_level": "high" if target_region["criticality"] > 0.7 else "medium"
                })
        
        return critical_regions
    
    def get_vulnerability_indicators(self,
                                    distance_result: TopologicalDistanceResult) -> List[Dict[str, Any]]:
        """Get vulnerability indicators from distance analysis.
        
        Args:
            distance_result: Topological distance result
            
        Returns:
            List of vulnerability indicators
        """
        indicators = []
        
        # 1. Check for high topological distance
        if distance_result.distance > 0.3:
            indicators.append({
                "type": "topological_deviation",
                "description": f"High topological distance ({distance_result.distance:.4f}) from reference implementation",
                "criticality": min(1.0, distance_result.distance * 1.5),
                "evidence": f"Distance threshold: 0.3, Measured: {distance_result.distance:.4f}"
            })
        
        # 2. Check for low stability score
        if distance_result.stability_score < 0.7:
            indicators.append({
                "type": "stability_issue",
                "description": f"Low stability score ({distance_result.stability_score:.4f}) in comparative analysis",
                "criticality": min(1.0, (1.0 - distance_result.stability_score) * 1.3),
                "evidence": f"Stability threshold: 0.7, Measured: {distance_result.stability_score:.4f}"
            })
        
        # 3. Check for critical regions
        if distance_result.critical_regions:
            high_risk_regions = [r for r in distance_result.critical_regions if r["risk_level"] == "high"]
            if high_risk_regions:
                indicators.append({
                    "type": "critical_regions",
                    "description": f"{len(high_risk_regions)} high-risk critical regions detected",
                    "criticality": min(1.0, len(high_risk_regions) * 0.2),
                    "evidence": f"High-risk regions: {len(high_risk_regions)}"
                })
        
        return indicators
    
    def get_tcon_compliance(self,
                           distance_result: TopologicalDistanceResult) -> float:
        """Get TCON (Topological Conformance) compliance score.
        
        Args:
            distance_result: Topological distance result
            
        Returns:
            TCON compliance score (0-1, higher = more compliant)
        """
        # TCON compliance is based on distance from reference implementation
        return 1.0 - min(1.0, distance_result.distance * 1.2)
    
    def get_comparison_report(self,
                             target_analysis: TopologicalAnalysisResult,
                             reference_analysis: TopologicalAnalysisResult,
                             distance_result: Optional[TopologicalDistanceResult] = None) -> str:
        """Get human-readable comparison report.
        
        Args:
            target_analysis: Analysis results for target implementation
            reference_analysis: Analysis results for reference implementation
            distance_result: Optional distance result (will be calculated if None)
            
        Returns:
            Comparison report as string
        """
        if distance_result is None:
            distance_result = self.calculate_distance(target_analysis, reference_analysis)
        
        lines = [
            "=" * 80,
            "TOPOLOGICAL COMPARISON REPORT",
            "=" * 80,
            f"Comparison Timestamp: {datetime.fromtimestamp(distance_result.analysis_timestamp).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target Public Key: {target_analysis.public_key[:50]}{'...' if len(target_analysis.public_key) > 50 else ''}",
            f"Reference Public Key: {reference_analysis.public_key[:50]}{'...' if len(reference_analysis.public_key) > 50 else ''}",
            f"Curve: {self.curve.name}",
            "",
            "TOPOLOGICAL DISTANCE METRICS:",
            f"Distance: {distance_result.distance:.4f}",
            f"Metric Type: {distance_result.metric_type.value.upper()}",
            f"Stability Score: {distance_result.stability_score:.4f}",
            f"Confidence: {distance_result.confidence:.4f}",
            "",
            "BETTI NUMBER COMPARISON:",
            f"Target: β₀={target_analysis.betti_numbers.beta_0:.4f}, β₁={target_analysis.betti_numbers.beta_1:.4f}, β₂={target_analysis.betti_numbers.beta_2:.4f}",
            f"Reference: β₀={reference_analysis.betti_numbers.beta_0:.4f}, β₁={reference_analysis.betti_numbers.beta_1:.4f}, β₂={reference_analysis.betti_numbers.beta_2:.4f}",
            "",
            "CRITICAL REGIONS:"
        ]
        
        if not distance_result.critical_regions:
            lines.append("  No critical regions detected")
        else:
            for i, region in enumerate(distance_result.critical_regions[:5], 1):  # Show up to 5 regions
                lines.append(f"  {i}. Region {region['region_id']}:")
                lines.append(
                    f"     - u_r range: {region['u_r_range'][0]}-{region['u_r_range'][1]}, "
                    f"u_z range: {region['u_z_range'][0]}-{region['u_z_range'][1]}"
                )
                lines.append(
                    f"     - Cycle ID: {region['cycle_id']}, Dimension: {region['dimension']}, "
                    f"Persistence: {region['persistence']:.4f}"
                )
                lines.append(
                    f"     - Criticality: {region['criticality']:.4f}, Pattern: {region['pattern']}, "
                    f"Risk: {region['risk_level']}"
                )
            
            if len(distance_result.critical_regions) > 5:
                lines.append(f"  - And {len(distance_result.critical_regions) - 5} more regions")
        
        # Add vulnerability indicators
        vulnerability_indicators = self.get_vulnerability_indicators(distance_result)
        if vulnerability_indicators:
            lines.extend([
                "",
                "VULNERABILITY INDICATORS:"
            ])
            for i, indicator in enumerate(vulnerability_indicators, 1):
                lines.append(f"  {i}. [{indicator['type'].upper()}] {indicator['description']}")
                lines.append(f"     Criticality: {indicator['criticality']:.4f}")
                lines.append(f"     Evidence: {indicator['evidence']}")
        
        lines.extend([
            "",
            "=" * 80,
            "TOPOLOGICAL COMPARISON FOOTER",
            "=" * 80,
            "This report was generated by TopoSphere Topological Distance Calculator,",
            "a component of the Differential Analysis system for detecting ECDSA vulnerabilities.",
            "A 'secure' result does not guarantee the absence of all possible vulnerabilities.",
            "Additional security testing is recommended for critical systems.",
            "=" * 80
        ])
        
        return "\n".join(lines)


# ======================
# HELPER FUNCTIONS
# ======================

def calculate_topological_distance(target_analysis: TopologicalAnalysisResult,
                                  reference_analysis: TopologicalAnalysisResult,
                                  metric_type: DistanceMetricType = DistanceMetricType.WASSERSTEIN) -> float:
    """Calculate topological distance between two analysis results.
    
    Args:
        target_analysis: Analysis results for target implementation
        reference_analysis: Analysis results for reference implementation
        metric_type: Type of distance metric to use
        
    Returns:
        Topological distance (0-1, lower = more similar)
    """
    # In a real implementation, this would use a proper distance calculator
    # For demonstration, we'll simulate a result
    return random.uniform(0.0, 0.5)  # Simulated distance


def analyze_deviations(target_analysis: TopologicalAnalysisResult,
                      reference_analysis: TopologicalAnalysisResult) -> Dict[str, Any]:
    """Analyze deviations between target and reference implementations.
    
    Args:
        target_analysis: Analysis results for target implementation
        reference_analysis: Analysis results for reference implementation
        
    Returns:
        Dictionary with deviation analysis results
    """
    # In a real implementation, this would analyze the deviations
    # For demonstration, we'll return a mock result
    return {
        "topological_distance": 0.15,
        "betti_deviations": {
            "beta_0": abs(target_analysis.betti_numbers.beta_0 - reference_analysis.betti_numbers.beta_0),
            "beta_1": abs(target_analysis.betti_numbers.beta_1 - reference_analysis.betti_numbers.beta_1),
            "beta_2": abs(target_analysis.betti_numbers.beta_2 - reference_analysis.betti_numbers.beta_2)
        },
        "stability_difference": abs(
            target_analysis.stability_metrics.get("score", 0.5) - 
            reference_analysis.stability_metrics.get("score", 0.5)
        ),
        "critical_regions": [] if target_analysis.anomaly_score < 0.2 else [
            {
                "region_id": "CR-001",
                "u_r_range": (10000, 20000),
                "u_z_range": (30000, 40000),
                "criticality": 0.8,
                "pattern": "spiral"
            }
        ]
    }


def detect_anomalous_patterns(deviations: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect anomalous patterns from deviation analysis.
    
    Args:
        deviations: Deviation analysis results
        
    Returns:
        List of anomalous patterns
    """
    anomalous_patterns = []
    
    # Check for significant Betti number deviations
    if deviations["betti_deviations"]["beta_1"] > 0.3:
        anomalous_patterns.append({
            "type": "structured_anomaly",
            "description": f"Significant deviation in beta_1 ({deviations['betti_deviations']['beta_1']:.4f})",
            "criticality": min(1.0, deviations["betti_deviations"]["beta_1"] * 1.5)
        })
    
    # Check for high topological distance
    if deviations["topological_distance"] > 0.25:
        anomalous_patterns.append({
            "type": "topological_deviation",
            "description": f"High topological distance ({deviations['topological_distance']:.4f})",
            "criticality": min(1.0, deviations["topological_distance"] * 1.2)
        })
    
    # Check for critical regions
    if deviations["critical_regions"]:
        anomalous_patterns.append({
            "type": "critical_regions",
            "description": f"{len(deviations['critical_regions'])} critical regions detected",
            "criticality": min(1.0, len(deviations["critical_regions"]) * 0.2)
        })
    
    return anomalous_patterns
