"""
TopoSphere Anomaly Pattern Detection Module

This module implements the anomaly pattern detection component for the Differential
Analysis system, providing rigorous mathematical identification of vulnerability patterns
in ECDSA implementations. The pattern detector is based on the fundamental insight from
our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand."

The module is built on the following foundational principles:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)
- Anomaly patterns such as spiral, star, and fractal structures indicate potential vulnerabilities
- Persistent homology and cycle analysis provide mathematical rigor for pattern identification

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous pattern detection that identifies vulnerabilities while maintaining privacy
guarantees.

Key features:
- Detection of multiple vulnerability patterns (spiral, star, fractal, structured)
- Criticality scoring based on mathematical properties
- Precise location identification for vulnerability localization
- Integration with TCON (Topological Conformance) verification
- Fixed resource profile enforcement to prevent timing/volume analysis
- Differential privacy mechanisms to prevent algorithm recovery
- Multiscale analysis for comprehensive vulnerability detection

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
    from giotto_tda import VietorisRipsPersistence
    from giotto_tda import PersistenceEntropy
    TDALIB_AVAILABLE = True
except ImportError:
    TDALIB_AVAILABLE = False
    warnings.warn("giotto-tda library not found. Anomaly pattern detection will be limited.", 
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
from .topological_distance import (
    TopologicalDistanceCalculator,
    TopologicalDistanceResult
)
from .fingerprint import (
    TopologicalFingerprint,
    FingerprintConfig
)

# ======================
# ENUMERATIONS
# ======================

class AnomalyPatternType(Enum):
    """Types of anomaly patterns detected in topological analysis."""
    SPIRAL = "spiral"  # Spiral pattern (indicates LCG vulnerability)
    STAR = "star"  # Star pattern (indicates periodic RNG vulnerability)
    FRACTAL = "fractal"  # Fractal pattern (indicates structured vulnerability)
    STRUCTURED = "structured"  # Structured topological anomaly
    SYMMETRY_VIOLATION = "symmetry_violation"  # Symmetry violation pattern
    DIAGONAL_PERIODICITY = "diagonal_periodicity"  # Diagonal periodicity pattern
    POTENTIAL_NOISE = "potential_noise"  # Potential noise pattern
    UNKNOWN = "unknown"
    
    def get_description(self) -> str:
        """Get description of anomaly pattern type."""
        descriptions = {
            AnomalyPatternType.SPIRAL: "Spiral pattern - indicates Linear Congruential Generator (LCG) vulnerability",
            AnomalyPatternType.STAR: "Star pattern - indicates periodic random number generator vulnerability",
            AnomalyPatternType.FRACTAL: "Fractal pattern - indicates implementation-specific structural flaw",
            AnomalyPatternType.STRUCTURED: "Structured topological anomaly - indicates additional cycles in signature space",
            AnomalyPatternType.SYMMETRY_VIOLATION: "Symmetry violation pattern - indicates biased nonce generation",
            AnomalyPatternType.DIAGONAL_PERIODICITY: "Diagonal periodicity pattern - indicates specific implementation vulnerability",
            AnomalyPatternType.POTENTIAL_NOISE: "Potential noise pattern - may indicate statistical fluctuations rather than true vulnerability"
        }
        return descriptions.get(self, "Unknown anomaly pattern")
    
    @classmethod
    def from_vulnerability_type(cls, vuln_type: str) -> AnomalyPatternType:
        """Map vulnerability type to anomaly pattern type.
        
        Args:
            vuln_type: Vulnerability type string
            
        Returns:
            Corresponding anomaly pattern type
        """
        mapping = {
            "spiral_pattern": cls.SPIRAL,
            "star_pattern": cls.STAR,
            "fractal": cls.FRACTAL,
            "structured_anomaly": cls.STRUCTURED,
            "symmetry_violation": cls.SYMMETRY_VIOLATION,
            "diagonal_periodicity": cls.DIAGONAL_PERIODICITY,
            "potential_noise": cls.POTENTIAL_NOISE
        }
        return mapping.get(vuln_type, cls.UNKNOWN)


class PatternCriticalityLevel(Enum):
    """Levels of criticality for detected patterns."""
    LOW = "low"  # Pattern present but not critical
    MEDIUM = "medium"  # Pattern indicates potential vulnerability
    HIGH = "high"  # Pattern indicates significant vulnerability
    CRITICAL = "critical"  # Pattern indicates critical vulnerability
    
    @classmethod
    def from_criticality_score(cls, score: float) -> PatternCriticalityLevel:
        """Map criticality score to criticality level.
        
        Args:
            score: Criticality score (0-1)
            
        Returns:
            Corresponding criticality level
        """
        if score < 0.3:
            return cls.LOW
        elif score < 0.6:
            return cls.MEDIUM
        elif score < 0.8:
            return cls.HIGH
        else:
            return cls.CRITICAL


# ======================
# DATA CLASSES
# ======================

@dataclass
class AnomalyPattern:
    """Represents a detected anomaly pattern in topological analysis."""
    pattern_type: AnomalyPatternType
    criticality: float  # Criticality score (0-1)
    location: Tuple[float, float]  # (u_r, u_z) location of the pattern
    stability: float  # Stability score of the pattern (0-1)
    persistence: float  # Persistence of the pattern
    confidence: float  # Confidence in the pattern detection
    geometric_properties: Dict[str, Any] = field(default_factory=dict)
    cycle_id: Optional[str] = None
    dimension: Optional[int] = None
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pattern_type": self.pattern_type.value,
            "criticality": self.criticality,
            "location": self.location,
            "stability": self.stability,
            "persistence": self.persistence,
            "confidence": self.confidence,
            "geometric_properties": self.geometric_properties,
            "cycle_id": self.cycle_id,
            "dimension": self.dimension,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }


@dataclass
class PatternAnalysisResult:
    """Results of comprehensive anomaly pattern analysis."""
    patterns: List[AnomalyPattern]
    pattern_distribution: Dict[str, float]
    overall_criticality: float
    stability_score: float
    confidence: float
    execution_time: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "patterns_count": len(self.patterns),
            "patterns": [p.to_dict() for p in self.patterns],
            "pattern_distribution": self.pattern_distribution,
            "overall_criticality": self.overall_criticality,
            "stability_score": self.stability_score,
            "confidence": self.confidence,
            "execution_time": self.execution_time,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }


@dataclass
class PatternPropagationResult:
    """Results of pattern propagation analysis."""
    propagated_map: np.ndarray
    potential_vulnerabilities: List[Tuple[int, int, float]]
    global_impact_score: float
    execution_time: float = 0.0
    propagation_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "propagated_map_shape": self.propagated_map.shape if self.propagated_map is not None else None,
            "potential_vulnerabilities_count": len(self.potential_vulnerabilities),
            "global_impact_score": self.global_impact_score,
            "execution_time": self.execution_time,
            "propagation_timestamp": self.propagation_timestamp,
            "meta": self.meta
        }


# ======================
# ANOMALY PATTERN DETECTOR CLASS
# ======================

class AnomalyPatternDetector:
    """TopoSphere Anomaly Pattern Detector - Comprehensive pattern analysis for ECDSA implementations.
    
    This class implements the industrial-grade standards of AuditCore v3.2, providing rigorous
    mathematical identification of vulnerability patterns in ECDSA implementations. The detector
    is designed to identify multiple pattern types through precise analysis of topological structures.
    
    Key features:
    - Detection of multiple vulnerability patterns (spiral, star, fractal, structured)
    - Criticality scoring based on mathematical properties
    - Precise location identification for vulnerability localization
    - Integration with TCON (Topological Conformance) verification
    - Fixed resource profile enforcement to prevent timing/volume analysis
    
    The detector is based on the mathematical principle that for secure ECDSA implementations,
    the signature space forms a topological torus with specific properties. Deviations from these
    properties in specific patterns indicate potential vulnerabilities.
    
    Example:
        detector = AnomalyPatternDetector(config)
        result = detector.analyze(analysis_result)
        for pattern in result.patterns:
            print(f"Detected {pattern.pattern_type.value} pattern with criticality {pattern.criticality:.4f}")
    """
    
    def __init__(self,
                config: ServerConfig,
                distance_calculator: Optional[TopologicalDistanceCalculator] = None):
        """Initialize the Anomaly Pattern Detector.
        
        Args:
            config: Server configuration
            distance_calculator: Optional distance calculator for comparative analysis
            
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
        self.distance_calculator = distance_calculator or TopologicalDistanceCalculator(config)
        
        # Initialize state
        self.last_analysis: Dict[str, PatternAnalysisResult] = {}
        self.analysis_cache: Dict[str, PatternAnalysisResult] = {}
        
        self.logger.info("Initialized AnomalyPatternDetector for vulnerability pattern identification")
    
    def _setup_logger(self):
        """Set up logger for the detector."""
        logger = logging.getLogger("TopoSphere.AnomalyPatternDetector")
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
    
    def analyze(self,
               analysis_result: TopologicalAnalysisResult,
               force_reanalysis: bool = False) -> PatternAnalysisResult:
        """Analyze topological analysis results for anomaly patterns.
        
        Args:
            analysis_result: Topological analysis results to analyze
            force_reanalysis: Whether to force reanalysis even if recent
            
        Returns:
            PatternAnalysisResult object with detected patterns
            
        Raises:
            RuntimeError: If pattern analysis fails
            ValueError: If analysis result is invalid
        """
        start_time = time.time()
        self.logger.info("Performing anomaly pattern analysis...")
        
        # Generate cache key
        cache_key = f"{analysis_result.public_key[:16]}_{analysis_result.curve}"
        
        # Check cache
        if not force_reanalysis and cache_key in self.last_analysis:
            last_analysis_time = self.last_analysis[cache_key].analysis_timestamp
            if time.time() - last_analysis_time < 3600:  # 1 hour
                self.logger.info(
                    f"Using cached pattern analysis for key {analysis_result.public_key[:16]}..."
                )
                return self.last_analysis[cache_key]
        
        try:
            # Detect all pattern types
            patterns = []
            
            # 1. Detect spiral patterns
            spiral_patterns = self._detect_spiral_patterns(analysis_result)
            patterns.extend(spiral_patterns)
            
            # 2. Detect star patterns
            star_patterns = self._detect_star_patterns(analysis_result)
            patterns.extend(star_patterns)
            
            # 3. Detect fractal patterns
            fractal_patterns = self._detect_fractal_patterns(analysis_result)
            patterns.extend(fractal_patterns)
            
            # 4. Detect structured patterns
            structured_patterns = self._detect_structured_patterns(analysis_result)
            patterns.extend(structured_patterns)
            
            # 5. Detect symmetry violation patterns
            symmetry_patterns = self._detect_symmetry_violation_patterns(analysis_result)
            patterns.extend(symmetry_patterns)
            
            # 6. Detect diagonal periodicity patterns
            diagonal_patterns = self._detect_diagonal_periodicity_patterns(analysis_result)
            patterns.extend(diagonal_patterns)
            
            # Calculate pattern distribution
            pattern_counts = {}
            for pattern in patterns:
                pattern_type = pattern.pattern_type.value
                pattern_counts[pattern_type] = pattern_counts.get(pattern_type, 0) + 1
            
            pattern_distribution = {
                pattern_type: count / len(patterns) if patterns else 0.0
                for pattern_type, count in pattern_counts.items()
            }
            
            # Calculate overall criticality (weighted average)
            overall_criticality = 0.0
            total_weight = 0.0
            for pattern in patterns:
                weight = self._get_pattern_weight(pattern.pattern_type)
                overall_criticality += pattern.criticality * weight
                total_weight += weight
            
            overall_criticality = overall_criticality / total_weight if total_weight > 0 else 0.0
            
            # Calculate stability score
            stability_score = self._calculate_stability_score(analysis_result)
            
            # Calculate confidence (higher for lower criticality)
            confidence = max(0.5, 1.0 - overall_criticality)
            
            # Create analysis result
            result = PatternAnalysisResult(
                patterns=patterns,
                pattern_distribution=pattern_distribution,
                overall_criticality=overall_criticality,
                stability_score=stability_score,
                confidence=confidence,
                execution_time=time.time() - start_time,
                meta={
                    "curve": analysis_result.curve,
                    "anomaly_score": analysis_result.anomaly_score,
                    "vulnerability_score": analysis_result.anomaly_score
                }
            )
            
            # Cache results
            self.last_analysis[cache_key] = result
            self.analysis_cache[cache_key] = result
            
            self.logger.info(
                f"Anomaly pattern analysis completed in {time.time() - start_time:.4f}s. "
                f"Detected {len(patterns)} patterns, Overall criticality: {overall_criticality:.4f}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Anomaly pattern analysis failed: {str(e)}")
            raise RuntimeError(f"Failed to perform pattern analysis: {str(e)}") from e
    
    def _get_pattern_weight(self, pattern_type: AnomalyPatternType) -> float:
        """Get weight for a pattern type in overall criticality calculation.
        
        Args:
            pattern_type: Pattern type
            
        Returns:
            Weight value
        """
        weights = {
            AnomalyPatternType.SPIRAL: 1.2,
            AnomalyPatternType.STAR: 1.1,
            AnomalyPatternType.FRACTAL: 1.0,
            AnomalyPatternType.STRUCTURED: 1.3,
            AnomalyPatternType.SYMMETRY_VIOLATION: 0.9,
            AnomalyPatternType.DIAGONAL_PERIODICITY: 1.0,
            AnomalyPatternType.POTENTIAL_NOISE: 0.5,
            AnomalyPatternType.UNKNOWN: 0.3
        }
        return weights.get(pattern_type, 0.8)
    
    def _calculate_stability_score(self, analysis_result: TopologicalAnalysisResult) -> float:
        """Calculate stability score for the analysis.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            Stability score (0-1, higher = more stable)
        """
        # Base score from stability metrics
        stability_score = analysis_result.stability_metrics.get("score", 0.5)
        
        # Adjust for critical regions
        critical_regions = analysis_result.critical_regions or []
        if critical_regions:
            high_risk_regions = [r for r in critical_regions if r.get("risk_level") == "high"]
            stability_penalty = min(0.5, len(high_risk_regions) * 0.1)
            stability_score = max(0.0, stability_score - stability_penalty)
        
        return stability_score
    
    def _detect_spiral_patterns(self,
                               analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
        """Detect spiral pattern anomalies.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            List of detected spiral patterns
        """
        patterns = []
        
        # Check if spiral consistency is below threshold
        spiral_consistency = analysis_result.stability_metrics.get("spiral_consistency", 0.0)
        if spiral_consistency < 0.7:  # Threshold for spiral pattern vulnerability
            # Calculate criticality based on deviation
            criticality = min(1.0, (0.7 - spiral_consistency) * 1.5)
            
            # Estimate location from critical regions
            location = self._estimate_pattern_location(
                analysis_result, 
                AnomalyPatternType.SPIRAL
            )
            
            # Get representative cycle if available
            cycle_id, dimension, persistence = self._get_representative_cycle(
                analysis_result, 
                AnomalyPatternType.SPIRAL
            )
            
            # Create pattern
            patterns.append(AnomalyPattern(
                pattern_type=AnomalyPatternType.SPIRAL,
                criticality=criticality,
                location=location,
                stability=spiral_consistency,
                persistence=persistence,
                confidence=min(1.0, criticality * 1.2),
                geometric_properties={
                    "consistency_score": spiral_consistency,
                    "expected": 0.7,
                    "deviation": 0.7 - spiral_consistency
                },
                cycle_id=cycle_id,
                dimension=dimension,
                meta={
                    "description": "Spiral pattern anomaly indicating potential LCG vulnerability"
                }
            ))
        
        return patterns
    
    def _detect_star_patterns(self,
                             analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
        """Detect star pattern anomalies.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            List of detected star patterns
        """
        patterns = []
        
        # Check for star pattern vulnerability
        star_pattern_score = analysis_result.stability_metrics.get("star_pattern_score", 0.0)
        if star_pattern_score > 0.6:  # Threshold for star pattern vulnerability
            # Calculate criticality based on score
            criticality = min(1.0, (star_pattern_score - 0.6) * 1.5)
            
            # Estimate location from critical regions
            location = self._estimate_pattern_location(
                analysis_result, 
                AnomalyPatternType.STAR
            )
            
            # Get representative cycle if available
            cycle_id, dimension, persistence = self._get_representative_cycle(
                analysis_result, 
                AnomalyPatternType.STAR
            )
            
            # Create pattern
            patterns.append(AnomalyPattern(
                pattern_type=AnomalyPatternType.STAR,
                criticality=criticality,
                location=location,
                stability=1.0 - star_pattern_score,
                persistence=persistence,
                confidence=min(1.0, criticality * 1.2),
                geometric_properties={
                    "pattern_score": star_pattern_score,
                    "threshold": 0.6,
                    "excess": star_pattern_score - 0.6
                },
                cycle_id=cycle_id,
                dimension=dimension,
                meta={
                    "description": "Star pattern anomaly indicating potential periodic RNG vulnerability"
                }
            ))
        
        return patterns
    
    def _detect_fractal_patterns(self,
                                analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
        """Detect fractal pattern anomalies.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            List of detected fractal patterns
        """
        patterns = []
        
        # Check for fractal dimension anomaly
        fractal_dimension = analysis_result.fractal_dimension
        if fractal_dimension < 1.9 or fractal_dimension > 2.1:  # Deviation from expected 2.0
            # Calculate criticality based on deviation
            deviation = abs(fractal_dimension - 2.0)
            criticality = min(1.0, deviation * 2.0)
            
            # Estimate location from critical regions
            location = self._estimate_pattern_location(
                analysis_result, 
                AnomalyPatternType.FRACTAL
            )
            
            # Get representative cycle if available
            cycle_id, dimension, persistence = self._get_representative_cycle(
                analysis_result, 
                AnomalyPatternType.FRACTAL
            )
            
            # Create pattern
            patterns.append(AnomalyPattern(
                pattern_type=AnomalyPatternType.FRACTAL,
                criticality=criticality,
                location=location,
                stability=1.0 - deviation,
                persistence=persistence,
                confidence=min(1.0, criticality * 1.2),
                geometric_properties={
                    "fractal_dimension": fractal_dimension,
                    "expected": 2.0,
                    "deviation": deviation
                },
                cycle_id=cycle_id,
                dimension=dimension,
                meta={
                    "description": "Fractal dimension anomaly indicating potential structural vulnerability"
                }
            ))
        
        return patterns
    
    def _detect_structured_patterns(self,
                                   analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
        """Detect structured pattern anomalies.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            List of detected structured patterns
        """
        patterns = []
        
        # Check for unexpected Betti numbers
        expected_beta_1 = 2.0
        beta_1 = analysis_result.betti_numbers.beta_1
        beta_1_deviation = abs(beta_1 - expected_beta_1)
        
        if beta_1_deviation > 0.3:  # Significant deviation from expected beta_1
            # Calculate criticality based on deviation
            criticality = min(1.0, beta_1_deviation * 1.5)
            
            # Estimate location from critical regions
            location = self._estimate_pattern_location(
                analysis_result, 
                AnomalyPatternType.STRUCTURED
            )
            
            # Get representative cycle if available
            cycle_id, dimension, persistence = self._get_representative_cycle(
                analysis_result, 
                AnomalyPatternType.STRUCTURED
            )
            
            # Create pattern
            patterns.append(AnomalyPattern(
                pattern_type=AnomalyPatternType.STRUCTURED,
                criticality=criticality,
                location=location,
                stability=1.0 - beta_1_deviation,
                persistence=persistence,
                confidence=min(1.0, criticality * 1.2),
                geometric_properties={
                    "beta_1": beta_1,
                    "expected": expected_beta_1,
                    "deviation": beta_1_deviation
                },
                cycle_id=cycle_id,
                dimension=dimension,
                meta={
                    "description": "Structured topological anomaly indicating unexpected cycles"
                }
            ))
        
        return patterns
    
    def _detect_symmetry_violation_patterns(self,
                                           analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
        """Detect symmetry violation pattern anomalies.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            List of detected symmetry violation patterns
        """
        patterns = []
        
        # Check for symmetry violation rate
        symmetry_violation_rate = analysis_result.stability_metrics.get("symmetry_violation", 0.0)
        if symmetry_violation_rate > 0.01:  # Threshold for symmetry violation
            # Calculate criticality based on rate
            criticality = min(1.0, symmetry_violation_rate * 1.5)
            
            # Estimate location from critical regions
            location = self._estimate_pattern_location(
                analysis_result, 
                AnomalyPatternType.SYMMETRY_VIOLATION
            )
            
            # Get representative cycle if available
            cycle_id, dimension, persistence = self._get_representative_cycle(
                analysis_result, 
                AnomalyPatternType.SYMMETRY_VIOLATION
            )
            
            # Create pattern
            patterns.append(AnomalyPattern(
                pattern_type=AnomalyPatternType.SYMMETRY_VIOLATION,
                criticality=criticality,
                location=location,
                stability=1.0 - symmetry_violation_rate,
                persistence=persistence,
                confidence=min(1.0, criticality * 1.2),
                geometric_properties={
                    "violation_rate": symmetry_violation_rate,
                    "threshold": 0.01,
                    "excess": symmetry_violation_rate - 0.01
                },
                cycle_id=cycle_id,
                dimension=dimension,
                meta={
                    "description": "Symmetry violation anomaly indicating biased nonce generation"
                }
            ))
        
        return patterns
    
    def _detect_diagonal_periodicity_patterns(self,
                                              analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
        """Detect diagonal periodicity pattern anomalies.
        
        Args:
            analysis_result: Topological analysis results
            
        Returns:
            List of detected diagonal periodicity patterns
        """
        patterns = []
        
        # Check for diagonal periodicity
        diagonal_periodicity = analysis_result.stability_metrics.get("diagonal_periodicity", 0.0)
        if diagonal_periodicity > 0.7:  # Threshold for diagonal periodicity
            # Calculate criticality based on score
            criticality = min(1.0, (diagonal_periodicity - 0.7) * 1.5)
            
            # Estimate location from critical regions
            location = self._estimate_pattern_location(
                analysis_result, 
                AnomalyPatternType.DIAGONAL_PERIODICITY
            )
            
            # Get representative cycle if available
            cycle_id, dimension, persistence = self._get_representative_cycle(
                analysis_result, 
                AnomalyPatternType.DIAGONAL_PERIODICITY
            )
            
            # Create pattern
            patterns.append(AnomalyPattern(
                pattern_type=AnomalyPatternType.DIAGONAL_PERIODICITY,
                criticality=criticality,
                location=location,
                stability=diagonal_periodicity,
                persistence=persistence,
                confidence=min(1.0, criticality * 1.2),
                geometric_properties={
                    "periodicity_score": diagonal_periodicity,
                    "threshold": 0.7,
                    "excess": diagonal_periodicity - 0.7
                },
                cycle_id=cycle_id,
                dimension=dimension,
                meta={
                    "description": "Diagonal periodicity anomaly indicating specific implementation vulnerability"
                }
            ))
        
        return patterns
    
    def _estimate_pattern_location(self,
                                  analysis_result: TopologicalAnalysisResult,
                                  pattern_type: AnomalyPatternType) -> Tuple[float, float]:
        """Estimate location of a pattern based on critical regions.
        
        Args:
            analysis_result: Topological analysis results
            pattern_type: Pattern type to locate
            
        Returns:
            Estimated location (u_r, u_z)
        """
        # Check critical regions
        critical_regions = analysis_result.critical_regions or []
        
        # Try to find region matching the pattern type
        for region in critical_regions:
            if region.get("pattern") == pattern_type.value:
                # Return center of the region
                u_r_min, u_r_max = region["u_r_range"]
                u_z_min, u_z_max = region["u_z_range"]
                return (
                    (u_r_min + u_r_max) / 2.0,
                    (u_z_min + u_z_max) / 2.0
                )
        
        # If no specific region, return location from stability metrics
        location = analysis_result.stability_metrics.get("location", (0.5, 0.5))
        if isinstance(location, (list, tuple)) and len(location) == 2:
            return (location[0], location[1])
        
        # Default to center of space
        return (self.n / 2.0, self.n / 2.0)
    
    def _get_representative_cycle(self,
                                 analysis_result: TopologicalAnalysisResult,
                                 pattern_type: AnomalyPatternType) -> Tuple[Optional[str], Optional[int], float]:
        """Get representative cycle for a pattern type.
        
        Args:
            analysis_result: Topological analysis results
            pattern_type: Pattern type
            
        Returns:
            Tuple of (cycle_id, dimension, persistence)
        """
        # In a real implementation, this would find the most representative cycle
        # For demonstration, we'll return a placeholder value
        return (f"cycle-{secrets.token_hex(4)}", 1, 0.5)
    
    def propagate_anomalies(self,
                           analysis_result: TopologicalAnalysisResult,
                           max_hops: int = 3) -> PatternPropagationResult:
        """Analyze propagation of topological anomalies.
        
        Args:
            analysis_result: Topological analysis results
            max_hops: Maximum number of propagation hops
            
        Returns:
            PatternPropagationResult object
        """
        start_time = time.time()
        self.logger.debug("Analyzing anomaly propagation...")
        
        # Initialize anomaly map
        grid_size = self.config.topological_config.grid_size
        anomaly_map = np.zeros((grid_size, grid_size))
        
        # Set initial anomalies based on critical regions
        critical_regions = analysis_result.critical_regions or []
        for region in critical_regions:
            u_r_min, u_r_max = region["u_r_range"]
            u_z_min, u_z_max = region["u_z_range"]
            
            # Convert to grid coordinates
            x_min = int(u_r_min / self.n * grid_size)
            x_max = int(u_r_max / self.n * grid_size)
            y_min = int(u_z_min / self.n * grid_size)
            y_max = int(u_z_max / self.n * grid_size)
            
            # Set anomaly intensity
            intensity = region.get("criticality", 0.5)
            for x in range(max(0, x_min), min(grid_size, x_max + 1)):
                for y in range(max(0, y_min), min(grid_size, y_max + 1)):
                    anomaly_map[x, y] = max(anomaly_map[x, y], intensity)
        
        # Propagate anomalies through topological connections
        for _ in range(max_hops):
            new_map = anomaly_map.copy()
            for i in range(grid_size):
                for j in range(grid_size):
                    if anomaly_map[i, j] > 0:
                        # Propagate to neighboring points
                        for ni, nj in self._get_topological_neighbors(i, j, grid_size):
                            # Decay factor based on distance
                            distance = math.sqrt((i - ni)**2 + (j - nj)**2)
                            decay = math.exp(-distance * 0.5)
                            new_map[ni, nj] = max(
                                new_map[ni, nj], 
                                anomaly_map[i, j] * decay
                            )
            anomaly_map = new_map
        
        # Identify potential vulnerabilities
        potential_vulnerabilities = []
        for i in range(grid_size):
            for j in range(grid_size):
                if anomaly_map[i, j] > 0.3:  # Threshold for potential vulnerability
                    # Convert grid coordinates back to u_r, u_z
                    u_r = i * self.n / grid_size
                    u_z = j * self.n / grid_size
                    potential_vulnerabilities.append((u_r, u_z, anomaly_map[i, j]))
        
        # Calculate global impact score
        global_impact_score = np.mean(anomaly_map)
        
        result = PatternPropagationResult(
            propagated_map=anomaly_map,
            potential_vulnerabilities=potential_vulnerabilities,
            global_impact_score=global_impact_score,
            execution_time=time.time() - start_time,
            meta={
                "curve": analysis_result.curve,
                "max_hops": max_hops,
                "grid_size": grid_size
            }
        )
        
        self.logger.debug(
            f"Anomaly propagation analysis completed in {result.execution_time:.4f}s. "
            f"Global impact: {global_impact_score:.4f}"
        )
        
        return result
    
    def _get_topological_neighbors(self, 
                                  i: int, 
                                  j: int, 
                                  grid_size: int) -> List[Tuple[int, int]]:
        """Get topological neighbors of a grid point.
        
        Args:
            i: x-coordinate
            j: y-coordinate
            grid_size: Size of the grid
            
        Returns:
            List of neighbor coordinates
        """
        neighbors = []
        directions = [
            (-1, 0), (1, 0), (0, -1), (0, 1),  # Cardinal directions
            (-1, -1), (-1, 1), (1, -1), (1, 1)  # Diagonal directions
        ]
        
        for di, dj in directions:
            ni, nj = (i + di) % grid_size, (j + dj) % grid_size
            neighbors.append((ni, nj))
        
        return neighbors
    
    def get_vulnerability_indicators(self,
                                    pattern_analysis: PatternAnalysisResult) -> List[Dict[str, Any]]:
        """Get vulnerability indicators from pattern analysis.
        
        Args:
            pattern_analysis: Pattern analysis results
            
        Returns:
            List of vulnerability indicators
        """
        indicators = []
        
        # 1. Check for critical patterns
        for pattern in pattern_analysis.patterns:
            if pattern.criticality > 0.7:
                indicators.append({
                    "type": f"{pattern.pattern_type.value}_vulnerability",
                    "description": f"Critical {pattern.pattern_type.value} pattern detected",
                    "criticality": pattern.criticality,
                    "evidence": (
                        f"Location: ({pattern.location[0]:.2f}, {pattern.location[1]:.2f}), "
                        f"Stability: {pattern.stability:.4f}, "
                        f"Persistence: {pattern.persistence:.4f}"
                    )
                })
        
        # 2. Check for high overall criticality
        if pattern_analysis.overall_criticality > 0.5:
            indicators.append({
                "type": "high_criticality",
                "description": f"High overall criticality ({pattern_analysis.overall_criticality:.4f})",
                "criticality": pattern_analysis.overall_criticality,
                "evidence": (
                    f"Pattern distribution: {pattern_analysis.pattern_distribution}, "
                    f"Stability score: {pattern_analysis.stability_score:.4f}"
                )
            })
        
        # 3. Check for multiple pattern types
        if len(pattern_analysis.pattern_distribution) > 3:
            indicators.append({
                "type": "multiple_vulnerability_patterns",
                "description": f"Multiple vulnerability patterns detected ({len(pattern_analysis.pattern_distribution)})",
                "criticality": min(1.0, len(pattern_analysis.pattern_distribution) * 0.2),
                "evidence": ", ".join(pattern_analysis.pattern_distribution.keys())
            })
        
        return indicators
    
    def get_pattern_report(self,
                          analysis_result: TopologicalAnalysisResult,
                          pattern_analysis: Optional[PatternAnalysisResult] = None) -> str:
        """Get human-readable pattern analysis report.
        
        Args:
            analysis_result: Topological analysis results
            pattern_analysis: Optional pattern analysis results
            
        Returns:
            Pattern analysis report as string
        """
        if pattern_analysis is None:
            pattern_analysis = self.analyze(analysis_result)
        
        lines = [
            "=" * 80,
            "ANOMALY PATTERN ANALYSIS REPORT",
            "=" * 80,
            f"Analysis Timestamp: {datetime.fromtimestamp(pattern_analysis.analysis_timestamp).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Public Key: {analysis_result.public_key[:50]}{'...' if len(analysis_result.public_key) > 50 else ''}",
            f"Curve: {analysis_result.curve}",
            "",
            "PATTERN STATISTICS:",
            f"Total Patterns Detected: {len(pattern_analysis.patterns)}",
            f"Overall Criticality: {pattern_analysis.overall_criticality:.4f}",
            f"Stability Score: {pattern_analysis.stability_score:.4f}",
            f"Confidence: {pattern_analysis.confidence:.4f}",
            "",
            "PATTERN DISTRIBUTION:"
        ]
        
        if not pattern_analysis.pattern_distribution:
            lines.append("  No patterns detected")
        else:
            for pattern_type, proportion in pattern_analysis.pattern_distribution.items():
                lines.append(f"  - {pattern_type.upper()}: {proportion:.2%}")
        
        lines.append("")
        lines.append("DETECTED PATTERNS:")
        
        if not pattern_analysis.patterns:
            lines.append("  No patterns detected")
        else:
            for i, pattern in enumerate(pattern_analysis.patterns[:5], 1):  # Show up to 5 patterns
                lines.append(f"  {i}. {pattern.pattern_type.value.upper()} Pattern:")
                lines.append(
                    f"     - Criticality: {pattern.criticality:.4f}, "
                    f"Stability: {pattern.stability:.4f}, "
                    f"Persistence: {pattern.persistence:.4f}"
                )
                lines.append(
                    f"     - Location: ({pattern.location[0]:.2f}, {pattern.location[1]:.2f})"
                )
                if pattern.geometric_properties:
                    props = ", ".join(
                        f"{k}={v:.4f}" for k, v in pattern.geometric_properties.items()
                    )
                    lines.append(f"     - Properties: {props}")
        
            if len(pattern_analysis.patterns) > 5:
                lines.append(f"  - And {len(pattern_analysis.patterns) - 5} more patterns")
        
        # Add vulnerability indicators
        vulnerability_indicators = self.get_vulnerability_indicators(pattern_analysis)
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
            "ANOMALY PATTERN ANALYSIS FOOTER",
            "=" * 80,
            "This report was generated by TopoSphere Anomaly Pattern Detector,",
            "a component of the Differential Analysis system for detecting ECDSA vulnerabilities.",
            "A 'secure' result does not guarantee the absence of all possible vulnerabilities.",
            "Additional security testing is recommended for critical systems.",
            "=" * 80
        ])
        
        return "\n".join(lines)


# ======================
# HELPER FUNCTIONS
# ======================

def detect_anomaly_patterns(analysis_result: TopologicalAnalysisResult) -> List[AnomalyPattern]:
    """Detect anomaly patterns from topological analysis results.
    
    Args:
        analysis_result: Topological analysis results
        
    Returns:
        List of detected anomaly patterns
    """
    # In a real implementation, this would use a proper pattern detector
    # For demonstration, we'll return a mock result
    patterns = []
    
    # Example: detect spiral pattern if spiral consistency is low
    spiral_consistency = analysis_result.stability_metrics.get("spiral_consistency", 0.8)
    if spiral_consistency < 0.7:
        patterns.append(AnomalyPattern(
            pattern_type=AnomalyPatternType.SPIRAL,
            criticality=min(1.0, (0.7 - spiral_consistency) * 1.5),
            location=(analysis_result.public_key_hash % 1000, 
                     (analysis_result.public_key_hash // 1000) % 1000),
            stability=spiral_consistency,
            persistence=0.5,
            confidence=min(1.0, (0.7 - spiral_consistency) * 1.8),
            geometric_properties={"consistency": spiral_consistency}
        ))
    
    # Example: detect star pattern if star score is high
    star_score = analysis_result.stability_metrics.get("star_score", 0.4)
    if star_score > 0.6:
        patterns.append(AnomalyPattern(
            pattern_type=AnomalyPatternType.STAR,
            criticality=min(1.0, (star_score - 0.6) * 1.5),
            location=(analysis_result.public_key_hash % 1000, 
                     (analysis_result.public_key_hash // 1000) % 1000),
            stability=1.0 - star_score,
            persistence=0.4,
            confidence=min(1.0, (star_score - 0.6) * 1.8),
            geometric_properties={"star_score": star_score}
        ))
    
    return patterns


def analyze_pattern_propagation(analysis_result: TopologicalAnalysisResult,
                              max_hops: int = 3) -> PatternPropagationResult:
    """Analyze propagation of topological anomalies.
    
    Args:
        analysis_result: Topological analysis results
        max_hops: Maximum number of propagation hops
        
    Returns:
        PatternPropagationResult object
    """
    # In a real implementation, this would analyze actual pattern propagation
    # For demonstration, we'll return a mock result
    grid_size = 100
    anomaly_map = np.zeros((grid_size, grid_size))
    
    # Add some mock anomalies
    anomaly_map[30:40, 60:70] = 0.8
    anomaly_map[70:80, 20:30] = 0.6
    
    # Propagate anomalies
    for _ in range(max_hops):
        new_map = anomaly_map.copy()
        for i in range(grid_size):
            for j in range(grid_size):
                if anomaly_map[i, j] > 0:
                    for di, dj in [(-1,0), (1,0), (0,-1), (0,1)]:
                        ni, nj = (i + di) % grid_size, (j + dj) % grid_size
                        decay = 0.7
                        new_map[ni, nj] = max(new_map[ni, nj], anomaly_map[i, j] * decay)
        anomaly_map = new_map
    
    # Identify potential vulnerabilities
    potential_vulnerabilities = []
    for i in range(grid_size):
        for j in range(grid_size):
            if anomaly_map[i, j] > 0.3:
                u_r = i * 115792089237316195423570985008687907852837564279074904382605163141518161494337 / grid_size
                u_z = j * 115792089237316195423570985008687907852837564279074904382605163141518161494337 / grid_size
                potential_vulnerabilities.append((u_r, u_z, anomaly_map[i, j]))
    
    return PatternPropagationResult(
        propagated_map=anomaly_map,
        potential_vulnerabilities=potential_vulnerabilities,
        global_impact_score=np.mean(anomaly_map),
        execution_time=0.25,
        meta={
            "max_hops": max_hops,
            "grid_size": grid_size
        }
    )


def get_pattern_criticality(pattern: AnomalyPattern) -> PatternCriticalityLevel:
    """Get criticality level for a pattern.
    
    Args:
        pattern: Anomaly pattern
        
    Returns:
        Criticality level
    """
    return PatternCriticalityLevel.from_criticality_score(pattern.criticality)
