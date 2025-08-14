"""
Topological Calculations Module

This module provides advanced topological calculation utilities used throughout the TopoSphere system.
It implements the core mathematical operations required for topological analysis of ECDSA implementations,
including persistent homology, Betti number calculation, topological entropy, and vulnerability detection
through topological anomalies.

The module leverages the fastecdsa library for efficient elliptic curve operations while adding specialized
topological functionality for security analysis. Key features include:
- Persistent homology calculations for Betti numbers
- Spiral pattern analysis on the torus structure
- Diagonal symmetry verification
- Topological anomaly detection and classification
- Fractal dimension calculation for recursive refinement
- Quantum-inspired security metrics based on entanglement entropy
- Direct construction of topological representations from public keys

This module is designed to work seamlessly with topological_models.py, cryptographic_models.py, and
elliptic_curve.py, providing the topological backbone for the security framework.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Union, Callable, TypeVar, Protocol
import numpy as np
import random
import math
from functools import lru_cache
import warnings
import time
import sys
from collections import defaultdict
from enum import Enum

# External dependencies
try:
    from fastecdsa.curve import Curve, secp256k1
    from fastecdsa.point import Point
    from fastecdsa.util import mod_sqrt
    EC_LIBS_AVAILABLE = True
except ImportError as e:
    EC_LIBS_AVAILABLE = False
    warnings.warn(f"fastecdsa library not found: {e}. Some topological features will be limited.", 
                 RuntimeWarning)

# Optional dependencies for advanced topological analysis
try:
    from gtda.homology import VietorisRipsPersistence
    from gtda.diagrams import PersistenceEntropy, HeatKernel
    TOPOLOGY_LIBS_AVAILABLE = True
except ImportError:
    TOPOLOGY_LIBS_AVAILABLE = False
    warnings.warn("giotto-tda library not found. Some advanced topological features will be limited.",
                 RuntimeWarning)

# Import from our own modules
from ..models.topological_models import (
    BettiNumbers,
    PersistentCycle,
    StabilityMetrics,
    SignatureSpace,
    TorusStructure,
    TopologicalAnalysisResult
)
from ..models.cryptographic_models import (
    ECDSASignature,
    NonceSecurityAssessment
)
from .math_utils import (
    gcd,
    lcm,
    modular_inverse,
    compute_betti_numbers as math_compute_betti_numbers,
    is_torus_structure as math_is_torus_structure,
    calculate_topological_entropy as math_calculate_topological_entropy,
    check_diagonal_symmetry as math_check_diagonal_symmetry,
    compute_spiral_pattern as math_compute_spiral_pattern,
    estimate_private_key as math_estimate_private_key,
    calculate_periodicity as math_calculate_periodicity,
    calculate_fractal_dimension as math_calculate_fractal_dimension,
    calculate_uniformity_score as math_calculate_uniformity_score,
    calculate_entanglement_entropy
)
from .elliptic_curve import (
    compute_r,
    generate_synthetic_signatures,
    validate_public_key
)

# ======================
# ENUMERATIONS
# ======================

class TopologicalFeatureType(Enum):
    """Types of topological features detected in analysis."""
    HOLE = "hole"  # 1-dimensional hole (β₁)
    VOID = "void"  # 2-dimensional void (β₂)
    CONNECTED_COMPONENT = "connected_component"  # β₀
    CRITICAL_POINT = "critical_point"  # Singularity in the signature space
    SPIRAL_ANOMALY = "spiral_anomaly"  # Deviation from expected spiral pattern
    SYMMETRY_VIOLATION = "symmetry_violation"  # Diagonal symmetry violation
    FRACTAL_ANOMALY = "fractal_anomaly"  # Deviation from expected fractal structure


class AnomalySeverity(Enum):
    """Severity levels for detected topological anomalies."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ======================
# TOPOLOGICAL CALCULATION CLASSES
# ======================

@dataclass
class TopologicalFeature:
    """Represents a detected topological feature or anomaly."""
    feature_type: TopologicalFeatureType
    dimension: int
    birth: float
    death: float
    persistence: float
    location: Tuple[float, float]
    severity: AnomalySeverity
    description: str
    pattern: str = ""  # spiral, star, cluster, etc.
    confidence: float = 1.0
    criticality: float = 0.0
    is_anomalous: bool = False
    anomaly_id: str = field(default_factory=lambda: f"anomaly_{random.randint(100000, 99999)}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "feature_type": self.feature_type.value,
            "dimension": self.dimension,
            "birth": self.birth,
            "death": self.death,
            "persistence": self.persistence,
            "location": self.location,
            "severity": self.severity.value,
            "description": self.description,
            "pattern": self.pattern,
            "confidence": self.confidence,
            "criticality": self.criticality,
            "is_anomalous": self.is_anomalous,
            "anomaly_id": self.anomaly_id
        }


@dataclass
class TopologicalAnalysisParameters:
    """Parameters for controlling topological analysis."""
    epsilon: float = 0.1  # Maximum distance for neighborhood graph
    min_persistence: float = 0.05  # Minimum persistence for feature inclusion
    sample_size: int = 1000  # Number of points to sample for analysis
    sampling_rate: float = 0.01  # Rate of sampling for large datasets
    noise_level: float = 0.05  # Level of noise for differential privacy
    max_dimension: int = 2  # Maximum homology dimension to compute
    stability_threshold: float = 0.3  # Threshold for feature stability
    symmetry_check: bool = True  # Whether to check diagonal symmetry
    spiral_analysis: bool = True  # Whether to analyze spiral pattern
    entropy_calculation: bool = True  # Whether to calculate topological entropy
    quantum_metrics: bool = True  # Whether to calculate quantum-inspired metrics
    fractal_analysis: bool = True  # Whether to analyze fractal structure

    def get_epsilon(self, n: int) -> float:
        """Get appropriate epsilon based on curve order."""
        return max(0.01 * n, self.epsilon)

    def get_sample_size(self, total_points: int) -> int:
        """Get appropriate sample size based on total points."""
        return min(self.sample_size, int(total_points * self.sampling_rate))


# ======================
# TOPOLOGICAL CALCULATION UTILITIES
# ======================

def compute_persistent_homology(points: np.ndarray, 
                               params: TopologicalAnalysisParameters) -> List[np.ndarray]:
    """Compute persistent homology for a point cloud using Vietoris-Rips complex.
    
    Args:
        points: Point cloud representing the signature space (u_r, u_z, r)
        params: Analysis parameters
        
    Returns:
        List of persistence diagrams for each dimension
        
    Raises:
        RuntimeError: If giotto-tda is not available
    """
    if not TOPOLOGY_LIBS_AVAILABLE:
        raise RuntimeError("giotto-tda library is required for persistent homology but not available")
    
    if len(points) < 4:  # Need at least 4 points for meaningful homology
        return [np.array([]) for _ in range(params.max_dimension + 1)]
    
    # Extract just (u_r, u_z) for 2D analysis
    coordinates = points[:, :2]
    
    # Compute persistence
    vr = VietorisRipsPersistence(
        metric='euclidean',
        homology_dimensions=list(range(params.max_dimension + 1)),
        n_jobs=-1
    )
    
    diagrams = vr.fit_transform([coordinates])[0]
    return diagrams


def extract_betti_numbers(diagrams: List[np.ndarray], 
                         epsilon: float, 
                         n: int) -> BettiNumbers:
    """Extract Betti numbers at scale epsilon from persistence diagrams.
    
    Args:
        diagrams: Persistence diagrams for each dimension
        epsilon: Scale parameter for extraction
        n: Curve order (for normalization)
        
    Returns:
        BettiNumbers object with counts at scale epsilon
    """
    beta_0 = 0
    beta_1 = 0
    beta_2 = 0
    
    # For each dimension, count features that persist beyond epsilon
    for dim, diagram in enumerate(diagrams):
        if len(diagram) == 0:
            continue
            
        # Filter by persistence (death - birth > epsilon)
        persistent = diagram[diagram[:, 1] - diagram[:, 0] > epsilon]
        count = len(persistent)
        
        if dim == 0:
            beta_0 = count
        elif dim == 1:
            beta_1 = count
        elif dim == 2:
            beta_2 = count
    
    return BettiNumbers(
        beta_0=beta_0,
        beta_1=beta_1,
        beta_2=beta_2
    )


def calculate_persistence_stability(diagrams: List[np.ndarray],
                                   epsilon_range: List[float]) -> Dict[str, Any]:
    """Calculate stability metrics for persistent homology features.
    
    Measures how stable topological features are across different scales.
    
    Args:
        diagrams: Persistence diagrams for each dimension
        epsilon_range: Range of epsilon values to analyze
        
    Returns:
        Dictionary containing stability metrics
    """
    stability_by_dim = {}
    persistence_ratios = {}
    
    # For each dimension, calculate stability
    for dim in range(len(diagrams)):
        if len(diagrams[dim]) == 0:
            stability_by_dim[dim] = 0.0
            persistence_ratios[dim] = []
            continue
            
        # Calculate persistence ratios (persistence / max_persistence)
        persistences = diagrams[dim][:, 1] - diagrams[dim][:, 0]
        max_persistence = np.max(persistences) if len(persistences) > 0 else 1.0
        ratios = persistences / max_persistence
        
        # Stability is the ratio of features with high persistence
        stable_ratio = np.mean(ratios > 0.1)
        stability_by_dim[dim] = stable_ratio
        persistence_ratios[dim] = ratios.tolist()
    
    # Overall stability score (weighted average)
    stability_score = (
        0.3 * stability_by_dim.get(0, 0.0) +
        0.5 * stability_by_dim.get(1, 0.0) +
        0.2 * stability_by_dim.get(2, 0.0)
    )
    
    return {
        "stability_by_dimension": stability_by_dim,
        "stability_score": stability_score,
        "persistence_ratios": persistence_ratios
    }


def detect_persistent_cycles(diagrams: List[np.ndarray],
                            min_persistence: float = 0.1) -> List[PersistentCycle]:
    """Identify significant persistent cycles in the data.
    
    Args:
        diagrams: Persistence diagrams for each dimension
        min_persistence: Minimum persistence ratio to consider
        
    Returns:
        List of significant persistent cycles
    """
    cycles = []
    
    for dim, diagram in enumerate(diagrams):
        if len(diagram) == 0:
            continue
            
        # Calculate persistence
        persistences = diagram[:, 1] - diagram[:, 0]
        max_persistence = np.max(persistences) if len(persistences) > 0 else 1.0
        
        # Filter by minimum persistence
        mask = persistences > min_persistence * max_persistence
        significant = diagram[mask]
        significant_persistences = persistences[mask]
        
        # Create cycle objects
        for i, (point, persistence) in enumerate(zip(significant, significant_persistences)):
            birth, death = point
            cycle_id = f"cycle_{dim}_{i}"
            
            # For 1D cycles (holes), we can estimate location
            location = (0.0, 0.0)  # Placeholder - in real implementation would use cycle representative
            weight = persistence / max_persistence
            
            # Determine if anomalous (for dim=1, secure implementation should have exactly 2 cycles)
            is_anomalous = False
            anomaly_type = ""
            if dim == 1:
                if weight < 0.3:
                    is_anomalous = True
                    anomaly_type = "weak_cycle"
                elif weight > 0.9 and persistence < 0.5 * max_persistence:
                    is_anomalous = True
                    anomaly_type = "spiral_pattern"
            
            # Determine geometric pattern
            pattern = "unknown"
            if dim == 1 and is_anomalous:
                pattern = "spiral" if "spiral" in anomaly_type else "star"
            
            cycles.append(PersistentCycle(
                id=cycle_id,
                dimension=dim,
                birth=birth,
                death=death,
                persistence=persistence,
                stability=weight,
                representative_points=[],  # Would be populated in real implementation
                weight=weight,
                criticality=1.0 - weight,
                location=location,
                is_anomalous=is_anomalous,
                anomaly_type=anomaly_type,
                geometric_pattern=pattern
            ))
    
    return cycles


def analyze_symmetry_violations(points: np.ndarray, 
                               n: int) -> Dict[str, Any]:
    """Analyze symmetry violations in the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Dict containing symmetry violation analysis
    """
    if len(points) == 0:
        return {
            "violation_count": 0,
            "total_points": 0,
            "violation_rate": 1.0,
            "is_secure": False,
            "critical_regions": []
        }
    
    # Check symmetry for sampled points
    sample_size = min(1000, len(points))
    indices = random.sample(range(len(points)), sample_size)
    
    violations = 0
    critical_regions = defaultdict(int)
    total = 0
    
    for i in indices:
        u_r, u_z, r_val = points[i]
        
        # Find corresponding symmetric point (u_z, u_r)
        symmetric_r = None
        for j in range(len(points)):
            if abs(points[j, 0] - u_z) < 1e-10 and abs(points[j, 1] - u_r) < 1e-10:
                symmetric_r = points[j, 2]
                break
        
        if symmetric_r is not None:
            # Check if r values match (with tolerance for numerical issues)
            if abs(r_val - symmetric_r) > n * 1e-8:
                violations += 1
                
                # Track critical regions
                region_x = int(u_r // (n / 10))
                region_y = int(u_z // (n / 10))
                critical_regions[(region_x, region_y)] += 1
            
            total += 1
    
    violation_rate = violations / total if total > 0 else 1.0
    is_secure = violation_rate < 0.01
    
    # Format critical regions
    formatted_critical = [
        {"region": f"({x},{y})", "count": count}
        for (x, y), count in critical_regions.items()
    ]
    
    return {
        "violation_count": violations,
        "total_points": total,
        "violation_rate": violation_rate,
        "is_secure": is_secure,
        "critical_regions": formatted_critical
    }


def analyze_spiral_pattern(points: np.ndarray, 
                          n: int,
                          d: Optional[int] = None) -> Dict[str, Any]:
    """Analyze the spiral pattern in the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        d: Private key estimate (optional)
        
    Returns:
        Dict containing spiral pattern analysis
    """
    if len(points) == 0:
        return {
            "slope": 0.0,
            "period": n,
            "consistency_score": 0.0,
            "anomaly_score": 1.0,
            "is_vulnerable": True,
            "critical_points": []
        }
    
    # Estimate private key if not provided
    if d is None:
        d = math_estimate_private_key(points, n)
    
    # Analyze spiral consistency
    consistent_points = 0
    total_points = 0
    critical_points = []
    
    for i in range(len(points)):
        u_r, u_z, _ = points[i]
        
        # Calculate expected next point in the spiral
        u_r_next = (u_r + 1) % n
        u_z_next = (u_z + d) % n
        
        # Check if the next point exists
        found = False
        for j in range(len(points)):
            if (abs(points[j, 0] - u_r_next) < 1e-10 and 
                abs(points[j, 1] - u_z_next) < 1e-10):
                found = True
                break
        
        if found:
            consistent_points += 1
        else:
            # Check if this is a critical point (where ∂r/∂u_r = 0)
            if i > 0 and i < len(points) - 1:
                prev_r = points[i-1, 2]
                next_r = points[i+1, 2]
                if abs(next_r - prev_r) < 1e-10:
                    critical_points.append((u_r, u_z))
        
        total_points += 1
    
    consistency_score = consistent_points / total_points if total_points > 0 else 0.0
    
    # Calculate period
    g = gcd(d - 1, n) if d is not None else 1
    period = n // g if g > 0 else n
    
    # Anomaly score (lower is better)
    anomaly_score = 1.0 - consistency_score
    
    return {
        "slope": d if d is not None else 0.0,
        "period": period,
        "consistency_score": consistency_score,
        "anomaly_score": anomaly_score,
        "is_vulnerable": period < n / 10 or consistency_score < 0.7,
        "critical_points": critical_points
    }


def detect_topological_anomalies(points: np.ndarray,
                                n: int,
                                betti_numbers: BettiNumbers,
                                params: TopologicalAnalysisParameters) -> List[TopologicalFeature]:
    """Detect topological anomalies in the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        betti_numbers: Calculated Betti numbers
        params: Analysis parameters
        
    Returns:
        List of detected topological anomalies
    """
    anomalies = []
    
    # 1. Check for unexpected Betti numbers
    expected = {"beta_0": 1, "beta_1": 2, "beta_2": 1}
    deviations = {
        "beta_0": abs(betti_numbers.beta_0 - expected["beta_0"]),
        "beta_1": abs(betti_numbers.beta_1 - expected["beta_1"]),
        "beta_2": abs(betti_numbers.beta_2 - expected["beta_2"])
    }
    
    # β₀ anomalies
    if deviations["beta_0"] > 0.5:
        severity = AnomalySeverity.CRITICAL if deviations["beta_0"] > 1.0 else AnomalySeverity.HIGH
        anomalies.append(TopologicalFeature(
            feature_type=TopologicalFeatureType.CONNECTED_COMPONENT,
            dimension=0,
            birth=0.0,
            death=0.0,
            persistence=0.0,
            location=(0.0, 0.0),
            severity=severity,
            description=f"Unexpected number of connected components ({betti_numbers.beta_0} instead of 1)",
            confidence=1.0 - min(deviations["beta_0"] / 2.0, 1.0),
            criticality=min(deviations["beta_0"], 1.0)
        ))
    
    # β₁ anomalies
    if abs(deviations["beta_1"] - 0.0) > 0.3:
        # Determine type of anomaly
        if betti_numbers.beta_1 < 1.5:
            pattern = "spiral_pattern"
            description = f"Reduced cycle structure ({betti_numbers.beta_1} instead of 2.0), indicating spiral pattern vulnerability"
        elif betti_numbers.beta_1 > 2.5:
            pattern = "star_pattern"
            description = f"Excessive cycle structure ({betti_numbers.beta_1} instead of 2.0), indicating star pattern vulnerability"
        else:
            pattern = "irregular"
            description = f"Irregular cycle structure ({betti_numbers.beta_1} instead of 2.0)"
        
        severity = AnomalySeverity.HIGH
        if abs(deviations["beta_1"] - 0.0) > 0.8:
            severity = AnomalySeverity.CRITICAL
        elif abs(deviations["beta_1"] - 0.0) > 0.5:
            severity = AnomalySeverity.MEDIUM
        
        anomalies.append(TopologicalFeature(
            feature_type=TopologicalFeatureType.HOLE,
            dimension=1,
            birth=0.0,
            death=0.0,
            persistence=0.0,
            location=(0.0, 0.0),
            severity=severity,
            description=description,
            pattern=pattern,
            confidence=1.0 - min(abs(deviations["beta_1"] - 0.0) / 2.0, 1.0),
            criticality=min(abs(deviations["beta_1"] - 0.0), 1.0),
            is_anomalous=True
        ))
    
    # β₂ anomalies
    if deviations["beta_2"] > 0.3:
        severity = AnomalySeverity.MEDIUM if deviations["beta_2"] < 0.7 else AnomalySeverity.HIGH
        anomalies.append(TopologicalFeature(
            feature_type=TopologicalFeatureType.VOID,
            dimension=2,
            birth=0.0,
            death=0.0,
            persistence=0.0,
            location=(0.0, 0.0),
            severity=severity,
            description=f"Unexpected void structure ({betti_numbers.beta_2} instead of 1.0)",
            confidence=1.0 - min(deviations["beta_2"] / 2.0, 1.0),
            criticality=min(deviations["beta_2"], 1.0)
        ))
    
    # 2. Check for symmetry violations
    symmetry_analysis = analyze_symmetry_violations(points, n)
    if symmetry_analysis["violation_rate"] > 0.01:
        severity = AnomalySeverity.HIGH if symmetry_analysis["violation_rate"] > 0.05 else AnomalySeverity.MEDIUM
        anomalies.append(TopologicalFeature(
            feature_type=TopologicalFeatureType.SYMMETRY_VIOLATION,
            dimension=0,
            birth=0.0,
            death=0.0,
            persistence=0.0,
            location=(0.0, 0.0),
            severity=severity,
            description=f"Diagonal symmetry violation rate is {symmetry_analysis['violation_rate']:.4f} (threshold: 0.01)",
            confidence=1.0 - symmetry_analysis["violation_rate"],
            criticality=symmetry_analysis["violation_rate"]
        ))
    
    # 3. Check for spiral pattern anomalies
    spiral_analysis = analyze_spiral_pattern(points, n)
    if spiral_analysis["anomaly_score"] > 0.3:
        severity = AnomalySeverity.HIGH if spiral_analysis["anomaly_score"] > 0.6 else AnomalySeverity.MEDIUM
        anomalies.append(TopologicalFeature(
            feature_type=TopologicalFeatureType.SPIRAL_ANOMALY,
            dimension=1,
            birth=0.0,
            death=0.0,
            persistence=0.0,
            location=(0.0, 0.0),
            severity=severity,
            description=f"Spiral pattern consistency is {spiral_analysis['consistency_score']:.4f} (threshold: 0.7)",
            pattern=spiral_analysis.get("pattern", "irregular"),
            confidence=spiral_analysis["consistency_score"],
            criticality=1.0 - spiral_analysis["consistency_score"]
        ))
    
    # 4. Check for fractal structure anomalies
    fractal_dimension = math_calculate_fractal_dimension(points, n)
    if fractal_dimension < 1.8 or fractal_dimension > 2.2:
        severity = AnomalySeverity.MEDIUM
        if fractal_dimension < 1.5 or fractal_dimension > 2.5:
            severity = AnomalySeverity.HIGH
            
        anomalies.append(TopologicalFeature(
            feature_type=TopologicalFeatureType.FRACTAL_ANOMALY,
            dimension=-1,
            birth=0.0,
            death=0.0,
            persistence=0.0,
            location=(0.0, 0.0),
            severity=severity,
            description=f"Fractal dimension is {fractal_dimension:.4f} (expected: ~2.0 for secure implementations)",
            confidence=1.0 - abs(fractal_dimension - 2.0) / 2.0,
            criticality=abs(fractal_dimension - 2.0) / 2.0
        ))
    
    return anomalies


def calculate_torus_structure(points: np.ndarray, 
                             n: int,
                             d: Optional[int] = None) -> TorusStructure:
    """Analyze the torus structure of the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        d: Private key estimate (optional)
        
    Returns:
        TorusStructure object
    """
    if len(points) == 0:
        return TorusStructure(
            n=n,
            is_valid_torus=False,
            confidence=0.0
        )
    
    # Estimate private key if not provided
    if d is None:
        d = math_estimate_private_key(points, n)
    
    # Analyze spiral pattern
    spiral_analysis = analyze_spiral_pattern(points, n, d)
    
    # Calculate periodicity
    periodicity_analysis = math_calculate_periodicity(points, n)
    
    # Check diagonal symmetry
    symmetry_analysis = analyze_symmetry_violations(points, n)
    
    # Find critical points
    critical_points = spiral_analysis.get("critical_points", [])
    
    # Determine if structure is valid torus
    is_valid_torus = (
        abs(spiral_analysis["consistency_score"] - 1.0) < 0.3 and
        symmetry_analysis["violation_rate"] < 0.05 and
        spiral_analysis["period"] > n / 2
    )
    
    # Calculate confidence
    confidence = (
        0.4 * spiral_analysis["consistency_score"] +
        0.3 * (1.0 - symmetry_analysis["violation_rate"]) +
        0.3 * (spiral_analysis["period"] / n)
    )
    
    return TorusStructure(
        n=n,
        private_key_estimate=d,
        spiral_slope=spiral_analysis.get("slope", 0.0),
        spiral_period=spiral_analysis.get("period", n),
        diagonal_period=periodicity_analysis.get("diagonal_period", n),
        symmetry_violation_rate=symmetry_analysis.get("violation_rate", 1.0),
        is_valid_torus=is_valid_torus,
        confidence=confidence,
        critical_points=critical_points
    )


def analyze_quantum_metrics(points: np.ndarray, 
                          n: int,
                          sample_size: int = 1000) -> Dict[str, float]:
    """Calculate quantum-inspired security metrics.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        sample_size: Number of points to sample for calculation
        
    Returns:
        Dictionary containing quantum-inspired metrics
    """
    if len(points) == 0:
        return {
            "entanglement_entropy": 0.0,
            "vulnerability_score": 1.0
        }
    
    # Calculate entanglement entropy
    entanglement_entropy = calculate_entanglement_entropy(points, n, sample_size)
    
    # Calculate vulnerability score based on entropy
    vulnerability_score = 1.0 - entanglement_entropy
    
    return {
        "entanglement_entropy": entanglement_entropy,
        "vulnerability_score": vulnerability_score
    }


def analyze_signature_space(Q: Point, 
                           curve: Curve, 
                           params: Optional[TopologicalAnalysisParameters] = None) -> TopologicalAnalysisResult:
    """Analyze the topological structure of the signature space.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        params: Analysis parameters (uses defaults if None)
        
    Returns:
        TopologicalAnalysisResult object containing analysis results
        
    Raises:
        RuntimeError: If fastecdsa is not available
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if not validate_public_key(Q, curve):
        return TopologicalAnalysisResult(
            status=TopologicalAnalysisStatus.ERROR,
            betti_numbers=BettiNumbers(beta_0=0, beta_1=0, beta_2=0),
            persistence_diagrams=[],
            uniformity_score=0.0,
            fractal_dimension=0.0,
            topological_entropy=0.0,
            entropy_anomaly_score=1.0,
            is_torus_structure=False,
            confidence=0.0,
            anomaly_score=1.0,
            anomaly_types=[],
            vulnerabilities=[],
            stability_metrics={"score": 0.0}
        )
    
    # Use default parameters if none provided
    if params is None:
        params = TopologicalAnalysisParameters()
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(
        Q, 
        curve, 
        num_samples=params.sample_size,
        sampling_rate=params.sampling_rate
    )
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    if len(points) == 0:
        return TopologicalAnalysisResult(
            status=TopologicalAnalysisStatus.ERROR,
            betti_numbers=BettiNumbers(beta_0=0, beta_1=0, beta_2=0),
            persistence_diagrams=[],
            uniformity_score=0.0,
            fractal_dimension=0.0,
            topological_entropy=0.0,
            entropy_anomaly_score=1.0,
            is_torus_structure=False,
            confidence=0.0,
            anomaly_score=1.0,
            anomaly_types=[],
            vulnerabilities=[],
            stability_metrics={"score": 0.0}
        )
    
    # Compute Betti numbers
    epsilon = params.get_epsilon(curve.n)
    betti = math_compute_betti_numbers(points, epsilon)
    
    # Calculate topological entropy
    topological_entropy = math_calculate_topological_entropy(points, curve.n)
    
    # Check diagonal symmetry
    symmetry_analysis = math_check_diagonal_symmetry(points, curve.n)
    
    # Analyze spiral pattern
    spiral_analysis = math_compute_spiral_pattern(points, curve.n)
    
    # Calculate stability metrics
    stability_metrics = calculate_persistence_stability(
        compute_persistent_homology(points, params),
        np.linspace(0.01 * curve.n, 0.1 * curve.n, 10)
    )
    
    # Detect anomalies
    anomalies = detect_topological_anomalies(points, curve.n, BettiNumbers(**betti), params)
    anomaly_score = sum(anomaly.criticality for anomaly in anomalies) / max(1, len(anomalies)) if anomalies else 0.0
    
    # Analyze torus structure
    torus_analysis = calculate_torus_structure(points, curve.n)
    
    # Calculate quantum metrics
    quantum_metrics = analyze_quantum_metrics(points, curve.n)
    
    # Determine overall status
    if anomaly_score < 0.2 and torus_analysis.is_valid_torus:
        status = TopologicalAnalysisStatus.SECURE
    elif anomaly_score < 0.5:
        status = TopologicalAnalysisStatus.INDETERMINATE
    else:
        status = TopologicalAnalysisStatus.VULNERABLE
    
    # Create analysis result
    return TopologicalAnalysisResult(
        status=status,
        betti_numbers=BettiNumbers(
            beta_0=betti["beta_0"],
            beta_1=betti["beta_1"],
            beta_2=betti["beta_2"]
        ),
        persistence_diagrams=[],  # Would be populated in real implementation
        uniformity_score=math_calculate_uniformity_score(points, curve.n),
        fractal_dimension=math_calculate_fractal_dimension(points, curve.n),
        topological_entropy=topological_entropy,
        entropy_anomaly_score=1.0 - topological_entropy,
        is_torus_structure=torus_analysis.is_valid_torus,
        confidence=torus_analysis.confidence,
        anomaly_score=anomaly_score,
        anomaly_types=list(set(anomaly.feature_type.value for anomaly in anomalies)),
        vulnerabilities=[anomaly.to_dict() for anomaly in anomalies],
        stability_metrics={
            "score": stability_metrics["stability_score"],
            **stability_metrics["stability_by_dimension"]
        },
        nerve_analysis={
            "is_valid": torus_analysis.is_valid_torus,
            "confidence": torus_analysis.confidence
        },
        smoothing_analysis={
            "stability_map": np.zeros((100, 100)).tolist()  # Placeholder
        },
        mapper_analysis={
            "quantum_metrics": quantum_metrics
        }
    )


def validate_topological_integrity(points: np.ndarray, 
                                 n: int,
                                 betti_numbers: BettiNumbers) -> Dict[str, Any]:
    """Validate the topological integrity of the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        betti_numbers: Calculated Betti numbers
        
    Returns:
        Dictionary with integrity validation results
    """
    results = {
        "is_valid": True,
        "issues": [],
        "confidence": 1.0
    }
    
    # Check Betti numbers
    expected = {"beta_0": 1, "beta_1": 2, "beta_2": 1}
    deviations = {
        "beta_0": abs(betti_numbers.beta_0 - expected["beta_0"]),
        "beta_1": abs(betti_numbers.beta_1 - expected["beta_1"]),
        "beta_2": abs(betti_numbers.beta_2 - expected["beta_2"])
    }
    
    if deviations["beta_0"] > 0.5:
        results["is_valid"] = False
        results["issues"].append(f"Unexpected number of connected components ({betti_numbers.beta_0} instead of 1)")
    
    if abs(deviations["beta_1"] - 0.0) > 0.5:
        results["is_valid"] = False
        results["issues"].append(f"Unexpected cycle structure ({betti_numbers.beta_1} instead of 2)")
    
    if deviations["beta_2"] > 0.5:
        results["is_valid"] = False
        results["issues"].append(f"Unexpected void structure ({betti_numbers.beta_2} instead of 1)")
    
    # Check symmetry
    symmetry = math_check_diagonal_symmetry(points, n)
    if symmetry["violation_rate"] > 0.01:
        results["is_valid"] = False
        results["issues"].append(f"Diagonal symmetry violation rate is too high ({symmetry['violation_rate']:.4f})")
    
    # Calculate confidence
    confidence = 1.0
    confidence -= 0.3 * min(deviations["beta_0"], 1.0)
    confidence -= 0.4 * min(abs(deviations["beta_1"] - 0.0), 1.0)
    confidence -= 0.2 * min(deviations["beta_2"], 1.0)
    confidence -= 0.1 * min(symmetry["violation_rate"] * 10, 1.0)
    
    results["confidence"] = max(0.0, min(1.0, confidence))
    return results


def analyze_fractal_structure(points: np.ndarray, 
                             n: int,
                             max_zoom: int = 5) -> Dict[str, Any]:
    """Analyze the fractal structure of the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        max_zoom: Maximum zoom level for fractal detection
        
    Returns:
        Dictionary with fractal structure analysis
    """
    if len(points) < 100:
        return {
            "fractal_dimension": 0.0,
            "zoom_levels": [],
            "is_fractal_consistent": False
        }
    
    # Calculate base fractal dimension
    base_dimension = math_calculate_fractal_dimension(points, n)
    
    # Analyze at different zoom levels
    zoom_levels = []
    current_scale = 1
    current_points = points
    
    for zoom_level in range(1, max_zoom + 1):
        # Scale down the space
        scale_factor = 2 ** zoom_level
        scaled_n = n // scale_factor
        
        if scaled_n < 10:  # Too small to analyze
            break
        
        # Create scaled points
        scaled_points = []
        for u_r, u_z, r in current_points:
            scaled_u_r = u_r // scale_factor
            scaled_u_z = u_z // scale_factor
            scaled_points.append((scaled_u_r, scaled_u_z, r))
        
        scaled_points = np.array(scaled_points)
        
        # Analyze scaled space
        scaled_dimension = math_calculate_fractal_dimension(scaled_points, scaled_n)
        
        # Check if dimension is consistent
        dimension_consistent = abs(scaled_dimension - base_dimension) < 0.2
        
        zoom_levels.append({
            "zoom_level": zoom_level,
            "scale_factor": scale_factor,
            "fractal_dimension": scaled_dimension,
            "is_consistent": dimension_consistent
        })
        
        current_scale = scale_factor
        current_points = scaled_points
    
    # Determine if fractal structure is consistent
    consistent_levels = sum(1 for level in zoom_levels if level["is_consistent"])
    is_fractal_consistent = consistent_levels >= len(zoom_levels) * 0.7
    
    return {
        "fractal_dimension": base_dimension,
        "zoom_levels": zoom_levels,
        "is_fractal_consistent": is_fractal_consistent
    }


def detect_critical_regions(points: np.ndarray, 
                           n: int,
                           anomaly_score: float,
                           threshold: float = 0.3) -> List[Dict[str, Any]]:
    """Identify critical regions with anomalous topological features.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        anomaly_score: Overall anomaly score
        threshold: Threshold for identifying critical regions
        
    Returns:
        List of critical regions with details
    """
    if len(points) == 0:
        return []
    
    # Create grid to analyze regions
    grid_size = 50
    grid = np.zeros((grid_size, grid_size))
    
    # Normalize points to [0,1]x[0,1]
    points_normalized = points / n
    
    # Count anomalies in each grid cell
    for u_r, u_z, _ in points_normalized:
        i = min(int(u_r * grid_size), grid_size - 1)
        j = min(int(u_z * grid_size), grid_size - 1)
        grid[i, j] += 1
    
    # Identify critical regions (high anomaly density)
    critical_regions = []
    threshold_value = np.percentile(grid, 90)  # Top 10% of regions
    
    for i in range(grid_size):
        for j in range(grid_size):
            if grid[i, j] >= threshold_value:
                # Convert back to original coordinates
                u_r_min = int((i / grid_size) * n)
                u_r_max = int(((i + 1) / grid_size) * n)
                u_z_min = int((j / grid_size) * n)
                u_z_max = int(((j + 1) / grid_size) * n)
                
                critical_regions.append({
                    "region": f"[{u_r_min}, {u_r_max}) x [{u_z_min}, {u_z_max})",
                    "density": float(grid[i, j]),
                    "anomaly_score": min(grid[i, j] / np.max(grid), 1.0),
                    "risk_level": "high" if grid[i, j] > threshold_value * 1.5 else "medium"
                })
    
    return critical_regions


def generate_topological_fingerprint(Q: Point,
                                    curve: Curve,
                                    params: Optional[TopologicalAnalysisParameters] = None) -> Dict[str, Any]:
    """Generate topological fingerprint for implementation identification.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        params: Analysis parameters
        
    Returns:
        Dictionary containing topological fingerprint
    """
    if params is None:
        params = TopologicalAnalysisParameters()
    
    # Analyze signature space
    analysis = analyze_signature_space(Q, curve, params)
    
    # Generate fingerprint components
    fingerprint = {
        "betti_numbers": {
            "beta_0": analysis.betti_numbers.beta_0,
            "beta_1": analysis.betti_numbers.beta_1,
            "beta_2": analysis.betti_numbers.beta_2
        },
        "topological_entropy": analysis.topological_entropy,
        "symmetry_violation_rate": analysis.stability_metrics.get("symmetry_violation", 1.0),
        "spiral_consistency": analysis.stability_metrics.get("spiral_consistency", 0.0),
        "fractal_dimension": analysis.fractal_dimension,
        "entanglement_entropy": analysis.mapper_analysis["quantum_metrics"]["entanglement_entropy"],
        "anomaly_score": analysis.anomaly_score,
        "signature": ""
    }
    
    # Create signature string
    signature_parts = [
        f"{fingerprint['betti_numbers']['beta_0']:.1f}",
        f"{fingerprint['betti_numbers']['beta_1']:.1f}",
        f"{fingerprint['betti_numbers']['beta_2']:.1f}",
        f"{fingerprint['topological_entropy']:.2f}",
        f"{fingerprint['symmetry_violation_rate']:.4f}",
        f"{fingerprint['spiral_consistency']:.4f}",
        f"{fingerprint['fractal_dimension']:.2f}",
        f"{fingerprint['entanglement_entropy']:.4f}"
    ]
    
    fingerprint["signature"] = "-".join(signature_parts)
    
    return fingerprint


def analyze_topological_vulnerability(Q: Point,
                                     curve: Curve,
                                     params: Optional[TopologicalAnalysisParameters] = None) -> Dict[str, Any]:
    """Analyze topological vulnerabilities for risk assessment.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        params: Analysis parameters
        
    Returns:
        Dictionary containing vulnerability analysis
    """
    if params is None:
        params = TopologicalAnalysisParameters()
    
    # Analyze signature space
    analysis = analyze_signature_space(Q, curve, params)
    
    # Calculate vulnerability score
    vulnerability_score = analysis.anomaly_score
    
    # Determine vulnerability level
    if vulnerability_score >= 0.7:
        level = "critical"
    elif vulnerability_score >= 0.4:
        level = "high"
    elif vulnerability_score >= 0.2:
        level = "medium"
    else:
        level = "low"
    
    # Generate recommendations
    recommendations = []
    if level == "critical":
        recommendations.append("URGENT: High probability of private key leakage. Rotate address immediately.")
    elif level == "high":
        recommendations.append("HIGH RISK: Significant vulnerability detected. Consider rotating address soon.")
    elif level == "medium":
        recommendations.append("CAUTION: Minor issues detected. Monitor usage and consider rotation.")
    
    # Add specific recommendations based on detected issues
    if not analysis.is_torus_structure:
        recommendations.append("Topology does not match expected torus structure (β₁ ≠ 2.0)")
    if analysis.stability_metrics.get("symmetry_violation", 1.0) > 0.01:
        recommendations.append("High symmetry violation rate detected (>1%)")
    if analysis.mapper_analysis["quantum_metrics"]["entanglement_entropy"] < 0.5:
        recommendations.append("Low entanglement entropy detected (<0.5)")
    
    return {
        "vulnerability_score": vulnerability_score,
        "vulnerability_level": level,
        "recommendations": recommendations,
        "analysis": analysis.to_dict()
    }
