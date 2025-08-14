# shared/models/topological_models.py

```python
"""
Topological Models Module

This module defines the core topological models used throughout the TopoSphere system.
These models represent the mathematical structures underlying ECDSA security analysis,
including Betti numbers, torus structure, persistent homology, and topological anomalies.

The models are designed to be shared between client and server components, ensuring
consistent interpretation of topological data across the system.

Key components:
- Betti numbers as security indicators
- Torus structure analysis for ECDSA signature space
- Persistent homology for vulnerability detection
- Stability metrics for topological features
- Anomaly detection models

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Union, Protocol
import numpy as np
from collections import defaultdict

# ======================
# ENUMERATIONS
# ======================

class TopologicalStructure(Enum):
    """Types of topological structures identified in ECDSA analysis."""
    TORUS = "torus"  # β₀=1, β₁=2, β₂=1 (secure ECDSA)
    SPHERE = "sphere"  # β₀=1, β₁=0, β₂=1
    DOUBLE_TORUS = "double_torus"  # β₀=1, β₁=4, β₂=1
    PLANE = "plane"  # β₀=1, β₁=0, β₂=0
    LINE = "line"  # β₀=1, β₁=1, β₂=0
    POINT_CLOUD = "point_cloud"  # β₀=N, β₁=0, β₂=0
    UNKNOWN = "unknown"  # Doesn't match any known structure


class VulnerabilityType(Enum):
    """Types of topological vulnerabilities detected."""
    STRUCTURED = "structured_vulnerability"  # Additional topological cycles
    POTENTIAL_NOISE = "potential_noise"  # Additional cycles may be statistical noise
    SPIRAL_PATTERN = "spiral_pattern"  # Indicates LCG vulnerability
    STAR_PATTERN = "star_pattern"  # Indicates periodic RNG vulnerability
    SYMMETRY_VIOLATION = "symmetry_violation"  # Biased nonce generation
    DIAGONAL_PERIODICITY = "diagonal_periodicity"  # Specific implementation vulnerability
    FRACTAL_ANOMALY = "fractal_anomaly"  # Deviation from expected fractal structure
    ENTROPY_ANOMALY = "entropy_anomaly"  # Low topological entropy indicating vulnerability


class TopologicalAnalysisStatus(Enum):
    """Status of topological analysis."""
    SUCCESS = "success"
    PARTIAL = "partial"  # Some analyses completed, others failed
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"  # Insufficient data for definitive conclusion


# ======================
# DATA CLASSES
# ======================

@dataclass(frozen=True)
class BettiNumbers:
    """Represents the Betti numbers for a topological space.
    
    Betti numbers are topological invariants that count the number of holes in various dimensions:
    - β₀: Number of connected components
    - β₁: Number of 1-dimensional holes (loops)
    - β₂: Number of 2-dimensional holes (voids)
    
    For secure ECDSA implementations, we expect β₀=1, β₁=2, β₂=1 (torus structure).
    """
    beta_0: int
    beta_1: int
    beta_2: int
    expected: Dict[str, int] = field(default_factory=lambda: {"beta_0": 1, "beta_1": 2, "beta_2": 1})
    
    @property
    def is_torus(self) -> bool:
        """Check if the Betti numbers correspond to a torus structure."""
        return (self.beta_0 == self.expected["beta_0"] and 
                self.beta_1 == self.expected["beta_1"] and 
                self.beta_2 == self.expected["beta_2"])
    
    @property
    def deviation_score(self) -> float:
        """Calculate a normalized deviation score from expected torus values."""
        dev_0 = abs(self.beta_0 - self.expected["beta_0"])
        dev_1 = abs(self.beta_1 - self.expected["beta_1"])
        dev_2 = abs(self.beta_2 - self.expected["beta_2"])
        
        # Normalize by expected values
        norm_dev_0 = dev_0 / max(1, self.expected["beta_0"])
        norm_dev_1 = dev_1 / max(1, self.expected["beta_1"])
        norm_dev_2 = dev_2 / max(1, self.expected["beta_2"])
        
        return (norm_dev_0 + norm_dev_1 + norm_dev_2) / 3.0


@dataclass
class PersistentCycle:
    """Represents a persistent cycle in topological analysis.
    
    Persistent cycles are topological features that persist across multiple scales
    in persistent homology analysis. They can indicate structural properties or
    vulnerabilities in the ECDSA signature space.
    """
    id: str
    dimension: int
    birth: float
    death: float
    persistence: float
    stability: float
    representative_points: List[Tuple[int, int]]
    weight: float
    criticality: float
    location: Tuple[float, float]  # (u_r, u_z) centroid
    is_anomalous: bool = False
    anomaly_type: str = ""
    geometric_pattern: str = ""  # spiral, star, cluster, etc.
    
    @property
    def persistence_ratio(self) -> float:
        """Calculate persistence ratio relative to the filtration range."""
        return self.persistence / max(1e-10, self.death) if self.birth > 0 else 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "dimension": self.dimension,
            "birth": self.birth,
            "death": self.death,
            "persistence": self.persistence,
            "stability": self.stability,
            "representative_points": self.representative_points,
            "weight": self.weight,
            "criticality": self.criticality,
            "location": self.location,
            "is_anomalous": self.is_anomalous,
            "anomaly_type": self.anomaly_type,
            "geometric_pattern": self.geometric_pattern
        }


@dataclass
class StabilityMetrics:
    """Metrics for measuring topological stability across scales.
    
    These metrics assess how stable topological features are when subjected to
    small perturbations, which is critical for determining if detected features
    represent real structure or noise.
    """
    stability_by_dimension: Dict[int, float]
    stability_score: float
    stability_map: np.ndarray
    confidence_interval: Tuple[float, float] = (0.0, 0.0)
    is_torus: bool = False
    torus_confidence: float = 0.0
    
    @classmethod
    def from_analysis(cls, 
                     persistence_diagrams: List[np.ndarray],
                     expected_betti: BettiNumbers,
                     epsilon: float = 0.05) -> StabilityMetrics:
        """Create stability metrics from persistence diagrams."""
        stability_by_dim = {}
        
        # Calculate stability for each dimension
        for dim, diagram in enumerate(persistence_diagrams):
            if len(diagram) == 0:
                stability_by_dim[dim] = 0.0
                continue
                
            # Calculate persistence ratios
            persistences = diagram[:, 1] - diagram[:, 0]
            max_persistence = np.max(persistences) if len(persistences) > 0 else 1.0
            
            # Stability is the ratio of long-lived features
            stable_features = np.sum(persistences > epsilon * max_persistence)
            stability_by_dim[dim] = stable_features / len(diagram) if len(diagram) > 0 else 0.0
        
        # Overall stability score (weighted average)
        stability_score = (
            0.3 * stability_by_dim.get(0, 0.0) +
            0.5 * stability_by_dim.get(1, 0.0) +
            0.2 * stability_by_dim.get(2, 0.0)
        )
        
        # Torus confidence (based on β₁)
        is_torus = (abs(stability_by_dim.get(1, 0) - 2.0) < 0.5)
        torus_confidence = 1.0 - abs(stability_by_dim.get(1, 0) - 2.0) / 2.0 if is_torus else 0.0
        
        return cls(
            stability_by_dimension=stability_by_dim,
            stability_score=stability_score,
            stability_map=np.zeros((100, 100)),  # Will be populated by analysis
            is_torus=is_torus,
            torus_confidence=min(max(torus_confidence, 0.0), 1.0)
        )


@dataclass
class SignatureSpace:
    """Represents the ECDSA signature space as a topological manifold.
    
    The ECDSA signature space for a fixed private key forms a topological torus,
    which can be analyzed using algebraic topology to detect vulnerabilities.
    """
    n: int  # Order of the elliptic curve subgroup
    public_key: str
    curve_name: str
    betti_numbers: BettiNumbers
    persistence_diagrams: List[np.ndarray]
    spiral_pattern: Optional[Dict[str, Any]] = None
    diagonal_symmetry: Optional[Dict[str, float]] = None
    topological_entropy: float = 0.0
    fractal_dimension: float = 0.0
    uniformity_score: float = 0.0
    structure_type: TopologicalStructure = TopologicalStructure.UNKNOWN
    
    def is_secure(self, 
                 entropy_threshold: float = 0.5,
                 symmetry_threshold: float = 0.01) -> bool:
        """Determine if the signature space structure is secure.
        
        Args:
            entropy_threshold: Minimum acceptable topological entropy
            symmetry_threshold: Maximum acceptable symmetry violation rate
            
        Returns:
            bool: True if the structure is secure, False otherwise
        """
        # Torus structure check
        has_torus_structure = self.betti_numbers.is_torus
        
        # Entropy check
        has_sufficient_entropy = self.topological_entropy > entropy_threshold
        
        # Symmetry check
        symmetry_ok = (self.diagonal_symmetry is None or 
                      self.diagonal_symmetry.get('violation_rate', 1.0) < symmetry_threshold)
        
        return has_torus_structure and has_sufficient_entropy and symmetry_ok
    
    def get_security_metrics(self) -> Dict[str, float]:
        """Get quantitative security metrics from the signature space analysis."""
        metrics = {
            "betti_deviation": self.betti_numbers.deviation_score,
            "topological_entropy": self.topological_entropy,
            "fractal_dimension": self.fractal_dimension,
            "uniformity_score": self.uniformity_score,
            "symmetry_violation": self.diagonal_symmetry.get('violation_rate', 1.0) if self.diagonal_symmetry else 1.0
        }
        
        # Overall security score (weighted combination)
        metrics["security_score"] = (
            0.3 * (1.0 - metrics["betti_deviation"]) +
            0.25 * min(metrics["topological_entropy"] / 2.0, 1.0) +  # Assuming max entropy ~2.0
            0.2 * metrics["uniformity_score"] +
            0.25 * (1.0 - metrics["symmetry_violation"])
        )
        
        return metrics


@dataclass
class TorusStructure:
    """Represents the torus structure of ECDSA signature space.
    
    For secure ECDSA implementations, the signature space forms a topological torus
    with specific properties that can be analyzed for vulnerabilities.
    """
    n: int  # Order of the elliptic curve subgroup
    private_key_estimate: Optional[int] = None
    spiral_slope: float = 0.0
    spiral_period: int = 0
    diagonal_period: int = 0
    symmetry_violation_rate: float = 0.0
    is_valid_torus: bool = False
    confidence: float = 0.0
    critical_points: List[Tuple[int, int]] = field(default_factory=list)
    
    @classmethod
    def analyze_from_signatures(cls, 
                               signatures: List[Tuple[int, int, int]], 
                               n: int) -> TorusStructure:
        """Analyze signatures to determine torus structure properties.
        
        Args:
            signatures: List of (u_r, u_z, r) signature points
            n: Order of the elliptic curve subgroup
            
        Returns:
            TorusStructure: Analyzed torus structure
        """
        # Implementation would analyze the signatures to determine:
        # - Spiral slope (related to private key)
        # - Periodicity in both spiral and diagonal directions
        # - Symmetry violations
        # - Critical points where ∂r/∂u_r = 0
        
        # This is a placeholder for the actual analysis
        return cls(
            n=n,
            spiral_slope=0.0,
            spiral_period=n,
            diagonal_period=n,
            symmetry_violation_rate=0.0,
            is_valid_torus=True,
            confidence=1.0
        )
    
    def get_vulnerability_indicators(self) -> Dict[str, Any]:
        """Get indicators that may suggest vulnerabilities in the torus structure."""
        indicators = {
            "spiral_consistency": self.spiral_period / self.n,
            "diagonal_consistency": self.diagonal_period / self.n,
            "symmetry_violation_rate": self.symmetry_violation_rate,
            "critical_point_density": len(self.critical_points) / (self.n * self.n) if self.n > 0 else 0
        }
        
        # Vulnerability score (lower is better)
        indicators["vulnerability_score"] = (
            0.3 * (1 - indicators["spiral_consistency"]) +
            0.3 * (1 - indicators["diagonal_consistency"]) +
            0.25 * indicators["symmetry_violation_rate"] +
            0.15 * indicators["critical_point_density"]
        )
        
        return indicators


@dataclass
class TopologicalAnalysisResult:
    """Comprehensive topological analysis result with industrial-grade metrics."""
    status: TopologicalAnalysisStatus
    betti_numbers: BettiNumbers
    persistence_diagrams: List[np.ndarray]
    uniformity_score: float
    fractal_dimension: float
    topological_entropy: float
    entropy_anomaly_score: float
    is_torus_structure: bool
    confidence: float
    anomaly_score: float
    anomaly_types: List[str]
    vulnerabilities: List[Dict[str, Any]]
    stability_metrics: Dict[str, float]
    nerve_analysis: Optional[Dict[str, Any]] = None
    smoothing_analysis: Optional[Dict[str, Any]] = None
    mapper_analysis: Optional[Dict[str, Any]] = None
    
    @property
    def is_secure(self) -> bool:
        """Determine if the implementation is secure based on topological analysis."""
        # Secure if torus structure is present and anomaly score is low
        return self.is_torus_structure and self.anomaly_score < 0.2
    
    @property
    def vulnerability_level(self) -> str:
        """Categorize the vulnerability level based on anomaly score."""
        if not self.is_torus_structure:
            return "critical"
        elif self.anomaly_score >= 0.5:
            return "high"
        elif self.anomaly_score >= 0.2:
            return "medium"
        elif self.anomaly_score >= 0.1:
            return "low"
        else:
            return "secure"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary for serialization."""
        return {
            "status": self.status.value,
            "betti_numbers": {
                "beta_0": self.betti_numbers.beta_0,
                "beta_1": self.betti_numbers.beta_1,
                "beta_2": self.betti_numbers.beta_2
            },
            "uniformity_score": self.uniformity_score,
            "fractal_dimension": self.fractal_dimension,
            "topological_entropy": self.topological_entropy,
            "entropy_anomaly_score": self.entropy_anomaly_score,
            "is_torus_structure": self.is_torus_structure,
            "confidence": self.confidence,
            "anomaly_score": self.anomaly_score,
            "anomaly_types": self.anomaly_types,
            "vulnerabilities": self.vulnerabilities,
            "stability_metrics": self.stability_metrics,
            "nerve_analysis": self.nerve_analysis,
            "smoothing_analysis": self.smoothing_analysis,
            "mapper_analysis": self.mapper_analysis,
            "vulnerability_level": self.vulnerability_level
        }


# ======================
# PROTOCOLS AND INTERFACES
# ======================

class TopologicalAnalyzerProtocol(Protocol):
    """Protocol for topological analysis implementations."""
    
    def analyze_signatures(self, 
                          signatures: List[Tuple[int, int, int]], 
                          n: int) -> TopologicalAnalysisResult:
        """Analyze ECDSA signatures for topological vulnerabilities.
        
        Args:
            signatures: List of (u_r, u_z, r) signature points
            n: Order of the elliptic curve subgroup
            
        Returns:
            TopologicalAnalysisResult: Comprehensive analysis results
        """
        ...
    
    def detect_vulnerabilities(self, 
                              analysis: TopologicalAnalysisResult) -> List[Dict[str, Any]]:
        """Detect specific vulnerabilities from topological analysis.
        
        Args:
            analysis: Topological analysis results
            
        Returns:
            List of detected vulnerabilities with details
        """
        ...
    
    def get_torus_structure(self, 
                           signatures: List[Tuple[int, int, int]], 
                           n: int) -> TorusStructure:
        """Analyze the torus structure of the signature space.
        
        Args:
            signatures: List of (u_r, u_z, r) signature points
            n: Order of the elliptic curve subgroup
            
        Returns:
            TorusStructure: Analyzed torus properties
        """
        ...


class PersistentHomologyProtocol(Protocol):
    """Protocol for persistent homology calculations."""
    
    def compute_persistence(self, 
                           points: np.ndarray, 
                           max_epsilon: float = None) -> List[np.ndarray]:
        """Compute persistent homology for a point cloud.
        
        Args:
            points: Point cloud data
            max_epsilon: Maximum epsilon for filtration (optional)
            
        Returns:
            List of persistence diagrams for each dimension
        """
        ...
    
    def extract_betti_numbers(self, 
                             persistence_diagrams: List[np.ndarray], 
                             epsilon: float) -> BettiNumbers:
        """Extract Betti numbers from persistence diagrams at scale epsilon.
        
        Args:
            persistence_diagrams: Persistence diagrams for each dimension
            epsilon: Scale parameter for extraction
            
        Returns:
            BettiNumbers: Extracted Betti numbers
        """
        ...
    
    def identify_persistent_cycles(self, 
                                  persistence_diagrams: List[np.ndarray],
                                  min_persistence: float = 0.1) -> List[PersistentCycle]:
        """Identify significant persistent cycles in the data.
        
        Args:
            persistence_diagrams: Persistence diagrams for each dimension
            min_persistence: Minimum persistence ratio to consider
            
        Returns:
            List of significant persistent cycles
        """
        ...


class SmoothingProtocol(Protocol):
    """Protocol for smoothing implementation from TCON."""
    def apply_smoothing(self,
                       points: np.ndarray,
                       epsilon: float,
                       kernel: str = 'gaussian') -> np.ndarray:
        """Applies topological smoothing to the point cloud."""
        ...
    
    def compute_persistence_stability(self,
                                     points: np.ndarray,
                                     epsilon_range: List[float]) -> Dict[str, Any]:
        """Computes stability metrics of persistent homology features."""
        ...
    
    def get_stability_map(self, points: np.ndarray) -> np.ndarray:
        """Generates a stability map showing regions of topological instability."""
        ...


# ======================
# HELPER FUNCTIONS
# ======================

def calculate_topological_entropy(points: np.ndarray, 
                                 n: int, 
                                 base: float = 2) -> float:
    """Calculate topological entropy of the signature space.
    
    Topological entropy serves as a quantitative security metric:
    - For secure implementations: h_top > log(n)/2
    - For vulnerable implementations: h_top < log(n)/4
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        base: Logarithm base for entropy calculation
        
    Returns:
        float: Topological entropy value
    """
    if len(points) == 0:
        return 0.0
    
    # Implementation would calculate entropy based on the distribution
    # This is a simplified placeholder
    return np.log2(n) * 0.75  # Placeholder value for demonstration


def check_diagonal_symmetry(points: np.ndarray, n: int) -> Dict[str, float]:
    """Check diagonal symmetry as vulnerability indicator.
    
    For a secure implementation, r(u_r, u_z) = r(u_z, u_r) for all (u_r, u_z).
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Dict containing symmetry violation metrics
    """
    violations = 0
    total = 0
    
    # Check symmetry for sampled points
    for i in range(min(1000, len(points))):
        u_r, u_z, r_val = points[i]
        
        # Find corresponding symmetric point
        # In real implementation, would need to locate the symmetric point
        symmetric_r = r_val  # Placeholder
        
        if abs(r_val - symmetric_r) > 1e-6:
            violations += 1
        total += 1
    
    violation_rate = violations / total if total > 0 else 0.0
    return {
        "violation_count": violations,
        "total_points": total,
        "violation_rate": violation_rate,
        "is_secure": violation_rate < 0.01
    }


def identify_critical_regions(analysis: TopologicalAnalysisResult, 
                            threshold: float = 0.3) -> List[Dict[str, Any]]:
    """Identifies critical regions with anomalous topological features.
    
    Args:
        analysis: Topological analysis results
        threshold: Threshold for identifying critical regions
        
    Returns:
        List of critical regions with details
    """
    critical_regions = []
    
    # Implementation would analyze stability map and other metrics
    # to identify regions with high anomaly scores
    
    # Placeholder implementation
    if analysis.smoothing_analysis and "stability_map" in analysis.smoothing_analysis:
        stability_map = analysis.smoothing_analysis["stability_map"]
        # Find regions with low stability
        for i in range(stability_map.shape[0]):
            for j in range(stability_map.shape[1]):
                if stability_map[i, j] < threshold:
                    critical_regions.append({
                        "region": (i, j),
                        "stability": stability_map[i, j],
                        "type": "stability_anomaly"
                    })
    
    return critical_regions


def compute_spiral_pattern(points: np.ndarray, 
                          n: int, 
                          d: Optional[int] = None) -> Dict[str, Any]:
    """Analyze the spiral pattern in the signature space.
    
    The spiral structure on the torus provides critical security insights:
    - Period T = n / GCD(d-1, n) serves as an indicator of vulnerability
    - When GCD(d-1, n) is large, T is small, indicating regular patterns
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        d: Private key estimate (optional)
        
    Returns:
        Dict containing spiral pattern analysis
    """
    # Implementation would analyze the spiral structure
    # This is a simplified placeholder
    return {
        "slope": 0.0,
        "period": n,
        "consistency_score": 1.0,
        "is_vulnerable": False,
        "vulnerability_score": 0.0
    }


def analyze_symmetry_violations(points: np.ndarray, 
                               n: int) -> Dict[str, Any]:
    """Analyze symmetry violations in the signature space.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptiptic curve subgroup
        
    Returns:
        Dict containing symmetry violation analysis
    """
    # Implementation would analyze symmetry violations
    # This is a simplified placeholder
    return {
        "violation_rate": 0.0,
        "pattern": "uniform",
        "critical_regions": [],
        "vulnerability_score": 0.0
    }
```
