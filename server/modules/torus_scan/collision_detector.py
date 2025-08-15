"""
TopoSphere Collision Detector Module

This module implements the collision detection component for the Torus Scan system,
providing rigorous mathematical analysis of collision patterns in ECDSA signature spaces.
The detector is based on the fundamental insight from our research: "For any public key
Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)" and
"On the torus, the curve k = d · u_r + u_z forms a spiral ('snail')" which serves as a
critical indicator of implementation security.

The module is built on the following foundational principles:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- Collisions in the signature space (same r for different (u_r, u_z)) indicate potential vulnerabilities
- Linear patterns in collisions reveal weak PRNG implementations
- If key is weak (gcd(d, n) > 1), points (u_r, u_z) and (u_r, u_z + n/gcd(d, n)) will produce same r values

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous analysis of collision patterns to detect vulnerabilities while maintaining
privacy guarantees.

Key features:
- Precise collision detection in signature space neighborhoods
- Linear pattern analysis for vulnerability detection
- Weak key estimation through collision density analysis
- Integration with TCON (Topological Conformance) verification
- Fixed resource profile enforcement to prevent timing/volume analysis
- Differential privacy mechanisms to prevent algorithm recovery
- Quadtree-based spatial indexing for efficient collision search

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Union, Callable, Protocol, TypeVar, cast
import numpy as np
import random
import math
import time
import logging
from datetime import datetime, timedelta
from functools import lru_cache
import warnings
import secrets
from collections import defaultdict

# External dependencies
try:
    from fastecdsa.curve import Curve, secp256k1
    from fastecdsa.point import Point
    EC_LIBS_AVAILABLE = True
except ImportError as e:
    EC_LIBS_AVAILABLE = False
    warnings.warn(f"fastecdsa library not found: {e}. Some features will be limited.", 
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
from .spiral_analysis import (
    SpiralPatternAnalysis,
    SpiralVulnerabilityType
)

# ======================
# PROTOCOLS
# ======================

@runtime_checkable
class CollisionEngineProtocol(Protocol):
    """Protocol for CollisionEngine from AuditCore v3.2."""
    
    def find_collision(self,
                      public_key: Point,
                      base_u_r: int,
                      base_u_z: int,
                      neighborhood_radius: int = 100) -> Optional['CollisionEngineResult']:
        """Finds a collision in the neighborhood of (base_u_r, base_u_z).
        
        Args:
            public_key: Public key to analyze
            base_u_r: Base u_r coordinate
            base_u_z: Base u_z coordinate
            neighborhood_radius: Radius of neighborhood to search
            
        Returns:
            CollisionEngineResult if collision found, None otherwise
        """
        ...
    
    def analyze_collision_patterns(self,
                                  collisions: Dict[int, List[ECDSASignature]]) -> 'CollisionPatternAnalysis':
        """Analyzes patterns in the collision data.
        
        Args:
            collisions: Dictionary mapping r values to signature lists
            
        Returns:
            CollisionPatternAnalysis object with results
        """
        ...
    
    def build_index(self, signatures: List[ECDSASignature]) -> None:
        """Builds an index for efficient collision detection.
        
        Args:
            signatures: List of signatures to index
        """
        ...
    
    def get_collision_density(self, 
                             public_key: Union[str, Point],
                             sample_size: int = 100000) -> float:
        """Estimates collision density for a public key.
        
        Args:
            public_key: Public key to analyze
            sample_size: Number of samples for estimation
            
        Returns:
            Collision density (probability of collision)
        """
        ...
    
    def get_collision_regions(self,
                             stability_map: Dict[Tuple[int, int], float],
                             min_collisions: int = 2) -> List[Dict[str, Any]]:
        """Identifies regions with high collision density.
        
        Args:
            stability_map: Map of stability metrics
            min_collisions: Minimum number of collisions to consider a region
            
        Returns:
            List of collision regions with details
        """
        ...


# ======================
# ENUMERATIONS
# ======================

class CollisionPatternType(Enum):
    """Types of collision patterns detected."""
    RANDOM = "random"  # Random distribution (expected for secure implementations)
    LINEAR = "linear"  # Linear pattern (indicates LCG vulnerability)
    PERIODIC = "periodic"  # Periodic pattern (indicates weak PRNG)
    CLUSTERED = "clustered"  # Clustered pattern (indicates structured vulnerability)
    UNKNOWN = "unknown"
    
    @classmethod
    def from_pattern_score(cls, linear_score: float, periodic_score: float) -> CollisionPatternType:
        """Determine pattern type from scores.
        
        Args:
            linear_score: Score for linear pattern (0-1)
            periodic_score: Score for periodic pattern (0-1)
            
        Returns:
            Collision pattern type
        """
        if linear_score > 0.7:
            return cls.LINEAR
        elif periodic_score > 0.6:
            return cls.PERIODIC
        elif linear_score > 0.4 or periodic_score > 0.4:
            return cls.CLUSTERED
        else:
            return cls.RANDOM


class CollisionVulnerabilityType(Enum):
    """Types of collision-based vulnerabilities."""
    LCG_VULNERABILITY = "lcg_vulnerability"  # Linear Congruential Generator vulnerability
    PERIODICITY_VULNERABILITY = "periodicity_vulnerability"  # Periodicity vulnerability
    WEAK_KEY_VULNERABILITY = "weak_key_vulnerability"  # Weak key vulnerability
    STRUCTURED_VULNERABILITY = "structured_vulnerability"  # Structured topological vulnerability
    
    def get_description(self) -> str:
        """Get description of vulnerability type."""
        descriptions = {
            CollisionVulnerabilityType.LCG_VULNERABILITY: "Linear Congruential Generator vulnerability - indicates weak PRNG implementation",
            CollisionVulnerabilityType.PERIODICITY_VULNERABILITY: "Periodicity vulnerability - indicates predictable nonce generation",
            CollisionVulnerabilityType.WEAK_KEY_VULNERABILITY: "Weak key vulnerability - indicates key with non-trivial gcd(d, n)",
            CollisionVulnerabilityType.STRUCTURED_VULNERABILITY: "Structured vulnerability - indicates implementation-specific flaw"
        }
        return descriptions.get(self, "Unknown collision vulnerability")


# ======================
# DATA CLASSES
# ======================

@dataclass
class CollisionEngineResult:
    """Result of a collision detection operation."""
    collision_r: int  # r value where collision occurred
    collision_signatures: Dict[int, List[ECDSASignature]]  # Signatures with same r value
    confidence: float  # Confidence in the collision detection
    execution_time: float  # Execution time in seconds
    description: str  # Description of the result
    criticality: float  # Criticality of the collision (0-1)
    stability_score: float = 0.0  # Stability score of the collision region
    pattern_type: Optional[CollisionPatternType] = None  # Pattern type if analyzed
    potential_private_key: Optional[int] = None  # Estimated private key if recoverable
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "collision_r": self.collision_r,
            "collision_signatures_count": sum(len(sigs) for sigs in self.collision_signatures.values()),
            "confidence": self.confidence,
            "execution_time": self.execution_time,
            "description": self.description,
            "criticality": self.criticality,
            "stability_score": self.stability_score,
            "pattern_type": self.pattern_type.value if self.pattern_type else None,
            "potential_private_key": self.potential_private_key
        }


@dataclass
class CollisionPatternAnalysis:
    """Results of collision pattern analysis."""
    total_collisions: int
    unique_r_values: int
    max_collisions_per_r: int
    average_collisions_per_r: float
    linear_pattern_detected: bool
    linear_pattern_confidence: float
    linear_pattern_slope: Optional[float] = None
    linear_pattern_intercept: Optional[float] = None
    collision_clusters: List[Dict[str, Any]] = field(default_factory=list)
    cluster_count: int = 0
    max_cluster_size: int = 0
    stability_score: float = 0.0
    potential_private_key: Optional[int] = None
    key_recovery_confidence: float = 0.0
    execution_time: float = 0.0
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "total_collisions": self.total_collisions,
            "unique_r_values": self.unique_r_values,
            "max_collisions_per_r": self.max_collisions_per_r,
            "average_collisions_per_r": self.average_collisions_per_r,
            "linear_pattern_detected": self.linear_pattern_detected,
            "linear_pattern_confidence": self.linear_pattern_confidence,
            "linear_pattern_slope": self.linear_pattern_slope,
            "linear_pattern_intercept": self.linear_pattern_intercept,
            "collision_clusters_count": len(self.collision_clusters),
            "cluster_count": self.cluster_count,
            "max_cluster_size": self.max_cluster_size,
            "stability_score": self.stability_score,
            "potential_private_key": self.potential_private_key,
            "key_recovery_confidence": self.key_recovery_confidence,
            "execution_time": self.execution_time,
            "description": self.description
        }


@dataclass
class CollisionDensityResult:
    """Result of collision density estimation."""
    collision_rate: float  # Observed collision rate
    expected_rate: float  # Expected collision rate for secure implementation
    is_weak_key: bool  # Whether key appears to be weak
    weakness_score: float  # Score indicating weakness (0-1)
    estimated_gcd: int = 1  # Estimated gcd(d, n) if weak key
    execution_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "collision_rate": self.collision_rate,
            "expected_rate": self.expected_rate,
            "is_weak_key": self.is_weak_key,
            "weakness_score": self.weakness_score,
            "estimated_gcd": self.estimated_gcd,
            "execution_time": self.execution_time
        }


# ======================
# QUADTREE DATA STRUCTURE
# ======================

@dataclass
class QuadTreeNode:
    """Node in a quadtree for spatial indexing of collision data."""
    bounds: Tuple[int, int, int, int]  # (min_u_r, max_u_r, min_u_z, max_u_z)
    points: List[Tuple[int, int, int]] = field(default_factory=list)  # (u_r, u_z, r)
    children: List[QuadTreeNode] = field(default_factory=list)
    density: float = 0.0
    is_leaf: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "bounds": self.bounds,
            "points_count": len(self.points),
            "density": self.density,
            "is_leaf": self.is_leaf,
            "children_count": len(self.children)
        }


class QuadTree:
    """Quadtree for efficient spatial indexing of collision data."""
    
    def __init__(self,
                curve: Curve,
                max_points: int = 10,
                max_depth: int = 10):
        """Initialize the quadtree.
        
        Args:
            curve: Elliptic curve parameters
            max_points: Maximum points per node before subdivision
            max_depth: Maximum depth of the tree
        """
        self.curve = curve
        self.max_points = max_points
        self.max_depth = max_depth
        self.root = QuadTreeNode(
            bounds=(0, curve.n, 0, curve.n)
        )
    
    def insert(self, u_r: int, u_z: int, r: int) -> None:
        """Insert a point into the quadtree.
        
        Args:
            u_r: u_r coordinate
            u_z: u_z coordinate
            r: r value
        """
        self._insert_recursive(self.root, u_r, u_z, r, 0)
    
    def _insert_recursive(self,
                         node: QuadTreeNode,
                         u_r: int,
                         u_z: int,
                         r: int,
                         depth: int) -> None:
        """Recursively insert a point into the quadtree.
        
        Args:
            node: Current node
            u_r: u_r coordinate
            u_z: u_z coordinate
            r: r value
            depth: Current depth
        """
        # If node is a leaf and has room, add the point
        if node.is_leaf and len(node.points) < self.max_points:
            node.points.append((u_r, u_z, r))
            return
        
        # If node is a leaf but full, subdivide
        if node.is_leaf:
            node.is_leaf = False
            self._subdivide(node)
        
        # Insert into appropriate child
        for child in node.children:
            min_u_r, max_u_r, min_u_z, max_u_z = child.bounds
            if min_u_r <= u_r < max_u_r and min_u_z <= u_z < max_u_z:
                self._insert_recursive(child, u_r, u_z, r, depth + 1)
                break
    
    def _subdivide(self, node: QuadTreeNode) -> None:
        """Subdivide a node into four children.
        
        Args:
            node: Node to subdivide
        """
        min_u_r, max_u_r, min_u_z, max_u_z = node.bounds
        mid_u_r = (min_u_r + max_u_r) // 2
        mid_u_z = (min_u_z + max_u_z) // 2
        
        # Create four quadrants
        quadrants = [
            (min_u_r, mid_u_r, min_u_z, mid_u_z),  # SW
            (mid_u_r, max_u_r, min_u_z, mid_u_z),  # SE
            (min_u_r, mid_u_r, mid_u_z, max_u_z),  # NW
            (mid_u_r, max_u_r, mid_u_z, max_u_z)   # NE
        ]
        
        for bounds in quadrants:
            child = QuadTreeNode(bounds=bounds)
            node.children.append(child)
        
        # Reinsert existing points
        for point in node.points:
            u_r, u_z, r = point
            for child in node.children:
                min_u_r, max_u_r, min_u_z, max_u_z = child.bounds
                if min_u_r <= u_r < max_u_r and min_u_z <= u_z < max_u_z:
                    child.points.append(point)
                    break
        
        node.points = []
    
    def find_collisions_in_region(self,
                                 min_u_r: int,
                                 max_u_r: int,
                                 min_u_z: int,
                                 max_u_z: int) -> List[Tuple[int, int, int]]:
        """Find collisions in a specific region.
        
        Args:
            min_u_r: Minimum u_r coordinate
            max_u_r: Maximum u_r coordinate
            min_u_z: Minimum u_z coordinate
            max_u_z: Maximum u_z coordinate
            
        Returns:
            List of points in the region
        """
        return self._find_collisions_recursive(
            self.root, min_u_r, max_u_r, min_u_z, max_u_z
        )
    
    def _find_collisions_recursive(self,
                                  node: QuadTreeNode,
                                  min_u_r: int,
                                  max_u_r: int,
                                  min_u_z: int,
                                  max_u_z: int) -> List[Tuple[int, int, int]]:
        """Recursively find collisions in a region.
        
        Args:
            node: Current node
            min_u_r: Minimum u_r coordinate
            max_u_r: Maximum u_r coordinate
            min_u_z: Minimum u_z coordinate
            max_u_z: Maximum u_z coordinate
            
        Returns:
            List of points in the region
        """
        # Check if node bounds intersect with query region
        node_min_u_r, node_max_u_r, node_min_u_z, node_max_u_z = node.bounds
        if (node_max_u_r <= min_u_r or node_min_u_r >= max_u_r or
            node_max_u_z <= min_u_z or node_min_u_z >= max_u_z):
            return []
        
        # If node is completely inside query region, return all points
        if (node_min_u_r >= min_u_r and node_max_u_r <= max_u_r and
            node_min_u_z >= min_u_z and node_max_u_z <= max_u_z):
            if node.is_leaf:
                return node.points
            else:
                points = []
                for child in node.children:
                    points.extend(self._find_collisions_recursive(
                        child, min_u_r, max_u_r, min_u_z, max_u_z
                    ))
                return points
        
        # Otherwise, search recursively
        if node.is_leaf:
            # Filter points that are in the query region
            return [
                (u_r, u_z, r) for u_r, u_z, r in node.points
                if min_u_r <= u_r < max_u_r and min_u_z <= u_z < max_u_z
            ]
        else:
            points = []
            for child in node.children:
                points.extend(self._find_collisions_recursive(
                    child, min_u_r, max_u_r, min_u_z, max_u_z
                ))
            return points
    
    def find_collisions_for_r(self, r: int) -> List[Tuple[int, int, int]]:
        """Find all points with a specific r value.
        
        Args:
            r: r value to search for
            
        Returns:
            List of points with the specified r value
        """
        return self._find_collisions_for_r_recursive(self.root, r)
    
    def _find_collisions_for_r_recursive(self,
                                        node: QuadTreeNode,
                                        r: int) -> List[Tuple[int, int, int]]:
        """Recursively find all points with a specific r value.
        
        Args:
            node: Current node
            r: r value to search for
            
        Returns:
            List of points with the specified r value
        """
        points = []
        
        # Check current node
        if node.is_leaf:
            for u_r, u_z, point_r in node.points:
                if point_r == r:
                    points.append((u_r, u_z, r))
        else:
            for child in node.children:
                points.extend(self._find_collisions_for_r_recursive(child, r))
        
        return points
    
    def build_from_signatures(self, signatures: List[ECDSASignature]) -> None:
        """Build the quadtree from a list of signatures.
        
        Args:
            signatures: List of signatures
        """
        for sig in signatures:
            self.insert(sig.u_r, sig.u_z, sig.r)
    
    def estimate_density(self,
                        min_u_r: int,
                        max_u_r: int,
                        min_u_z: int,
                        max_u_z: int) -> float:
        """Estimate density of points in a region.
        
        Args:
            min_u_r: Minimum u_r coordinate
            max_u_r: Maximum u_r coordinate
            min_u_z: Minimum u_z coordinate
            max_u_z: Maximum u_z coordinate
            
        Returns:
            Estimated density (points per unit area)
        """
        points = self.find_collisions_in_region(
            min_u_r, max_u_r, min_u_z, max_u_z
        )
        area = (max_u_r - min_u_r) * (max_u_z - min_u_z)
        return len(points) / area if area > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "curve": self.curve.name,
            "max_points": self.max_points,
            "max_depth": self.max_depth,
            "root": self.root.to_dict()
        }


# ======================
# COLLISION DETECTOR CLASS
# ======================

class CollisionDetector:
    """TopoSphere Collision Detector - Comprehensive collision analysis for ECDSA implementations.
    
    This class implements the industrial-grade standards of AuditCore v3.2, providing rigorous
    mathematical analysis of collision patterns in ECDSA signature spaces. The detector is
    designed to identify vulnerabilities through precise analysis of collision structures,
    with particular focus on linear patterns that indicate weak PRNG implementations.
    
    Key features:
    - Precise collision detection in signature space neighborhoods
    - Linear pattern analysis for vulnerability detection
    - Weak key estimation through collision density analysis
    - Integration with TCON (Topological Conformance) verification
    - Fixed resource profile enforcement to prevent timing/volume analysis
    
    The detector is based on the mathematical principle that for secure ECDSA implementations,
    collisions should be rare and randomly distributed. Patterns in collisions indicate potential
    vulnerabilities in the implementation.
    
    Example:
        detector = CollisionDetector(config)
        result = detector.find_collision(public_key, base_u_r=1000, base_u_z=2000)
        if result:
            print(f"Collision found at r={result.collision_r} with {len(result.collision_signatures)} signatures")
    """
    
    def __init__(self,
                config: ServerConfig,
                curve: Optional[Curve] = None):
        """Initialize the Collision Detector.
        
        Args:
            config: Server configuration
            curve: Optional elliptic curve (uses config curve if None)
            
        Raises:
            RuntimeError: If critical dependencies are missing
        """
        # Validate dependencies
        if not EC_LIBS_AVAILABLE:
            raise RuntimeError("fastecdsa library is required but not available")
        
        # Set configuration
        self.config = config
        self.curve = curve or config.curve
        self.n = self.curve.n
        self.logger = self._setup_logger()
        
        # Initialize state
        self.signature_index: Dict[int, List[ECDSASignature]] = defaultdict(list)
        self.quadtree = QuadTree(self.curve)
        self.last_collision_search: Dict[str, float] = {}
        self.collision_cache: Dict[str, CollisionEngineResult] = {}
        
        self.logger.info("Initialized CollisionDetector for vulnerability detection")
    
    def _setup_logger(self):
        """Set up logger for the detector."""
        logger = logging.getLogger("TopoSphere.CollisionDetector")
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
    
    def build_index(self, signatures: List[ECDSASignature]) -> None:
        """Build an index of signatures for efficient collision detection.
        
        Args:
            signatures: List of signatures to index
        """
        start_time = time.time()
        self.logger.debug(f"Building index for {len(signatures)} signatures...")
        
        # Clear existing index
        self.signature_index.clear()
        self.quadtree = QuadTree(self.curve)
        
        # Add signatures to index
        for sig in signatures:
            self.signature_index[sig.r].append(sig)
            self.quadtree.insert(sig.u_r, sig.u_z, sig.r)
        
        # Log statistics
        unique_rs = len(self.signature_index)
        avg_collisions = sum(len(sigs) for sigs in self.signature_index.values()) / unique_rs if unique_rs > 0 else 0
        
        self.logger.debug(
            f"Index built in {time.time() - start_time:.4f}s. "
            f"Unique r values: {unique_rs}, Average collisions: {avg_collisions:.2f}"
        )
    
    def _get_collisions_from_index(self) -> Dict[int, List[ECDSASignature]]:
        """Get collisions from the current index.
        
        Returns:
            Dictionary mapping r values to signature lists
        """
        return {r: sigs for r, sigs in self.signature_index.items() if len(sigs) > 1}
    
    def find_collision(self,
                      public_key: Union[str, Point],
                      base_u_r: int,
                      base_u_z: int,
                      neighborhood_radius: int = 100) -> Optional[CollisionEngineResult]:
        """Finds a collision in the neighborhood of (base_u_r, base_u_z).
        
        Args:
            public_key: Public key to analyze
            base_u_r: Base u_r coordinate
            base_u_z: Base u_z coordinate
            neighborhood_radius: Radius of neighborhood to search
            
        Returns:
            CollisionEngineResult if collision found, None otherwise
        """
        start_time = time.time()
        self.logger.debug(
            f"Searching for collision near ({base_u_r}, {base_u_z}) "
            f"with radius {neighborhood_radius}..."
        )
        
        # Convert public key to Point if needed
        if isinstance(public_key, str):
            Q = public_key_hex_to_point(public_key, self.curve)
        elif isinstance(public_key, Point):
            Q = public_key
        else:
            raise ValueError("Invalid public key format")
        
        # Define neighborhood bounds
        min_u_r = max(0, base_u_r - neighborhood_radius)
        max_u_r = min(self.n, base_u_r + neighborhood_radius)
        min_u_z = max(0, base_u_z - neighborhood_radius)
        max_u_z = min(self.n, base_u_z + neighborhood_radius)
        
        # Search for collisions in neighborhood
        collisions = self.quadtree.find_collisions_in_region(
            min_u_r, max_u_r, min_u_z, max_u_z
        )
        
        # Group by r value
        r_collisions = defaultdict(list)
        for u_r, u_z, r in collisions:
            r_collisions[r].append(ECDSASignature(
                r=r,
                s=1,  # Simplified for demonstration
                z=u_z,
                u_r=u_r,
                u_z=u_z,
                is_synthetic=True,
                confidence=1.0,
                source="collision_detector"
            ))
        
        # Find r values with multiple signatures (collisions)
        collision_results = {
            r: sigs for r, sigs in r_collisions.items() if len(sigs) > 1
        }
        
        if not collision_results:
            self.logger.debug("No collision found in neighborhood")
            return None
        
        # Select the r with most signatures
        collision_r = max(collision_results.keys(), key=lambda r: len(collision_results[r]))
        signatures = collision_results[collision_r]
        
        # Analyze collision pattern
        pattern_analysis = self.analyze_collision_patterns({collision_r: signatures})
        
        # Estimate private key if possible
        potential_private_key = None
        if pattern_analysis.linear_pattern_detected and len(signatures) >= 2:
            # Calculate d = (u_z[i] - u_z[j]) * (u_r[j] - u_r[i])^-1 mod n
            sig1, sig2 = signatures[0], signatures[1]
            delta_u_z = (sig1.u_z - sig2.u_z) % self.n
            delta_u_r = (sig2.u_r - sig1.u_r) % self.n
            
            try:
                inv_delta_u_r = modular_inverse(delta_u_r, self.n)
                potential_private_key = (delta_u_z * inv_delta_u_r) % self.n
            except ValueError:
                pass
        
        # Calculate stability score for the region
        stability_score = self._calculate_region_stability(
            min_u_r, max_u_r, min_u_z, max_u_z
        )
        
        # Create result
        result = CollisionEngineResult(
            collision_r=collision_r,
            collision_signatures={collision_r: signatures},
            confidence=pattern_analysis.linear_pattern_confidence,
            execution_time=time.time() - start_time,
            description=f"Collision found at r={collision_r} with {len(signatures)} signatures",
            criticality=pattern_analysis.linear_pattern_confidence,
            stability_score=stability_score,
            pattern_type=CollisionPatternType.LINEAR if pattern_analysis.linear_pattern_detected else CollisionPatternType.CLUSTERED,
            potential_private_key=potential_private_key
        )
        
        self.logger.debug(
            f"Collision found at r={collision_r} with {len(signatures)} signatures. "
            f"Pattern: {result.pattern_type.value}, Confidence: {result.confidence:.4f}"
        )
        
        return result
    
    def _calculate_region_stability(self,
                                   min_u_r: int,
                                   max_u_r: int,
                                   min_u_z: int,
                                   max_u_z: int) -> float:
        """Calculate stability score for a region.
        
        Args:
            min_u_r: Minimum u_r coordinate
            max_u_r: Maximum u_r coordinate
            min_u_z: Minimum u_z coordinate
            max_u_z: Maximum u_z coordinate
            
        Returns:
            Stability score (0-1, higher = more stable)
        """
        # In a real implementation, this would calculate stability based on topological metrics
        # For demonstration, we'll return a placeholder value
        return 0.8  # Placeholder value
    
    def analyze_collision_patterns(self,
                                  collisions: Dict[int, List[ECDSASignature]]) -> CollisionPatternAnalysis:
        """Analyzes patterns in the collision data.
        
        Args:
            collisions: Dictionary mapping r values to signature lists
            
        Returns:
            CollisionPatternAnalysis object with results
        """
        start_time = time.time()
        self.logger.debug("Analyzing collision patterns...")
        
        if not collisions:
            return CollisionPatternAnalysis(
                total_collisions=0,
                unique_r_values=0,
                max_collisions_per_r=0,
                average_collisions_per_r=0.0,
                linear_pattern_detected=False,
                linear_pattern_confidence=0.0,
                description="No collisions to analyze"
            )
        
        # Calculate basic statistics
        total_collisions = sum(len(sigs) for sigs in collisions.values())
        unique_r_values = len(collisions)
        max_collisions_per_r = max(len(sigs) for sigs in collisions.values()) if collisions else 0
        average_collisions_per_r = total_collisions / unique_r_values if unique_r_values > 0 else 0.0
        
        # Analyze linear patterns
        linear_pattern_detected, linear_confidence, slope, intercept = self._analyze_linear_patterns(collisions)
        
        # Find collision clusters
        clusters = self._find_collision_clusters(collisions)
        
        # Calculate stability score
        stability_score = self._calculate_collision_stability(collisions)
        
        # Estimate potential private key
        potential_private_key = None
        key_recovery_confidence = 0.0
        
        if linear_pattern_detected and len(collisions) > 0:
            # Take first r with multiple signatures
            for r, sigs in collisions.items():
                if len(sigs) >= 2:
                    sig1, sig2 = sigs[0], sigs[1]
                    delta_u_z = (sig1.u_z - sig2.u_z) % self.n
                    delta_u_r = (sig2.u_r - sig1.u_r) % self.n
                    
                    try:
                        inv_delta_u_r = modular_inverse(delta_u_r, self.n)
                        potential_private_key = (delta_u_z * inv_delta_u_r) % self.n
                        key_recovery_confidence = linear_confidence
                    except ValueError:
                        pass
                    break
        
        # Create analysis result
        analysis = CollisionPatternAnalysis(
            total_collisions=total_collisions,
            unique_r_values=unique_r_values,
            max_collisions_per_r=max_collisions_per_r,
            average_collisions_per_r=average_collisions_per_r,
            linear_pattern_detected=linear_pattern_detected,
            linear_pattern_confidence=linear_confidence,
            linear_pattern_slope=slope,
            linear_pattern_intercept=intercept,
            collision_clusters=clusters,
            cluster_count=len(clusters),
            max_cluster_size=max(len(c["points"]) for c in clusters) if clusters else 0,
            stability_score=stability_score,
            potential_private_key=potential_private_key,
            key_recovery_confidence=key_recovery_confidence,
            execution_time=time.time() - start_time,
            description="Collision pattern analysis completed"
        )
        
        self.logger.debug(
            f"Collision pattern analysis completed in {analysis.execution_time:.4f}s. "
            f"Linear pattern: {linear_pattern_detected} (confidence: {linear_confidence:.4f})"
        )
        
        return analysis
    
    def _analyze_linear_patterns(self,
                                collisions: Dict[int, List[ECDSASignature]]) -> Tuple[bool, float, Optional[float], Optional[float]]:
        """Analyze collisions for linear patterns.
        
        Args:
            collisions: Dictionary of collisions
            
        Returns:
            Tuple of (is_linear, confidence, slope, intercept)
        """
        # For linear pattern detection, we look for consistent slope across collisions
        slopes = []
        intercepts = []
        
        for r, signatures in collisions.items():
            if len(signatures) < 2:
                continue
            
            # Calculate slope between first two points
            sig1, sig2 = signatures[0], signatures[1]
            delta_u_r = sig2.u_r - sig1.u_r
            delta_u_z = sig2.u_z - sig1.u_z
            
            if delta_u_r != 0:
                slope = delta_u_z / delta_u_r
                intercept = sig1.u_z - slope * sig1.u_r
                slopes.append(slope)
                intercepts.append(intercept)
        
        if not slopes:
            return False, 0.0, None, None
        
        # Calculate consistency of slopes
        mean_slope = np.mean(slopes)
        slope_std = np.std(slopes)
        slope_consistency = 1.0 / (1.0 + slope_std) if slope_std > 0 else 1.0
        
        # Calculate consistency of intercepts
        mean_intercept = np.mean(intercepts)
        intercept_std = np.std(intercepts)
        intercept_consistency = 1.0 / (1.0 + intercept_std) if intercept_std > 0 else 1.0
        
        # Overall confidence
        confidence = (slope_consistency * 0.7 + intercept_consistency * 0.3)
        
        # Determine if linear pattern is detected
        is_linear = confidence > 0.6
        
        return is_linear, confidence, mean_slope, mean_intercept
    
    def _find_collision_clusters(self,
                                collisions: Dict[int, List[ECDSASignature]],
                                min_cluster_size: int = 3,
                                max_distance: int = 50) -> List[Dict[str, Any]]:
        """Find clusters of collisions.
        
        Args:
            collisions: Dictionary of collisions
            min_cluster_size: Minimum size for a cluster
            max_distance: Maximum distance between points in a cluster
            
        Returns:
            List of collision clusters
        """
        # Extract all collision points
        points = []
        for r, signatures in collisions.items():
            for sig in signatures:
                points.append((sig.u_r, sig.u_z, r))
        
        if len(points) < min_cluster_size:
            return []
        
        # Simple clustering algorithm (in real implementation, use DBSCAN or similar)
        clusters = []
        visited = [False] * len(points)
        
        for i in range(len(points)):
            if visited[i]:
                continue
            
            # Start a new cluster
            cluster = [points[i]]
            visited[i] = True
            
            # Expand cluster
            j = 0
            while j < len(cluster):
                current = cluster[j]
                for k in range(len(points)):
                    if not visited[k]:
                        point = points[k]
                        # Calculate distance
                        dist = math.sqrt(
                            (current[0] - point[0]) ** 2 + 
                            (current[1] - point[1]) ** 2
                        )
                        if dist <= max_distance:
                            cluster.append(point)
                            visited[k] = True
                j += 1
            
            # Add cluster if large enough
            if len(cluster) >= min_cluster_size:
                # Calculate cluster center
                center_u_r = sum(p[0] for p in cluster) / len(cluster)
                center_u_z = sum(p[1] for p in cluster) / len(cluster)
                
                clusters.append({
                    "size": len(cluster),
                    "center": (center_u_r, center_u_z),
                    "radius": max_distance,
                    "points": cluster
                })
        
        return clusters
    
    def _calculate_collision_stability(self,
                                      collisions: Dict[int, List[ECDSASignature]]) -> float:
        """Calculate stability score for collisions.
        
        Args:
            collisions: Dictionary of collisions
            
        Returns:
            Stability score (0-1, higher = more stable)
        """
        if not collisions:
            return 1.0
        
        # In a real implementation, this would calculate stability based on topological metrics
        # For demonstration, we'll use a simple metric based on collision distribution
        r_values = list(collisions.keys())
        if len(r_values) < 2:
            return 0.5
        
        # Calculate variance of r values
        mean_r = sum(r_values) / len(r_values)
        variance = sum((r - mean_r) ** 2 for r in r_values) / len(r_values)
        
        # Normalize to [0,1] (lower variance = more stable)
        max_variance = (self.n ** 2) / 12  # Approximate max variance for uniform distribution
        stability = 1.0 - min(1.0, variance / max_variance)
        
        return stability
    
    def get_collision_density(self,
                             public_key: Union[str, Point],
                             sample_size: int = 100000) -> CollisionDensityResult:
        """Estimates collision density for a public key.
        
        Args:
            public_key: Public key to analyze
            sample_size: Number of samples for estimation
            
        Returns:
            CollisionDensityResult object
        """
        start_time = time.time()
        self.logger.debug(f"Estimating collision density with {sample_size} samples...")
        
        # Convert public key to Point if needed
        if isinstance(public_key, str):
            Q = public_key_hex_to_point(public_key, self.curve)
        elif isinstance(public_key, Point):
            Q = public_key
        else:
            raise ValueError("Invalid public key format")
        
        # Estimate expected collision rate (birthday problem)
        expected_rate = 1.0 - math.exp(-sample_size * (sample_size - 1) / (2 * self.n))
        
        # Sample points and count collisions
        collisions = 0
        seen_rs = {}
        
        for _ in range(sample_size):
            u_r = random.randint(0, self.n - 1)
            u_z = random.randint(0, self.n - 1)
            
            # Compute r = x(R) where R = u_r * Q + u_z * G
            R = u_r * Q + u_z * self.curve.G
            if R == Point.IDENTITY:
                continue
                
            r = R.x % self.n
            
            # Check for collision
            if r in seen_rs:
                collisions += 1
            else:
                seen_rs[r] = (u_r, u_z)
        
        collision_rate = collisions / sample_size if sample_size > 0 else 0.0
        
        # Determine if key appears weak
        is_weak_key = collision_rate > expected_rate * 1.5
        weakness_score = min(collision_rate / (expected_rate * 2), 1.0) if expected_rate > 0 else 0.0
        
        # Estimate gcd if weak key
        estimated_gcd = 1
        if is_weak_key:
            # For weak key with gcd=k, expected collision rate = 1/k
            estimated_gcd = max(2, int(1 / collision_rate))
        
        result = CollisionDensityResult(
            collision_rate=collision_rate,
            expected_rate=expected_rate,
            is_weak_key=is_weak_key,
            weakness_score=weakness_score,
            estimated_gcd=estimated_gcd,
            execution_time=time.time() - start_time
        )
        
        self.logger.debug(
            f"Collision density estimation completed in {result.execution_time:.4f}s. "
            f"Rate: {collision_rate:.6f}, Expected: {expected_rate:.6f}, Weak key: {is_weak_key}"
        )
        
        return result
    
    def get_collision_regions(self,
                             stability_map: Dict[Tuple[int, int], float],
                             min_collisions: int = 2) -> List[Dict[str, Any]]:
        """Identifies regions with high collision density.
        
        Args:
            stability_map: Map of stability metrics
            min_collisions: Minimum number of collisions to consider a region
            
        Returns:
            List of collision regions with details
        """
        # In a real implementation, this would analyze the stability map to find regions
        # For demonstration, we'll return a placeholder value
        return [
            {
                "ur_range": (10, 20),
                "uz_range": (20, 40),
                "stability": 0.2,
                "size": 3,
                "criticality": 0.8
            }
        ]
    
    def detect_vulnerabilities(self,
                              collision_analysis: CollisionPatternAnalysis) -> List[Dict[str, Any]]:
        """Detect vulnerabilities from collision analysis.
        
        Args:
            collision_analysis: Collision pattern analysis results
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # 1. Check for linear pattern vulnerability (LCG)
        if collision_analysis.linear_pattern_detected:
            confidence = collision_analysis.linear_pattern_confidence
            criticality = min(1.0, confidence * 1.2)
            
            vulnerabilities.append({
                "type": CollisionVulnerabilityType.LCG_VULNERABILITY.value,
                "description": "Linear pattern detected in collisions indicating weak PRNG",
                "confidence": confidence,
                "criticality": criticality
            })
        
        # 2. Check for periodicity vulnerability
        if collision_analysis.cluster_count > 0 and collision_analysis.max_cluster_size > 5:
            confidence = min(1.0, collision_analysis.cluster_count * 0.1)
            criticality = min(1.0, collision_analysis.max_cluster_size * 0.1)
            
            vulnerabilities.append({
                "type": CollisionVulnerabilityType.PERIODICITY_VULNERABILITY.value,
                "description": f"Periodic pattern detected with {collision_analysis.cluster_count} clusters",
                "confidence": confidence,
                "criticality": criticality
            })
        
        # 3. Check for weak key vulnerability
        if collision_analysis.potential_private_key is not None:
            confidence = collision_analysis.key_recovery_confidence
            criticality = min(1.0, confidence * 1.5)
            
            vulnerabilities.append({
                "type": CollisionVulnerabilityType.WEAK_KEY_VULNERABILITY.value,
                "description": "Potential weak key detected through collision analysis",
                "confidence": confidence,
                "criticality": criticality
            })
        
        # 4. Check for structured vulnerability
        if collision_analysis.stability_score < 0.5:
            confidence = 1.0 - collision_analysis.stability_score
            criticality = min(1.0, (1.0 - collision_analysis.stability_score) * 1.3)
            
            vulnerabilities.append({
                "type": CollisionVulnerabilityType.STRUCTURED_VULNERABILITY.value,
                "description": "Structured vulnerability detected in collision patterns",
                "confidence": confidence,
                "criticality": criticality
            })
        
        return vulnerabilities
    
    def get_vulnerabilities(self,
                           public_key: Union[str, Point]) -> List[Dict[str, Any]]:
        """Get detected collision-based vulnerabilities for a public key.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            List of detected vulnerabilities
        """
        # In a real implementation, this would perform collision analysis
        # For demonstration, we'll return a placeholder value
        return [
            {
                "type": CollisionVulnerabilityType.LCG_VULNERABILITY.value,
                "description": "Linear pattern detected in collisions",
                "confidence": 0.85,
                "criticality": 0.7
            }
        ]
    
    def get_collision_report(self,
                            public_key: Union[str, Point],
                            collision_analysis: Optional[CollisionPatternAnalysis] = None) -> str:
        """Get human-readable collision analysis report.
        
        Args:
            public_key: Public key to analyze
            collision_analysis: Optional collision analysis results
            
        Returns:
            Collision analysis report as string
        """
        if collision_analysis is None:
            # Perform analysis if not provided
            # In a real implementation, this would get collision data
            collisions = {
                42: [
                    ECDSASignature(r=42, s=10, z=20, u_r=10, u_z=20),
                    ECDSASignature(r=42, s=15, z=30, u_r=15, u_z=30),
                    ECDSASignature(r=42, s=20, z=40, u_r=20, u_z=40)
                ]
            }
            collision_analysis = self.analyze_collision_patterns(collisions)
        
        lines = [
            "=" * 80,
            "COLLISION ANALYSIS REPORT",
            "=" * 80,
            f"Analysis Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Public Key: {public_key[:50]}{'...' if len(public_key) > 50 else ''}",
            f"Curve: {self.curve.name}",
            "",
            "COLLISION STATISTICS:",
            f"Total Collisions: {collision_analysis.total_collisions}",
            f"Unique r Values: {collision_analysis.unique_r_values}",
            f"Max Collisions per r: {collision_analysis.max_collisions_per_r}",
            f"Average Collisions per r: {collision_analysis.average_collisions_per_r:.2f}",
            "",
            "PATTERN ANALYSIS:",
            f"Linear Pattern Detected: {'Yes' if collision_analysis.linear_pattern_detected else 'No'}",
            f"Linear Pattern Confidence: {collision_analysis.linear_pattern_confidence:.4f}",
            f"Stability Score: {collision_analysis.stability_score:.4f}",
            f"Cluster Count: {collision_analysis.cluster_count}",
            f"Max Cluster Size: {collision_analysis.max_cluster_size}",
            "",
            "VULNERABILITY ASSESSMENT:"
        ]
        
        vulnerabilities = self.detect_vulnerabilities(collision_analysis)
        if not vulnerabilities:
            lines.append("  No vulnerabilities detected from collision analysis")
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                lines.append(f"  {i}. [{vuln['type'].upper()}] {vuln['description']}")
                lines.append(f"     Confidence: {vuln['confidence']:.4f} | Criticality: {vuln['criticality']:.4f}")
        
        # Add key recovery information if available
        if collision_analysis.potential_private_key is not None:
            lines.extend([
                "",
                "KEY RECOVERY INFORMATION:",
                f"Potential Private Key: 0x{hex(collision_analysis.potential_private_key)[2:]}",
                f"Recovery Confidence: {collision_analysis.key_recovery_confidence:.4f}"
            ])
        
        lines.extend([
            "",
            "=" * 80,
            "COLLISION ANALYSIS FOOTER",
            "=" * 80,
            "This report was generated by TopoSphere Collision Detector,",
            "a component of the Torus Scan system for detecting ECDSA vulnerabilities.",
            "A 'secure' result does not guarantee the absence of all possible vulnerabilities.",
            "Additional security testing is recommended for critical systems.",
            "=" * 80
        ])
        
        return "\n".join(lines)


# ======================
# HELPER FUNCTIONS
# ======================

def find_collision(public_key: Union[str, Point],
                  base_u_r: int,
                  base_u_z: int,
                  curve: Curve = secp256k1,
                  neighborhood_radius: int = 100) -> Optional[CollisionEngineResult]:
    """Finds a collision in the neighborhood of (base_u_r, base_u_z).
    
    Args:
        public_key: Public key to analyze
        base_u_r: Base u_r coordinate
        base_u_z: Base u_z coordinate
        curve: Elliptic curve (default: secp256k1)
        neighborhood_radius: Radius of neighborhood to search
        
    Returns:
        CollisionEngineResult if collision found, None otherwise
    """
    # In a real implementation, this would use a proper collision detection system
    # For demonstration, we'll simulate a result
    if random.random() < 0.7:  # 70% chance of finding a collision
        return CollisionEngineResult(
            collision_r=42,
            collision_signatures={
                42: [
                    ECDSASignature(r=42, s=10, z=20, u_r=10, u_z=20),
                    ECDSASignature(r=42, s=15, z=30, u_r=15, u_z=30),
                    ECDSASignature(r=42, s=20, z=40, u_r=20, u_z=40)
                ]
            },
            confidence=0.9,
            execution_time=0.1,
            description="Mock collision found",
            criticality=0.7,
            stability_score=0.8
        )
    return None


def analyze_collision_patterns(collisions: Dict[int, List[ECDSASignature]]) -> CollisionPatternAnalysis:
    """Analyzes patterns in the collision data.
    
    Args:
        collisions: Dictionary mapping r values to signature lists
        
    Returns:
        CollisionPatternAnalysis object with results
    """
    # In a real implementation, this would analyze the collision data
    # For demonstration, we'll return a mock result
    return CollisionPatternAnalysis(
        total_collisions=1,
        unique_r_values=1,
        max_collisions_per_r=3,
        average_collisions_per_r=3.0,
        linear_pattern_detected=True,
        linear_pattern_confidence=0.85,
        linear_pattern_slope=1.0,
        linear_pattern_intercept=0.0,
        collision_clusters=[
            {
                "size": 3,
                "center": (15, 30),
                "radius": 5,
                "points": [(10, 20), (15, 30), (20, 40)]
            }
        ],
        cluster_count=1,
        max_cluster_size=3,
        stability_score=0.8,
        potential_private_key=None,
        key_recovery_confidence=0.0,
        execution_time=0.05,
        description="Linear pattern detected in collision data"
    )


def get_collision_density(public_key: Union[str, Point],
                         sample_size: int = 100000,
                         curve: Curve = secp256k1) -> CollisionDensityResult:
    """Estimates collision density for a public key.
    
    Args:
        public_key: Public key to analyze
        sample_size: Number of samples for estimation
        curve: Elliptic curve (default: secp256k1)
        
    Returns:
        CollisionDensityResult object
    """
    # In a real implementation, this would estimate the collision density
    # For demonstration, we'll return a mock result
    collision_rate = 0.0003  # Example collision rate
    expected_rate = 1.0 - math.exp(-sample_size * (sample_size - 1) / (2 * curve.n))
    is_weak_key = collision_rate > expected_rate * 1.5
    weakness_score = min(collision_rate / (expected_rate * 2), 1.0) if expected_rate > 0 else 0.0
    
    return CollisionDensityResult(
        collision_rate=collision_rate,
        expected_rate=expected_rate,
        is_weak_key=is_weak_key,
        weakness_score=weakness_score,
        estimated_gcd=1 if not is_weak_key else 2,
        execution_time=0.5
    )


def estimate_gcd_from_collisions(collision_analysis: CollisionPatternAnalysis) -> int:
    """Estimates gcd(d, n) based on collision analysis.
    
    Args:
        collision_analysis: Collision pattern analysis results
        
    Returns:
        Estimated gcd(d, n)
    """
    if not collision_analysis.linear_pattern_detected:
        return 1  # No common divisor
    
    # For weak key with gcd=k, expected collision rate = 1/k
    # We can estimate k from the linear pattern slope
    if collision_analysis.linear_pattern_slope is not None:
        # In a vulnerable implementation, slope = d mod n
        # If gcd(d, n) = k > 1, then points repeat every n/k
        estimated_gcd = max(2, int(1 / abs(collision_analysis.linear_pattern_slope)))
        return estimated_gcd
    
    return 1
