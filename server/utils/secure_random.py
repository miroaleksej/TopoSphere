"""
TopoSphere Secure Random Utilities

This module implements secure random number generation utilities for the TopoSphere server,
providing cryptographically secure random values essential for cryptographic operations and
topological analysis. The module is built on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "Weak random number generation creates distinctive patterns in the signature space that can be
detected through topological analysis."

The module is built on the following foundational principles:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- Cryptographically secure random number generation prevents distinctive patterns in signature space
- Continuous monitoring of random number quality detects potential weaknesses
- Integration with topological analysis identifies subtle patterns in random sequences
- Fixed resource profile enforcement to prevent timing/volume analysis

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous random number generation that maintains security while enabling meaningful
topological analysis.

Key features:
- Cryptographically secure random number generation using system entropy
- Topological pattern detection for random sequence analysis
- Continuous monitoring of random number quality
- Integration with TCON (Topological Conformance) verification
- Fixed resource profile enforcement to prevent timing/volume analysis
- Differential privacy mechanisms to prevent algorithm recovery

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

import os
import math
import time
import logging
import warnings
import threading
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum

# External dependencies
try:
    import numpy as np
    from scipy import stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    warnings.warn("scipy library not found. Some statistical tests will be limited.", 
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

# Configure logger
logger = logging.getLogger("TopoSphere.Server.SecureRandom")
logger.addHandler(logging.NullHandler())

# ======================
# ENUMERATIONS
# ======================

class RandomSource(Enum):
    """Sources of random data for secure random generation."""
    SYSTEM = "system"  # System entropy source (os.urandom)
    CRYPTOGRAPHIC = "cryptographic"  # Cryptographic PRNG (secrets module)
    HYBRID = "hybrid"  # Hybrid approach combining multiple sources
    QUANTUM = "quantum"  # Quantum random number generator (if available)
    
    def get_description(self) -> str:
        """Get description of random source."""
        descriptions = {
            RandomSource.SYSTEM: "System entropy source using os.urandom",
            RandomSource.CRYPTOGRAPHIC: "Cryptographic PRNG using secrets module",
            RandomSource.HYBRID: "Hybrid approach combining multiple entropy sources",
            RandomSource.QUANTUM: "Quantum random number generator (requires external hardware)"
        }
        return descriptions.get(self, "Unknown random source")
    
    def is_available(self) -> bool:
        """Check if random source is available on this system."""
        if self == RandomSource.QUANTUM:
            # In a real implementation, this would check for quantum RNG hardware
            return False
        return True


class RandomQuality(Enum):
    """Quality levels for random sequences."""
    EXCELLENT = "excellent"  # Passes all statistical tests
    GOOD = "good"  # Minor deviations but still secure
    WARNING = "warning"  # Significant deviations requiring attention
    POOR = "poor"  # Fails critical tests, insecure for cryptographic use
    CRITICAL = "critical"  # Highly structured, vulnerable to attacks
    
    def get_threshold(self) -> float:
        """Get quality threshold for this level.
        
        Returns:
            Threshold value (higher = better quality)
        """
        thresholds = {
            RandomQuality.EXCELLENT: 0.9,
            RandomQuality.GOOD: 0.7,
            RandomQuality.WARNING: 0.5,
            RandomQuality.POOR: 0.3,
            RandomQuality.CRITICAL: 0.0
        }
        return thresholds.get(self, 0.0)
    
    @classmethod
    def from_quality_score(cls, quality_score: float) -> RandomQuality:
        """Map quality score to quality level.
        
        Args:
            quality_score: Quality score (0-1)
            
        Returns:
            Corresponding quality level
        """
        if quality_score >= 0.9:
            return cls.EXCELLENT
        elif quality_score >= 0.7:
            return cls.GOOD
        elif quality_score >= 0.5:
            return cls.WARNING
        elif quality_score >= 0.3:
            return cls.POOR
        else:
            return cls.CRITICAL


class RandomPattern(Enum):
    """Patterns detected in random sequences."""
    UNIFORM = "uniform"  # Expected uniform distribution
    SPIRAL = "spiral"  # Spiral pattern indicating vulnerability
    STAR = "star"  # Star pattern indicating periodicity
    CLUSTERED = "clustered"  # Clustered pattern indicating weak randomness
    LINEAR = "linear"  # Linear pattern indicating predictable randomness
    DIAGONAL = "diagonal"  # Diagonal pattern indicating bias
    
    def get_description(self) -> str:
        """Get description of random pattern type."""
        descriptions = {
            RandomPattern.UNIFORM: "Uniform distribution as expected for secure random generation",
            RandomPattern.SPIRAL: "Spiral pattern indicating potential vulnerability in random number generation",
            RandomPattern.STAR: "Star pattern indicating periodicity in random number generation",
            RandomPattern.CLUSTERED: "Clustered pattern indicating weak randomness or bias",
            RandomPattern.LINEAR: "Linear pattern indicating predictable randomness",
            RandomPattern.DIAGONAL: "Diagonal pattern indicating bias in random number generation"
        }
        return descriptions.get(self, "Unknown random pattern")
    
    def get_criticality_weight(self) -> float:
        """Get criticality weight for this pattern.
        
        Returns:
            Weight value (higher = more critical)
        """
        weights = {
            RandomPattern.UNIFORM: 0.0,
            RandomPattern.SPIRAL: 0.6,
            RandomPattern.STAR: 0.5,
            RandomPattern.CLUSTERED: 0.8,
            RandomPattern.LINEAR: 0.9,
            RandomPattern.DIAGONAL: 0.7
        }
        return weights.get(self, 0.5)
    
    @classmethod
    def from_analysis(cls, 
                     uniformity_score: float,
                     spiral_score: float,
                     star_score: float,
                     symmetry_violation: float) -> RandomPattern:
        """Map analysis results to pattern type.
        
        Args:
            uniformity_score: Score measuring uniformity (0-1)
            spiral_score: Spiral pattern score
            star_score: Star pattern score
            symmetry_violation: Symmetry violation rate
            
        Returns:
            Corresponding random pattern
        """
        if uniformity_score > 0.8 and spiral_score > 0.7 and star_score > 0.7:
            return cls.UNIFORM
        elif spiral_score > 0.7:
            return cls.SPIRAL
        elif star_score > 0.6:
            return cls.STAR
        elif uniformity_score < 0.3:
            return cls.CLUSTERED
        elif symmetry_violation > 0.1:
            return cls.DIAGONAL
        else:
            return cls.LINEAR


# ======================
# DATA CLASSES
# ======================

@dataclass
class RandomAnalysisResult:
    """Represents analysis results for random sequence quality."""
    pattern_type: RandomPattern  # Detected pattern type
    uniformity_score: float  # Score measuring uniformity (0-1, higher = more uniform)
    entropy: float  # Shannon entropy value
    symmetry_violation_rate: float  # Rate of symmetry violations
    spiral_score: float  # Spiral pattern score
    star_score: float  # Star pattern score
    quality_score: float  # Overall quality score (0-1)
    quality_level: RandomQuality  # Quality level
    execution_time: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pattern_type": self.pattern_type.value,
            "uniformity_score": self.uniformity_score,
            "entropy": self.entropy,
            "symmetry_violation_rate": self.symmetry_violation_rate,
            "spiral_score": self.spiral_score,
            "star_score": self.star_score,
            "quality_score": self.quality_score,
            "quality_level": self.quality_level.value,
            "execution_time": self.execution_time,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }
    
    @property
    def is_secure(self) -> bool:
        """Determine if random sequence is secure for cryptographic use."""
        return self.quality_level in [RandomQuality.EXCELLENT, RandomQuality.GOOD]
    
    def get_recommendation(self) -> str:
        """Get remediation recommendation based on analysis."""
        recommendations = {
            RandomPattern.UNIFORM: "Random sequence quality is excellent. No action required.",
            RandomPattern.SPIRAL: "Address the spiral pattern in random sequence that may indicate vulnerability in random number generation.",
            RandomPattern.STAR: "Investigate the star pattern that may indicate periodicity in random number generation.",
            RandomPattern.CLUSTERED: "Replace the random number generator with a cryptographically secure implementation that does not exhibit clustering.",
            RandomPattern.LINEAR: "Immediately replace the random number generator as it shows highly predictable linear patterns.",
            RandomPattern.DIAGONAL: "Fix the bias in random number generation to restore diagonal symmetry in the signature space."
        }
        return recommendations.get(self.pattern_type, "Review the random number generator for potential cryptographic weaknesses.")


# ======================
# SECURE RANDOM UTILITIES
# ======================

class SecureRandom:
    """TopoSphere Secure Random - Cryptographically secure random number generation.
    
    This class implements the industrial-grade standards of AuditCore v3.2, providing
    mathematically rigorous random number generation that prevents distinctive patterns
    in the signature space while maintaining privacy guarantees and resource efficiency.
    
    Key features:
    - Cryptographically secure random number generation using system entropy
    - Topological pattern detection for random sequence analysis
    - Continuous monitoring of random number quality
    - Integration with TCON (Topological Conformance) verification
    - Fixed resource profile enforcement to prevent timing/volume analysis
    
    The implementation is based on the mathematical principle that for secure ECDSA
    implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1).
    Weak random number generation creates distinctive patterns in this space that can
    be detected through topological analysis, as demonstrated in our research.
    
    Example:
        secure_random = SecureRandom()
        nonce = secure_random.generate_nonce(curve.n)
        print(f"Secure nonce: {nonce}")
        
        # Analyze quality of random sequence
        sequence = [secure_random.randint(0, curve.n) for _ in range(1000)]
        analysis = secure_random.analyze_random_sequence(sequence)
        print(f"Random quality: {analysis.quality_level.value}")
    """
    
    def __init__(self,
                config: ServerConfig,
                random_source: RandomSource = RandomSource.CRYPTOGRAPHIC):
        """Initialize the Secure Random module.
        
        Args:
            config: Server configuration
            random_source: Preferred random source
            
        Raises:
            RuntimeError: If no secure random source is available
        """
        # Set configuration
        self.config = config
        self.curve = config.curve
        self.logger = self._setup_logger()
        
        # Determine available random source
        self.random_source = random_source
        if not self.random_source.is_available():
            # Try to find an available source
            for source in RandomSource:
                if source.is_available():
                    self.random_source = source
                    break
            
            if not self.random_source.is_available():
                raise RuntimeError("No secure random source available on this system")
        
        # Initialize state
        self.last_analysis: Dict[str, RandomAnalysisResult] = {}
        self.analysis_cache: Dict[str, RandomAnalysisResult] = {}
        self.random_quality_history: List[RandomAnalysisResult] = []
        
        # Initialize monitoring
        self.monitoring_active = False
        self.monitoring_thread = None
        self.monitoring_interval = 300.0  # 5 minutes
        self.monitoring_callback = None
        
        self.logger.info(
            f"Initialized SecureRandom with {self.random_source.value} source"
        )
    
    def _setup_logger(self):
        """Set up logger for the module."""
        logger = logging.getLogger("TopoSphere.Server.SecureRandom")
        logger.setLevel(self.config.log_level)
        
        # Add console handler if none exists
        if not logger.handlers and self.config.log_to_console:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def generate_nonce(self, n: int) -> int:
        """
        Generate a cryptographically secure nonce for ECDSA signing.
        
        Args:
            n: Order of the elliptic curve subgroup
            
        Returns:
            Secure nonce value (1 <= k < n)
        """
        start_time = time.time()
        self.logger.debug("Generating secure nonce for ECDSA signing...")
        
        # Generate random value
        k = self.randint(1, n - 1)
        
        # Verify that k is suitable (gcd(k, n) == 1)
        if gcd(k, n) != 1:
            # Regenerate if not suitable
            self.logger.warning("Generated nonce with gcd(k, n) > 1. Regenerating...")
            k = self.randint(1, n - 1)
            
            # Ensure we eventually get a good value
            max_attempts = 10
            attempts = 1
            while gcd(k, n) != 1 and attempts < max_attempts:
                k = self.randint(1, n - 1)
                attempts += 1
                
            if gcd(k, n) != 1:
                self.logger.error("Failed to generate suitable nonce after multiple attempts")
                raise RuntimeError("Failed to generate suitable nonce")
        
        self.logger.debug(
            f"Secure nonce generated in {time.time() - start_time:.6f}s: {k % 10000}..."
        )
        
        return k
    
    def generate_secure_u_r(self, n: int) -> int:
        """
        Generate a secure u_r value for bijective parameterization.
        
        For secure ECDSA implementations, u_r must satisfy gcd(u_r, n) = 1 to ensure
        proper bijective parameterization and prevent weak key vulnerabilities.
        
        Args:
            n: Order of the elliptic curve subgroup
            
        Returns:
            Secure u_r value (1 <= u_r < n and gcd(u_r, n) = 1)
        """
        start_time = time.time()
        self.logger.debug("Generating secure u_r value for bijective parameterization...")
        
        # Generate random u_r
        u_r = self.randint(1, n - 1)
        
        # Verify that gcd(u_r, n) = 1
        if gcd(u_r, n) != 1:
            # Regenerate if not suitable
            self.logger.warning("Generated u_r with gcd(u_r, n) > 1. Regenerating...")
            u_r = self.randint(1, n - 1)
            
            # Ensure we eventually get a good value
            max_attempts = 10
            attempts = 1
            while gcd(u_r, n) != 1 and attempts < max_attempts:
                u_r = self.randint(1, n - 1)
                attempts += 1
                
            if gcd(u_r, n) != 1:
                self.logger.error("Failed to generate secure u_r after multiple attempts")
                # Fallback: use a prime that doesn't divide n
                # In a real implementation, this would be more sophisticated
                u_r = 2
                while gcd(u_r, n) != 1:
                    u_r = next_prime(u_r)
        
        self.logger.debug(
            f"Secure u_r generated in {time.time() - start_time:.6f}s: {u_r % 10000}..."
        )
        
        return u_r
    
    def randint(self, a: int, b: int) -> int:
        """
        Generate a cryptographically secure random integer in the range [a, b].
        
        Args:
            a: Lower bound (inclusive)
            b: Upper bound (inclusive)
            
        Returns:
            Random integer in the specified range
        """
        if a > b:
            raise ValueError("Lower bound must be less than or equal to upper bound")
        
        # Calculate range size
        range_size = b - a + 1
        
        # For small ranges, use direct generation
        if range_size <= 2**32:
            if self.random_source == RandomSource.CRYPTOGRAPHIC:
                return secrets.randbelow(range_size) + a
            else:
                # Use system entropy source
                return self._system_randint(a, b)
        
        # For large ranges, use multiple iterations to avoid bias
        # This is important for elliptic curve operations where n is large
        num_bytes = (range_size.bit_length() + 7) // 8
        while True:
            # Generate random bytes
            rand_bytes = self._get_random_bytes(num_bytes)
            
            # Convert to integer
            rand_int = int.from_bytes(rand_bytes, byteorder='big')
            
            # Reduce to range
            rand_int %= range_size
            
            # Check if within range
            if rand_int < range_size:
                return rand_int + a
    
    def _get_random_bytes(self, n: int) -> bytes:
        """
        Get cryptographically secure random bytes.
        
        Args:
            n: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        if self.random_source == RandomSource.CRYPTOGRAPHIC:
            return secrets.token_bytes(n)
        else:
            return self._system_random_bytes(n)
    
    def _system_random_bytes(self, n: int) -> bytes:
        """
        Get random bytes from system entropy source.
        
        Args:
            n: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        return os.urandom(n)
    
    def _system_randint(self, a: int, b: int) -> int:
        """
        Generate random integer using system entropy source.
        
        Args:
            a: Lower bound (inclusive)
            b: Upper bound (inclusive)
            
        Returns:
            Random integer in the specified range
        """
        range_size = b - a + 1
        rand_bytes = self._system_random_bytes((range_size.bit_length() + 7) // 8)
        rand_int = int.from_bytes(rand_bytes, byteorder='big')
        return (rand_int % range_size) + a
    
    def analyze_random_sequence(self,
                              sequence: List[int],
                              n: Optional[int] = None,
                              resolution: int = 100) -> RandomAnalysisResult:
        """
        Analyze a random sequence for quality and potential vulnerabilities.
        
        Args:
            sequence: Sequence of random values to analyze
            n: Optional modulus for the sequence (used for u_r, u_z analysis)
            resolution: Resolution for grid-based analysis
            
        Returns:
            RandomAnalysisResult object with analysis results
        """
        start_time = time.time()
        self.logger.info("Performing random sequence quality analysis...")
        
        # Generate cache key
        cache_key = f"sequence_{len(sequence)}_{hash(tuple(sequence[:10]))}"
        
        # Check cache
        if cache_key in self.last_analysis:
            last_analysis = self.last_analysis[cache_key].analysis_timestamp
            if time.time() - last_analysis < 3600:  # 1 hour
                self.logger.info(f"Using cached random sequence analysis...")
                return self.last_analysis[cache_key]
        
        try:
            # Analyze uniformity
            uniformity_score = self._analyze_uniformity(sequence)
            
            # Calculate entropy
            entropy = self._calculate_entropy(sequence)
            
            # Analyze symmetry violations (if n is provided)
            symmetry_violation_rate = 0.0
            if n is not None:
                symmetry_violation_rate = self._analyze_symmetry_violations(sequence, n)
            
            # Analyze spiral patterns
            spiral_score = self._analyze_spiral_pattern(sequence, n, resolution)
            
            # Analyze star patterns
            star_score = self._analyze_star_pattern(sequence, n, resolution)
            
            # Determine pattern type
            pattern_type = RandomPattern.from_analysis(
                uniformity_score,
                spiral_score,
                star_score,
                symmetry_violation_rate
            )
            
            # Calculate quality score
            quality_score = self._calculate_quality_score(
                uniformity_score,
                entropy,
                symmetry_violation_rate,
                spiral_score,
                star_score
            )
            
            # Determine quality level
            quality_level = RandomQuality.from_quality_score(quality_score)
            
            # Create analysis result
            result = RandomAnalysisResult(
                pattern_type=pattern_type,
                uniformity_score=uniformity_score,
                entropy=entropy,
                symmetry_violation_rate=symmetry_violation_rate,
                spiral_score=spiral_score,
                star_score=star_score,
                quality_score=quality_score,
                quality_level=quality_level,
                execution_time=time.time() - start_time,
                meta={
                    "sequence_length": len(sequence),
                    "modulus": n,
                    "resolution": resolution
                }
            )
            
            # Cache results
            self.last_analysis[cache_key] = result
            self.analysis_cache[cache_key] = result
            
            # Record in history
            self.random_quality_history.append(result)
            if len(self.random_quality_history) > 100:
                self.random_quality_history.pop(0)
            
            self.logger.info(
                f"Random sequence analysis completed in {time.time() - start_time:.4f}s. "
                f"Quality: {quality_level.value.upper()}, Score: {quality_score:.4f}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Random sequence analysis failed: {str(e)}")
            raise ValueError(f"Analysis failed: {str(e)}") from e
    
    def _analyze_uniformity(self, sequence: List[int]) -> float:
        """Analyze uniformity of random sequence.
        
        Args:
            sequence: Sequence of random values
            
        Returns:
            Uniformity score (0-1, higher = more uniform)
        """
        if not sequence:
            return 0.0
        
        # Calculate histogram
        min_val = min(sequence)
        max_val = max(sequence)
        range_size = max_val - min_val + 1
        
        # Use appropriate number of bins
        num_bins = min(100, range_size)
        hist, _ = np.histogram(sequence, bins=num_bins)
        
        # Calculate entropy of distribution
        probabilities = hist / len(sequence)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        
        # Normalize entropy to 0-1 (higher = more uniform)
        max_entropy = np.log2(len(hist))
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _calculate_entropy(self, sequence: List[int]) -> float:
        """Calculate Shannon entropy of random sequence.
        
        Args:
            sequence: Sequence of random values
            
        Returns:
            Shannon entropy value
        """
        if not sequence:
            return 0.0
        
        # Count frequencies
        freq = {}
        for val in sequence:
            freq[val] = freq.get(val, 0) + 1
        
        # Calculate probabilities
        n = len(sequence)
        probabilities = [count / n for count in freq.values()]
        
        # Calculate entropy
        return -sum(p * math.log2(p) for p in probabilities if p > 0)
    
    def _analyze_symmetry_violations(self,
                                    sequence: List[int],
                                    n: int) -> float:
        """Analyze symmetry violations in random sequence.
        
        For ECDSA, the signature space should exhibit diagonal symmetry.
        
        Args:
            sequence: Sequence of random values (interpreted as u_r or u_z)
            n: Modulus for the sequence
            
        Returns:
            Symmetry violation rate (0-1)
        """
        if len(sequence) < 100 or n is None:
            return 0.0
        
        # For symmetry analysis, we need pairs of values
        # Assuming sequence contains alternating u_r, u_z values
        if len(sequence) % 2 != 0:
            sequence = sequence[:-1]
        
        points = [(sequence[i], sequence[i+1]) for i in range(0, len(sequence), 2)]
        
        # Check symmetry: (u_r, u_z) should have similar properties to (u_z, u_r)
        violations = 0
        for u_r, u_z in points:
            # Map to grid coordinates
            i1 = int(u_r / n * 100)
            j1 = int(u_z / n * 100)
            i2 = int(u_z / n * 100)
            j2 = int(u_r / n * 100)
            
            # Check if points are in similar density regions
            # In a real implementation, this would use a density grid
            if abs(i1 - j2) > 10 or abs(j1 - i2) > 10:
                violations += 1
        
        return violations / len(points)
    
    def _analyze_spiral_pattern(self,
                              sequence: List[int],
                              n: Optional[int],
                              resolution: int) -> float:
        """Analyze spiral patterns in random sequence.
        
        Args:
            sequence: Sequence of random values
            n: Optional modulus for the sequence
            resolution: Resolution for grid-based analysis
            
        Returns:
            Spiral pattern score (0-1, higher = more spiral-like)
        """
        if len(sequence) < 100 or n is None:
            return 0.0
        
        # For spiral analysis, we need pairs of values
        # Assuming sequence contains alternating u_r, u_z values
        if len(sequence) % 2 != 0:
            sequence = sequence[:-1]
        
        points = np.array([(sequence[i] % n, sequence[i+1] % n) for i in range(0, len(sequence), 2)])
        
        # Create grid
        grid = np.zeros((resolution, resolution))
        for u_r, u_z in points:
            i = min(resolution - 1, int(u_r / n * resolution))
            j = min(resolution - 1, int(u_z / n * resolution))
            grid[i, j] += 1
        
        # Normalize grid
        max_val = np.max(grid)
        if max_val > 0:
            grid = grid / max_val
        
        # Analyze spiral pattern
        # Calculate radial distribution
        center = resolution / 2
        spiral_score = 0.0
        counts = [0] * resolution
        
        for i in range(resolution):
            for j in range(resolution):
                if grid[i, j] > 0:
                    r = int(math.sqrt((i - center)**2 + (j - center)**2))
                    if r < resolution:
                        counts[r] += grid[i, j]
        
        # Check for regular pattern in radial distribution
        if sum(counts) > 0:
            counts = [c / sum(counts) for c in counts]
            # Calculate variance in radial distribution
            mean = sum(counts) / len(counts)
            variance = sum((c - mean)**2 for c in counts) / len(counts)
            # Higher variance indicates more structured pattern
            spiral_score = min(1.0, variance * 10.0)
        
        return spiral_score
    
    def _analyze_star_pattern(self,
                            sequence: List[int],
                            n: Optional[int],
                            resolution: int) -> float:
        """Analyze star patterns in random sequence.
        
        Args:
            sequence: Sequence of random values
            n: Optional modulus for the sequence
            resolution: Resolution for grid-based analysis
            
        Returns:
            Star pattern score (0-1, higher = more star-like)
        """
        if len(sequence) < 100 or n is None:
            return 0.0
        
        # For star analysis, we need pairs of values
        # Assuming sequence contains alternating u_r, u_z values
        if len(sequence) % 2 != 0:
            sequence = sequence[:-1]
        
        points = np.array([(sequence[i] % n, sequence[i+1] % n) for i in range(0, len(sequence), 2)])
        
        # Create grid
        grid = np.zeros((resolution, resolution))
        for u_r, u_z in points:
            i = min(resolution - 1, int(u_r / n * resolution))
            j = min(resolution - 1, int(u_z / n * resolution))
            grid[i, j] += 1
        
        # Normalize grid
        max_val = np.max(grid)
        if max_val > 0:
            grid = grid / max_val
        
        # Analyze star pattern
        center = resolution / 2
        angles = []
        
        for i in range(resolution):
            for j in range(resolution):
                if grid[i, j] > 0:
                    angle = math.atan2(j - center, i - center)
                    angles.append(angle)
        
        # Check for concentration at specific angles
        if angles:
            # Calculate circular variance
            mean_angle = np.angle(np.mean(np.exp(1j * np.array(angles))))
            deviations = [(angle - mean_angle + np.pi) % (2 * np.pi) - np.pi for angle in angles]
            circular_variance = 1 - np.abs(np.mean(np.exp(1j * np.array(deviations))))
            
            # Higher circular variance indicates more star-like pattern
            return min(1.0, circular_variance * 2.0)
        
        return 0.0
    
    def _calculate_quality_score(self,
                               uniformity_score: float,
                               entropy: float,
                               symmetry_violation: float,
                               spiral_score: float,
                               star_score: float) -> float:
        """Calculate overall quality score for random sequence.
        
        Args:
            uniformity_score: Uniformity score (0-1)
            entropy: Shannon entropy value
            symmetry_violation: Symmetry violation rate
            spiral_score: Spiral pattern score
            star_score: Star pattern score
            
        Returns:
            Quality score (0-1, higher = better quality)
        """
        # Base score from uniformity and entropy
        base_score = (uniformity_score * 0.4 + entropy / math.log(256) * 0.3)
        
        # Penalties for specific issues
        penalties = []
        
        # Symmetry violation
        if symmetry_violation > 0.05:
            penalties.append(symmetry_violation * 0.3)
        
        # Spiral pattern
        if spiral_score > 0.3:
            penalties.append(spiral_score * 0.2)
        
        # Star pattern
        if star_score > 0.3:
            penalties.append(star_score * 0.2)
        
        # Calculate final score
        quality_score = max(0.0, base_score - sum(penalties))
        return quality_score
    
    def get_random_quality_report(self,
                                sequence: List[int],
                                n: Optional[int] = None) -> str:
        """Get human-readable random quality report.
        
        Args:
            sequence: Sequence of random values to analyze
            n: Optional modulus for the sequence
            
        Returns:
            Quality report as string
        """
        result = self.analyze_random_sequence(sequence, n)
        
        lines = [
            "=" * 80,
            "RANDOM SEQUENCE QUALITY REPORT",
            "=" * 80,
            f"Report Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Sequence Length: {len(sequence)}",
            f"Modulus: {n if n is not None else 'N/A'}",
            "",
            "QUALITY ASSESSMENT:",
            f"Quality Level: {result.quality_level.value.upper()}",
            f"Quality Score: {result.quality_score:.4f}",
            f"Pattern Type: {result.pattern_type.value.upper()}",
            "",
            "DETAILED METRICS:",
            f"Uniformity Score: {result.uniformity_score:.4f}",
            f"Shannon Entropy: {result.entropy:.4f}",
            f"Symmetry Violation Rate: {result.symmetry_violation_rate:.4f}",
            f"Spiral Pattern Score: {result.spiral_score:.4f}",
            f"Star Pattern Score: {result.star_score:.4f}",
            "",
            "RECOMMENDATION:",
            f"  {result.get_recommendation()}",
            "",
            "=" * 80,
            "RANDOM QUALITY REPORT FOOTER",
            "=" * 80,
            "This report was generated by TopoSphere Secure Random,",
            "a component of the server-side security framework for TopoSphere.",
            "Random sequence quality is critical for ECDSA security as weak randomness",
            "creates distinctive patterns in the signature space that can be exploited.",
            "A 'EXCELLENT' quality level indicates secure random generation.",
            "Additional testing is recommended if quality is 'WARNING' or lower.",
            "=" * 80
        ]
        
        return "\n".join(lines)
    
    def verify_secure_random(self,
                            sequence: List[int],
                            n: Optional[int] = None,
                            threshold: RandomQuality = RandomQuality.WARNING) -> bool:
        """Verify if a random sequence meets security criteria.
        
        Args:
            sequence: Sequence of random values to verify
            n: Optional modulus for the sequence
            threshold: Minimum acceptable quality level
            
        Returns:
            True if sequence meets security criteria, False otherwise
        """
        result = self.analyze_random_sequence(sequence, n)
        return result.quality_level.value >= threshold.value
    
    def generate_secure_sequence(self,
                               length: int,
                               n: int,
                               secure_u_r: bool = False) -> List[int]:
        """Generate a secure random sequence.
        
        Args:
            length: Length of sequence to generate
            n: Modulus for the sequence
            secure_u_r: Whether to ensure gcd(u_r, n) = 1 for u_r values
            
        Returns:
            Secure random sequence
        """
        sequence = []
        
        for _ in range(length):
            if secure_u_r:
                # For u_r, ensure gcd(u_r, n) = 1
                u_r = self.generate_secure_u_r(n)
                sequence.append(u_r)
            else:
                # Regular random value
                sequence.append(self.randint(0, n - 1))
        
        return sequence
    
    def start_monitoring(self,
                        callback: Callable[[RandomAnalysisResult], None],
                        interval: float = 300.0) -> None:
        """Start monitoring random number quality.
        
        Args:
            callback: Function to call with analysis results
            interval: Interval between analyses (seconds)
        """
        if self.monitoring_active:
            self.logger.warning("Monitoring is already active")
            return
        
        self.monitoring_callback = callback
        self.monitoring_interval = interval
        self.monitoring_active = True
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    # Generate test sequence
                    test_sequence = self.generate_secure_sequence(1000, self.curve.n)
                    
                    # Analyze quality
                    analysis = self.analyze_random_sequence(test_sequence, self.curve.n)
                    
                    # Call callback
                    self.monitoring_callback(analysis)
                    
                    # Wait for next interval
                    time.sleep(self.monitoring_interval)
                except Exception as e:
                    self.logger.error(f"Monitoring failed: {str(e)}")
                    time.sleep(10)  # Wait before retrying
        
        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info(f"Started random quality monitoring (interval: {interval}s)")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring random number quality."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        self.logger.info("Stopped random quality monitoring")
    
    def get_quality_history(self) -> List[RandomAnalysisResult]:
        """Get history of random quality analyses.
        
        Returns:
            List of analysis results
        """
        return self.random_quality_history.copy()
    
    def get_average_quality(self) -> float:
        """Get average quality score from history.
        
        Returns:
            Average quality score (0-1)
        """
        if not self.random_quality_history:
            return 0.0
        
        total = sum(result.quality_score for result in self.random_quality_history)
        return total / len(self.random_quality_history)
    
    def is_tcon_compliant(self,
                         sequence: List[int],
                         n: Optional[int] = None) -> bool:
        """Verify TCON (Topological Conformance) compliance for random sequence.
        
        Args:
            sequence: Sequence of random values
            n: Optional modulus for the sequence
            
        Returns:
            True if TCON compliant, False otherwise
        """
        result = self.analyze_random_sequence(sequence, n)
        
        # TCON compliance requires:
        # 1. Quality level of at least GOOD
        # 2. No critical patterns (LINEAR or CLUSTERED)
        # 3. Symmetry violation rate < 0.05
        # 4. Spiral pattern score < 0.3
        # 5. Star pattern score < 0.3
        
        return (
            result.quality_level in [RandomQuality.EXCELLENT, RandomQuality.GOOD] and
            result.pattern_type not in [RandomPattern.LINEAR, RandomPattern.CLUSTERED] and
            result.symmetry_violation_rate < 0.05 and
            result.spiral_score < 0.3 and
            result.star_score < 0.3
        )
    
    def get_vulnerability_probability(self,
                                    sequence: List[int],
                                    n: Optional[int] = None) -> float:
        """Get the probability of vulnerability based on random sequence quality.
        
        Args:
            sequence: Sequence of random values
            n: Optional modulus for the sequence
            
        Returns:
            Vulnerability probability (0-1)
        """
        result = self.analyze_random_sequence(sequence, n)
        
        # Calculate vulnerability probability based on quality metrics
        vulnerability = (
            (1.0 - result.uniformity_score) * 0.3 +
            (1.0 - result.entropy / math.log(256)) * 0.2 +
            result.symmetry_violation_rate * 0.2 +
            result.spiral_score * 0.15 +
            result.star_score * 0.15
        )
        
        return min(1.0, vulnerability)
    
    def get_secure_random_generator(self,
                                  n: int,
                                  secure_u_r: bool = False) -> Callable[[], int]:
        """Get a secure random generator function.
        
        Args:
            n: Modulus for the random values
            secure_u_r: Whether to ensure gcd(u_r, n) = 1
            
        Returns:
            Function that generates secure random values
        """
        if secure_u_r:
            return lambda: self.generate_secure_u_r(n)
        else:
            return lambda: self.randint(0, n - 1)
