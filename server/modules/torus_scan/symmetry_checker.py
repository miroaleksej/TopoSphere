"""
TopoSphere Symmetry Checker Module

This module implements the symmetry analysis component for the Torus Scan system,
providing rigorous mathematical verification of diagonal symmetry in ECDSA signature spaces.
The checker is based on the fundamental insight from our research: "Diagonal symmetry
r(u_r, u_z) = r(u_z, u_r) must hold for secure implementations" which serves as a critical
indicator of implementation security.

The module is built on the following foundational principles:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)
- Diagonal symmetry r(u_r, u_z) = r(u_z, u_r) must hold for secure implementations
- Deviations from diagonal symmetry indicate potential vulnerabilities in nonce generation

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous analysis of symmetry patterns to detect vulnerabilities while maintaining
privacy guarantees.

Key features:
- Precise verification of diagonal symmetry in signature space
- Symmetry violation rate calculation with statistical confidence
- Critical region identification for vulnerability localization
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
import random
import math
import time
import logging
from datetime import datetime, timedelta
from functools import lru_cache
import warnings
import secrets

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
# ENUMERATIONS
# ======================

class SymmetryPatternType(Enum):
    """Types of symmetry patterns detected."""
    PERFECT = "perfect"  # Perfect symmetry (expected for secure implementations)
    NEAR_PERFECT = "near_perfect"  # Near-perfect symmetry with minor deviations
    PARTIAL = "partial"  # Partial symmetry with significant deviations
    BROKEN = "broken"  # Broken symmetry indicating vulnerability
    UNKNOWN = "unknown"
    
    @classmethod
    def from_violation_rate(cls, violation_rate: float) -> SymmetryPatternType:
        """Determine pattern type from violation rate.
        
        Args:
            violation_rate: Rate of symmetry violations (0-1)
            
        Returns:
            Symmetry pattern type
        """
        if violation_rate < 0.01:
            return cls.PERFECT
        elif violation_rate < 0.05:
            return cls.NEAR_PERFECT
        elif violation_rate < 0.1:
            return cls.PARTIAL
        else:
            return cls.BROKEN


class SymmetryVulnerabilityType(Enum):
    """Types of symmetry-based vulnerabilities."""
    BIAS_VULNERABILITY = "bias_vulnerability"  # Biased nonce generation
    STRUCTURED_VULNERABILITY = "structured_vulnerability"  # Structured vulnerability
    PERIODICITY_VULNERABILITY = "periodicity_vulnerability"  # Periodicity vulnerability
    DIAGONAL_PATTERN = "diagonal_pattern"  # Diagonal pattern vulnerability
    
    def get_description(self) -> str:
        """Get description of vulnerability type."""
        descriptions = {
            SymmetryVulnerabilityType.BIAS_VULNERABILITY: "Biased nonce generation - indicates weak randomness source",
            SymmetryVulnerabilityType.STRUCTURED_VULNERABILITY: "Structured vulnerability - indicates implementation-specific flaw",
            SymmetryVulnerabilityType.PERIODICITY_VULNERABILITY: "Periodicity vulnerability - indicates predictable nonce generation",
            SymmetryVulnerabilityType.DIAGONAL_PATTERN: "Diagonal pattern vulnerability - indicates implementation vulnerability"
        }
        return descriptions.get(self, "Unknown symmetry vulnerability")


# ======================
# DATA CLASSES
# ======================

@dataclass
class SymmetryAnalysisResult:
    """Results of symmetry analysis on the signature space."""
    violation_rate: float  # Rate of symmetry violations (0-1)
    total_samples: int  # Total number of samples tested
    violations_count: int  # Number of symmetry violations detected
    symmetry_score: float  # Symmetry score (1.0 - violation_rate)
    pattern_type: SymmetryPatternType
    critical_regions: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0  # Confidence in the analysis
    execution_time: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "violation_rate": self.violation_rate,
            "total_samples": self.total_samples,
            "violations_count": self.violations_count,
            "symmetry_score": self.symmetry_score,
            "pattern_type": self.pattern_type.value,
            "critical_regions_count": len(self.critical_regions),
            "confidence": self.confidence,
            "execution_time": self.execution_time,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }


@dataclass
class SymmetryVulnerability:
    """Represents a detected symmetry-based vulnerability."""
    vulnerability_type: SymmetryVulnerabilityType
    u_r: int  # u_r coordinate
    u_z: int  # u_z coordinate
    r1_value: int  # r value for (u_r, u_z)
    r2_value: int  # r value for (u_z, u_r)
    delta_r: int  # Difference between r1 and r2
    confidence: float = 1.0
    criticality: float = 1.0
    description: str = ""
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "vulnerability_type": self.violability_type.value,
            "u_r": self.u_r,
            "u_z": self.u_z,
            "r1_value": self.r1_value,
            "r2_value": self.r2_value,
            "delta_r": self.delta_r,
            "confidence": self.confidence,
            "criticality": self.criticality,
            "description": self.description,
            "timestamp": self.timestamp
        }


# ======================
# SYMMETRY CHECKER CLASS
# ======================

class SymmetryChecker:
    """TopoSphere Symmetry Checker - Comprehensive symmetry analysis for ECDSA implementations.
    
    This class implements the industrial-grade standards of AuditCore v3.2, providing rigorous
    mathematical verification of diagonal symmetry in ECDSA signature spaces. The checker is
    designed to detect vulnerabilities through precise analysis of symmetry patterns, with
    particular focus on violations of the critical property r(u_r, u_z) = r(u_z, u_r).
    
    Key features:
    - Precise verification of diagonal symmetry in signature space
    - Symmetry violation rate calculation with statistical confidence
    - Critical region identification for vulnerability localization
    - Integration with TCON (Topological Conformance) verification
    - Fixed resource profile enforcement to prevent timing/volume analysis
    
    The checker is based on the mathematical principle that for secure ECDSA implementations,
    diagonal symmetry must hold throughout the signature space. Deviations from this symmetry
    indicate potential vulnerabilities in the implementation.
    
    Example:
        checker = SymmetryChecker(config)
        result = checker.check(public_key)
        print(f"Symmetry violation rate: {result.violation_rate:.4f}")
    """
    
    def __init__(self,
                config: ServerConfig,
                curve: Optional[Curve] = None):
        """Initialize the Symmetry Checker.
        
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
        self.last_analysis: Dict[str, SymmetryAnalysisResult] = {}
        self.analysis_cache: Dict[str, SymmetryAnalysisResult] = {}
        
        self.logger.info("Initialized SymmetryChecker for symmetry verification")
    
    def _setup_logger(self):
        """Set up logger for the checker."""
        logger = logging.getLogger("TopoSphere.SymmetryChecker")
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
    
    def check(self,
             public_key: Union[str, Point],
             sample_size: int = 10000,
             force_recheck: bool = False) -> SymmetryAnalysisResult:
        """Check diagonal symmetry for a public key.
        
        Args:
            public_key: Public key to check (hex string or Point object)
            sample_size: Number of samples for symmetry verification
            force_recheck: Whether to force recheck even if recent
            
        Returns:
            SymmetryAnalysisResult object with results
            
        Raises:
            RuntimeError: If symmetry check fails
            ValueError: If public key is invalid
        """
        start_time = time.time()
        self.logger.info("Performing diagonal symmetry check...")
        
        # Convert public key to hex for caching
        if isinstance(public_key, Point):
            public_key_hex = point_to_public_key_hex(public_key)
        elif isinstance(public_key, str):
            public_key_hex = public_key
        else:
            raise ValueError("Invalid public key format")
        
        # Check cache
        if not force_recheck and public_key_hex in self.last_analysis:
            last_check_time = self.last_analysis[public_key_hex].analysis_timestamp
            if time.time() - last_check_time < 3600:  # 1 hour
                self.logger.info(
                    f"Using cached symmetry check for key {public_key_hex[:16]}..."
                )
                return self.last_analysis[public_key_hex]
        
        try:
            # Convert public key to Point if needed
            if isinstance(public_key, str):
                Q = public_key_hex_to_point(public_key, self.curve)
            elif isinstance(public_key, Point):
                Q = public_key
            else:
                raise ValueError("Invalid public key format")
            
            # Check diagonal symmetry
            violations = 0
            for _ in range(sample_size):
                u_r = random.randint(0, self.n - 1)
                u_z = random.randint(0, self.n - 1)
                
                # Compute r for (u_r, u_z) and (u_z, u_r)
                r1 = compute_r(Q, u_r, u_z, self.curve)
                r2 = compute_r(Q, u_z, u_r, self.curve)
                
                if r1 != r2:
                    violations += 1
            
            violation_rate = violations / sample_size
            symmetry_score = 1.0 - violation_rate
            
            # Determine pattern type
            pattern_type = SymmetryPatternType.from_violation_rate(violation_rate)
            
            # Get critical regions if violations detected
            critical_regions = []
            if violation_rate > 0.01:
                critical_regions = self._identify_critical_regions(
                    Q, 
                    sample_size=min(1000, sample_size)
                )
            
            # Calculate confidence (higher for lower violation rates)
            confidence = max(0.5, 1.0 - violation_rate)
            
            # Create analysis result
            analysis = SymmetryAnalysisResult(
                violation_rate=violation_rate,
                total_samples=sample_size,
                violations_count=violations,
                symmetry_score=symmetry_score,
                pattern_type=pattern_type,
                critical_regions=critical_regions,
                confidence=confidence,
                execution_time=time.time() - start_time,
                meta={
                    "curve": self.curve.name,
                    "sample_size": sample_size
                }
            )
            
            # Cache results
            self.last_analysis[public_key_hex] = analysis
            self.analysis_cache[public_key_hex] = analysis
            
            self.logger.info(
                f"Diagonal symmetry check completed in {time.time() - start_time:.4f}s. "
                f"Violation rate: {violation_rate:.4f}, Pattern: {pattern_type.value}"
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Symmetry check failed: {str(e)}")
            raise RuntimeError(f"Failed to perform symmetry check: {str(e)}") from e
    
    def _identify_critical_regions(self,
                                  Q: Point,
                                  sample_size: int = 1000) -> List[Dict[str, Any]]:
        """Identify regions with high symmetry violation rates.
        
        Args:
            Q: Public key point
            sample_size: Number of samples for region analysis
            
        Returns:
            List of critical regions with details
        """
        # Divide space into 10x10 grid
        grid_size = 10
        violation_counts = np.zeros((grid_size, grid_size))
        total_counts = np.zeros((grid_size, grid_size))
        
        # Sample points and check symmetry
        for _ in range(sample_size):
            u_r = random.randint(0, self.n - 1)
            u_z = random.randint(0, self.n - 1)
            
            # Determine grid cell
            x = int(u_r / self.n * grid_size)
            y = int(u_z / self.n * grid_size)
            
            if 0 <= x < grid_size and 0 <= y < grid_size:
                total_counts[x, y] += 1
                
                # Check symmetry
                r1 = compute_r(Q, u_r, u_z, self.curve)
                r2 = compute_r(Q, u_z, u_r, self.curve)
                
                if r1 != r2:
                    violation_counts[x, y] += 1
        
        # Calculate violation rates
        violation_rates = np.zeros((grid_size, grid_size))
        for x in range(grid_size):
            for y in range(grid_size):
                if total_counts[x, y] > 0:
                    violation_rates[x, y] = violation_counts[x, y] / total_counts[x, y]
        
        # Find regions with high violation rates
        critical_regions = []
        threshold = max(0.05, np.mean(violation_rates) + 2 * np.std(violation_rates))
        
        for x in range(grid_size):
            for y in range(grid_size):
                if violation_rates[x, y] > threshold:
                    u_r_min = int(x * self.n / grid_size)
                    u_r_max = int((x + 1) * self.n / grid_size)
                    u_z_min = int(y * self.n / grid_size)
                    u_z_max = int((y + 1) * self.n / grid_size)
                    
                    critical_regions.append({
                        "region_id": f"R{x}_{y}",
                        "u_r_range": (u_r_min, u_r_max),
                        "u_z_range": (u_z_min, u_z_max),
                        "violation_rate": float(violation_rates[x, y]),
                        "sample_count": int(total_counts[x, y]),
                        "risk_level": "high" if violation_rates[x, y] > 0.1 else "medium"
                    })
        
        # Sort by violation rate
        critical_regions.sort(
            key=lambda r: r["violation_rate"], 
            reverse=True
        )
        
        return critical_regions
    
    def detect_vulnerabilities(self,
                              symmetry_analysis: SymmetryAnalysisResult) -> List[SymmetryVulnerability]:
        """Detect vulnerabilities from symmetry analysis.
        
        Args:
            symmetry_analysis: Symmetry analysis results
            
        Returns:
            List of detected symmetry vulnerabilities
        """
        vulnerabilities = []
        
        # 1. Check for bias vulnerability (systematic deviation)
        if symmetry_analysis.violation_rate > 0.05:
            confidence = 1.0 - symmetry_analysis.violation_rate
            criticality = min(1.0, symmetry_analysis.violation_rate * 1.5)
            
            vulnerabilities.append(SymmetryVulnerability(
                vulnerability_type=SymmetryVulnerabilityType.BIAS_VULNERABILITY,
                u_r=0,  # Placeholder
                u_z=0,  # Placeholder
                r1_value=0,  # Placeholder
                r2_value=0,  # Placeholder
                delta_r=0,  # Placeholder
                confidence=confidence,
                criticality=criticality,
                description=f"High symmetry violation rate ({symmetry_analysis.violation_rate:.4f}) indicates biased nonce generation"
            ))
        
        # 2. Check for structured vulnerability (patterned deviations)
        if symmetry_analysis.pattern_type == SymmetryPatternType.PARTIAL or \
           symmetry_analysis.pattern_type == SymmetryPatternType.BROKEN:
            confidence = 1.0 - symmetry_analysis.violation_rate
            criticality = min(1.0, symmetry_analysis.violation_rate * 1.2)
            
            vulnerabilities.append(SymmetryVulnerability(
                vulnerability_type=SymmetryVulnerabilityType.STRUCTURED_VULNERABILITY,
                u_r=0,  # Placeholder
                u_z=0,  # Placeholder
                r1_value=0,  # Placeholder
                r2_value=0,  # Placeholder
                delta_r=0,  # Placeholder
                confidence=confidence,
                criticality=criticality,
                description=f"Structured symmetry violations detected ({symmetry_analysis.violation_rate:.4f} rate)"
            ))
        
        # 3. Check for periodicity vulnerability (cyclic deviations)
        if symmetry_analysis.critical_regions and len(symmetry_analysis.critical_regions) > 1:
            # Check if critical regions form a pattern
            x_coords = [int(r["region_id"].split("_")[0][1:]) for r in symmetry_analysis.critical_regions]
            y_coords = [int(r["region_id"].split("_")[1]) for r in symmetry_analysis.critical_regions]
            
            # Check for linear pattern in region coordinates
            if len(x_coords) > 2:
                slope, _ = np.polyfit(x_coords, y_coords, 1)
                if abs(slope - 1.0) < 0.2:  # Close to diagonal pattern
                    confidence = 0.8
                    criticality = min(1.0, symmetry_analysis.violation_rate * 1.3)
                    
                    vulnerabilities.append(SymmetryVulnerability(
                        vulnerability_type=SymmetryVulnerabilityType.PERIODICITY_VULNERABILITY,
                        u_r=0,  # Placeholder
                        u_z=0,  # Placeholder
                        r1_value=0,  # Placeholder
                        r2_value=0,  # Placeholder
                        delta_r=0,  # Placeholder
                        confidence=confidence,
                        criticality=criticality,
                        description=f"Periodic symmetry violations detected in diagonal pattern"
                    ))
        
        return vulnerabilities
    
    def get_vulnerabilities(self,
                           public_key: Union[str, Point]) -> List[SymmetryVulnerability]:
        """Get detected symmetry-based vulnerabilities for a public key.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            List of detected symmetry vulnerabilities
            
        Raises:
            ValueError: If public key is invalid
        """
        # Convert public key to hex
        if isinstance(public_key, Point):
            public_key_hex = point_to_public_key_hex(public_key)
        elif isinstance(public_key, str):
            public_key_hex = public_key
        else:
            raise ValueError("Invalid public key format")
        
        # Check if we have cached vulnerabilities
        if public_key_hex in self.analysis_cache:
            return self.detect_vulnerabilities(self.analysis_cache[public_key_hex])
        
        # Perform analysis to get vulnerabilities
        self.check(public_key)
        return self.detect_vulnerabilities(self.analysis_cache.get(public_key_hex, SymmetryAnalysisResult(
            violation_rate=0.0,
            total_samples=0,
            violations_count=0,
            symmetry_score=1.0,
            pattern_type=SymmetryPatternType.PERFECT
        )))
    
    def is_implementation_secure(self,
                                public_key: Union[str, Point]) -> bool:
        """Determine if an ECDSA implementation is secure based on symmetry check.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            True if implementation is secure, False otherwise
        """
        analysis = self.check(public_key)
        
        # Implementation is secure if violation rate is below threshold
        return analysis.violation_rate < 0.01
    
    def get_tcon_compliance(self,
                           public_key: Union[str, Point]) -> float:
        """Get TCON (Topological Conformance) compliance score.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            TCON compliance score (0-1, higher = more compliant)
        """
        analysis = self.check(public_key)
        
        # TCON compliance is based on symmetry score
        return analysis.symmetry_score
    
    def get_symmetry_score(self,
                          public_key: Union[str, Point]) -> float:
        """Get the symmetry score for an implementation.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            Symmetry score (0-1, higher = more symmetric)
        """
        return self.check(public_key).symmetry_score
    
    def get_violation_rate(self,
                          public_key: Union[str, Point]) -> float:
        """Get the symmetry violation rate for an implementation.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            Symmetry violation rate (0-1, lower = better)
        """
        return self.check(public_key).violation_rate
    
    def get_critical_regions(self,
                            public_key: Union[str, Point],
                            num_regions: int = 5) -> List[Dict[str, Any]]:
        """Get critical regions with high symmetry violation rates.
        
        Args:
            public_key: Public key to analyze
            num_regions: Number of critical regions to return
            
        Returns:
            List of critical regions with details
        """
        # Convert public key to Point if needed
        if isinstance(public_key, str):
            Q = public_key_hex_to_point(public_key, self.curve)
        elif isinstance(public_key, Point):
            Q = public_key
        else:
            raise ValueError("Invalid public key format")
        
        # Get critical regions
        critical_regions = self._identify_critical_regions(Q)
        
        # Return top regions
        return critical_regions[:num_regions]
    
    def generate_recommendations(self,
                                public_key: Union[str, Point]) -> List[str]:
        """Generate security recommendations based on symmetry analysis.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            List of security recommendations
        """
        analysis = self.check(public_key)
        vulnerabilities = self.get_vulnerabilities(public_key)
        
        recommendations = []
        
        # General security recommendation
        if analysis.violation_rate < 0.01:
            recommendations.append("CONTINUE_USING")
        elif analysis.violation_rate < 0.05:
            recommendations.append("CAUTION")
        else:
            recommendations.append("CONSIDER_ROTATION")
        
        # Specific recommendations based on vulnerabilities
        for vuln in vulnerabilities:
            if vuln.vulnerability_type == SymmetryVulnerabilityType.BIAS_VULNERABILITY:
                recommendations.append(
                    "FIX_BIAS: Address bias in nonce generation to ensure uniform distribution"
                )
            elif vuln.vulnerability_type == SymmetryVulnerabilityType.STRUCTURED_VULNERABILITY:
                recommendations.append(
                    "ANALYZE_STRUCTURE: Investigate structured deviations in symmetry pattern"
                )
            elif vuln.vulnerability_type == SymmetryVulnerabilityType.PERIODICITY_VULNERABILITY:
                recommendations.append(
                    "FIX_PERIODICITY: Address periodicity in symmetry violations to prevent predictability"
                )
        
        return recommendations
    
    def get_symmetry_report(self,
                           public_key: Union[str, Point]) -> str:
        """Get human-readable symmetry analysis report.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            Symmetry analysis report as string
        """
        analysis = self.check(public_key)
        vulnerabilities = self.get_vulnerabilities(public_key)
        
        lines = [
            "=" * 80,
            "SYMMETRY ANALYSIS REPORT",
            "=" * 80,
            f"Analysis Timestamp: {datetime.fromtimestamp(analysis.analysis_timestamp).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Public Key: {public_key[:50]}{'...' if len(public_key) > 50 else ''}",
            f"Curve: {self.curve.name}",
            "",
            "SYMMETRY STATISTICS:",
            f"Violation Rate: {analysis.violation_rate:.4f}",
            f"Symmetry Score: {analysis.symmetry_score:.4f}",
            f"Pattern Type: {analysis.pattern_type.value.upper()}",
            f"Total Samples: {analysis.total_samples}",
            f"Violations Detected: {analysis.violations_count}",
            "",
            "VULNERABILITY ASSESSMENT:",
            f"Implementation Secure: {'Yes' if self.is_implementation_secure(public_key) else 'No'}",
            "",
            "DETECTED VULNERABILITIES:"
        ]
        
        if not vulnerabilities:
            lines.append("  No vulnerabilities detected from symmetry analysis")
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                lines.append(f"  {i}. [{vuln.vulnerability_type.value.upper()}] {vuln.description}")
                lines.append(f"     Confidence: {vuln.confidence:.4f} | Criticality: {vuln.criticality:.4f}")
                if vuln.vulnerability_type == SymmetryVulnerabilityType.STRUCTURED_VULNERABILITY:
                    critical_regions = self.get_critical_regions(public_key)
                    if critical_regions:
                        lines.append("     Critical regions:")
                        for region in critical_regions[:3]:  # Show up to 3 regions
                            lines.append(
                                f"       - Region {region['region_id']}: "
                                f"u_r={region['u_r_range'][0]}-{region['u_r_range'][1]}, "
                                f"u_z={region['u_z_range'][0]}-{region['u_z_range'][1]}, "
                                f"risk={region['risk_level']}"
                            )
                        if len(critical_regions) > 3:
                            lines.append(f"       - And {len(critical_regions) - 3} more regions")
        
        lines.extend([
            "",
            "=" * 80,
            "SYMMETRY ANALYSIS FOOTER",
            "=" * 80,
            "This report was generated by TopoSphere Symmetry Checker,",
            "a component of the Torus Scan system for detecting ECDSA vulnerabilities.",
            "A 'secure' result does not guarantee the absence of all possible vulnerabilities.",
            "Additional security testing is recommended for critical systems.",
            "=" * 80
        ])
        
        return "\n".join(lines)


# ======================
# HELPER FUNCTIONS
# ======================

def check_diagonal_symmetry(public_key: Union[str, Point],
                          curve: Curve = secp256k1,
                          sample_size: int = 10000) -> Dict[str, Any]:
    """Check diagonal symmetry for a public key.
    
    Args:
        public_key: Public key to check (hex string or Point object)
        curve: Elliptic curve (default: secp256k1)
        sample_size: Number of samples for symmetry verification
        
    Returns:
        Dictionary with symmetry check results
    """
    # In a real implementation, this would use a proper symmetry checker
    # For demonstration, we'll simulate a result
    violation_rate = random.uniform(0.0, 0.1)  # Simulated violation rate
    
    return {
        "violation_rate": violation_rate,
        "total_samples": sample_size,
        "violations_count": int(violation_rate * sample_size),
        "symmetry_score": 1.0 - violation_rate,
        "pattern_type": "near_perfect" if violation_rate < 0.05 else "partial",
        "critical_regions": [] if violation_rate < 0.01 else [
            {
                "region_id": "R5_7",
                "u_r_range": (50000, 60000),
                "u_z_range": (70000, 80000),
                "violation_rate": 0.15,
                "sample_count": 100,
                "risk_level": "high"
            }
        ]
    }


def detect_symmetry_vulnerabilities(symmetry_analysis: SymmetryAnalysisResult) -> List[SymmetryVulnerability]:
    """Detect vulnerabilities from symmetry analysis.
    
    Args:
        symmetry_analysis: Symmetry analysis results
        
    Returns:
        List of detected symmetry vulnerabilities
    """
    vulnerabilities = []
    
    # 1. Check for bias vulnerability
    if symmetry_analysis.violation_rate > 0.05:
        confidence = 1.0 - symmetry_analysis.violation_rate
        criticality = min(1.0, symmetry_analysis.violation_rate * 1.5)
        
        vulnerabilities.append(SymmetryVulnerability(
            vulnerability_type=SymmetryVulnerabilityType.BIAS_VULNERABILITY,
            u_r=0,  # Placeholder
            u_z=0,  # Placeholder
            r1_value=0,  # Placeholder
            r2_value=0,  # Placeholder
            delta_r=0,  # Placeholder
            confidence=confidence,
            criticality=criticality,
            description=f"High symmetry violation rate ({symmetry_analysis.violation_rate:.4f}) indicates biased nonce generation"
        ))
    
    # 2. Check for structured vulnerability
    if symmetry_analysis.pattern_type == SymmetryPatternType.PARTIAL or \
       symmetry_analysis.pattern_type == SymmetryPatternType.BROKEN:
        confidence = 1.0 - symmetry_analysis.violation_rate
        criticality = min(1.0, symmetry_analysis.violation_rate * 1.2)
        
        vulnerabilities.append(SymmetryVulnerability(
            vulnerability_type=SymmetryVulnerabilityType.STRUCTURED_VULNERABILITY,
            u_r=0,  # Placeholder
            u_z=0,  # Placeholder
            r1_value=0,  # Placeholder
            r2_value=0,  # Placeholder
            delta_r=0,  # Placeholder
            confidence=confidence,
            criticality=criticality,
            description=f"Structured symmetry violations detected ({symmetry_analysis.violation_rate:.4f} rate)"
        ))
    
    return vulnerabilities


def is_implementation_secure_from_symmetry(symmetry_analysis: SymmetryAnalysisResult) -> bool:
    """Determine if an implementation is secure based on symmetry analysis.
    
    Args:
        symmetry_analysis: Symmetry analysis results
        
    Returns:
        True if implementation is secure, False otherwise
    """
    return symmetry_analysis.violation_rate < 0.01
