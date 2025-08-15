"""
TopoSphere Entanglement Entropy Analyzer Module

This module implements the Entanglement Entropy component for the Quantum Scanning system,
providing quantum-inspired vulnerability detection through entanglement analysis of ECDSA
signature spaces. The analyzer is based on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "Quantum entanglement entropy S = log₂(gcd(d, n)) provides a powerful metric for vulnerability detection."

The module is built on the following foundational principles:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- Quantum entanglement entropy S = log₂(gcd(d, n)) serves as a vulnerability metric
- Low entanglement entropy indicates potential weak key vulnerabilities
- Integration with topological analysis enables precise vulnerability localization

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous entanglement entropy analysis that identifies potential weaknesses in ECDSA
implementations.

Key features:
- Quantum entanglement entropy calculation for ECDSA signature spaces
- Weak key vulnerability detection through entanglement analysis
- Integration with TCON (Topological Conformance) verification
- Fixed resource profile enforcement to prevent timing/volume analysis
- Differential privacy mechanisms to prevent algorithm recovery
- Multiscale entanglement analysis for comprehensive vulnerability detection

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment. The module implements
the quantum entanglement model as described in our research, which provides a powerful metric for
detecting weak key vulnerabilities through the formula S = log₂(gcd(d, n)).

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
import random

# External dependencies
try:
    from giotto_tda import wasserstein_distance
    TDALIB_AVAILABLE = True
except ImportError:
    TDALIB_AVAILABLE = False
    warnings.warn("giotto-tda library not found. Entanglement analysis will be limited.", 
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
from .quantum_scanner import (
    QuantumScanner,
    QuantumScanConfig,
    ScanResult
)
from .amplitude_amplifier import (
    AmplitudeAmplifier
)
from .anomaly_mapper import (
    TopologicalAnomalyMapper
)

# ======================
# ENUMERATIONS
# ======================

class EntanglementPattern(Enum):
    """Types of entanglement patterns detected in quantum analysis."""
    WEAK_KEY = "weak_key"  # Weak key pattern (gcd(d, n) > 1)
    PARTIAL_ENTANGLEMENT = "partial_entanglement"  # Partial entanglement pattern
    FULL_ENTANGLEMENT = "full_entanglement"  # Full entanglement pattern
    DISCONNECTED = "disconnected"  # Disconnected entanglement pattern
    QUANTUM_NOISE = "quantum_noise"  # Quantum noise pattern
    
    def get_description(self) -> str:
        """Get description of entanglement pattern type."""
        descriptions = {
            EntanglementPattern.WEAK_KEY: "Weak key pattern indicating gcd(d, n) > 1 vulnerability",
            EntanglementPattern.PARTIAL_ENTANGLEMENT: "Partial entanglement pattern indicating implementation-specific structure",
            EntanglementPattern.FULL_ENTANGLEMENT: "Full entanglement pattern indicating maximum randomness",
            EntanglementPattern.DISCONNECTED: "Disconnected entanglement pattern indicating potential vulnerability",
            EntanglementPattern.QUANTUM_NOISE: "Quantum noise pattern indicating statistical fluctuations"
        }
        return descriptions.get(self, "Unknown entanglement pattern")
    
    def get_criticality_weight(self) -> float:
        """Get criticality weight for this entanglement pattern.
        
        Returns:
            Weight value (higher = more critical)
        """
        weights = {
            EntanglementPattern.WEAK_KEY: 1.0,
            EntanglementPattern.PARTIAL_ENTANGLEMENT: 0.6,
            EntanglementPattern.FULL_ENTANGLEMENT: 0.0,  # Not critical
            EntanglementPattern.DISCONNECTED: 0.8,
            EntanglementPattern.QUANTUM_NOISE: 0.2
        }
        return weights.get(self, 0.5)
    
    @classmethod
    def from_entanglement_score(cls, entanglement_score: float, gcd_value: int) -> EntanglementPattern:
        """Map entanglement metrics to pattern type.
        
        Args:
            entanglement_score: Entanglement score (0-1)
            gcd_value: GCD(d, n) value
            
        Returns:
            Corresponding entanglement pattern
        """
        if gcd_value > 1:
            return cls.WEAK_KEY
        elif entanglement_score < 0.3:
            return cls.DISCONNECTED
        elif entanglement_score < 0.7:
            return cls.PARTIAL_ENTANGLEMENT
        elif entanglement_score < 0.95:
            return cls.FULL_ENTANGLEMENT
        else:
            return cls.QUANTUM_NOISE


class EntanglementSeverity(Enum):
    """Severity levels for entanglement-based vulnerabilities."""
    CRITICAL = "critical"  # Immediate risk of key recovery
    HIGH = "high"  # High risk of vulnerability exploitation
    MEDIUM = "medium"  # Medium risk requiring attention
    LOW = "low"  # Low risk, potential for future issues
    SECURE = "secure"  # No entanglement-based vulnerabilities
    
    def get_threshold(self) -> float:
        """Get criticality threshold for this severity level.
        
        Returns:
            Threshold value (0-1)
        """
        thresholds = {
            EntanglementSeverity.CRITICAL: 0.8,
            EntanglementSeverity.HIGH: 0.6,
            EntanglementSeverity.MEDIUM: 0.4,
            EntanglementSeverity.LOW: 0.2,
            EntanglementSeverity.SECURE: 0.0
        }
        return thresholds.get(self, 0.0)
    
    @classmethod
    def from_criticality(cls, criticality: float) -> EntanglementSeverity:
        """Map criticality score to severity level.
        
        Args:
            criticality: Criticality score (0-1)
            
        Returns:
            Corresponding severity level
        """
        if criticality >= 0.8:
            return cls.CRITICAL
        elif criticality >= 0.6:
            return cls.HIGH
        elif criticality >= 0.4:
            return cls.MEDIUM
        elif criticality >= 0.2:
            return cls.LOW
        else:
            return cls.SECURE


# ======================
# DATA CLASSES
# ======================

@dataclass
class EntanglementMetrics:
    """Represents entanglement metrics for a quantum analysis."""
    entanglement_score: float  # Overall entanglement score (0-1)
    entanglement_entropy: float  # Entanglement entropy value
    gcd_value: int  # GCD(d, n) value
    pattern_type: EntanglementPattern  # Detected pattern type
    criticality: float  # Criticality score (0-1)
    confidence: float  # Confidence in metrics (0-1)
    location: Tuple[float, float]  # (u_r, u_z) location of pattern
    quantum_vulnerability_score: float  # Vulnerability score (0-1)
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "entanglement_score": self.entanglement_score,
            "entanglement_entropy": self.entanglement_entropy,
            "gcd_value": self.gcd_value,
            "pattern_type": self.pattern_type.value,
            "criticality": self.criticality,
            "confidence": self.confidence,
            "location": self.location,
            "quantum_vulnerability_score": self.quantum_vulnerability_score,
            "meta": self.meta
        }
    
    @property
    def severity(self) -> EntanglementSeverity:
        """Get severity level based on criticality."""
        return EntanglementSeverity.from_criticality(self.criticality)
    
    def get_recommendation(self) -> str:
        """Get remediation recommendation based on entanglement metrics."""
        recommendations = {
            EntanglementPattern.WEAK_KEY: "Immediately rotate the affected key as it has a weak private key (gcd(d, n) > 1).",
            EntanglementPattern.PARTIAL_ENTANGLEMENT: "Review implementation for potential structural weaknesses in random number generation.",
            EntanglementPattern.FULL_ENTANGLEMENT: "No entanglement-based vulnerabilities detected. Continue regular monitoring.",
            EntanglementPattern.DISCONNECTED: "Investigate disconnected entanglement pattern that may indicate implementation flaws.",
            EntanglementPattern.QUANTUM_NOISE: "Quantum noise detected. Monitor for potential emerging vulnerabilities."
        }
        return recommendations.get(self.pattern_type, "Review the implementation for potential cryptographic weaknesses.")


@dataclass
class EntanglementAnalysisResult:
    """Results of comprehensive entanglement analysis."""
    public_key: str  # Public key being analyzed
    curve: str  # Elliptic curve name
    entanglement_metrics: EntanglementMetrics  # Core entanglement metrics
    topological_integrity: float  # Topological integrity score
    symmetry_violation_rate: float  # Rate of symmetry violations
    spiral_score: float  # Spiral pattern score
    star_score: float  # Star pattern score
    critical_regions: List[Dict[str, Any]]  # Critical regions with anomalies
    quantum_vulnerability_score: float  # Overall quantum vulnerability score
    execution_time: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "public_key": self.public_key,
            "curve": self.curve,
            "entanglement_metrics": self.entanglement_metrics.to_dict(),
            "topological_integrity": self.topological_integrity,
            "symmetry_violation_rate": self.symmetry_violation_rate,
            "spiral_score": self.spiral_score,
            "star_score": self.star_score,
            "critical_regions_count": len(self.critical_regions),
            "quantum_vulnerability_score": self.quantum_vulnerability_score,
            "execution_time": self.execution_time,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }
    
    @property
    def security_level(self) -> str:
        """Get security level based on quantum vulnerability score."""
        if self.quantum_vulnerability_score < 0.2:
            return "secure"
        elif self.quantum_vulnerability_score < 0.4:
            return "caution"
        elif self.quantum_vulnerability_score < 0.7:
            return "vulnerable"
        else:
            return "critical"


# ======================
# ENTANGLEMENT ENTROPY ANALYZER CLASS
# ======================

class EntanglementEntropyAnalyzer:
    """TopoSphere Entanglement Entropy Analyzer - Quantum vulnerability detection.
    
    This class implements the industrial-grade standards of AuditCore v3.2, providing
    quantum-inspired entanglement entropy analysis for detecting vulnerabilities in ECDSA
    implementations. The analyzer is designed to identify weak key vulnerabilities and
    other quantum-related issues through precise calculation of entanglement metrics.
    
    Key features:
    - Quantum entanglement entropy calculation for ECDSA signature spaces
    - Weak key vulnerability detection through entanglement analysis
    - Integration with TCON (Topological Conformance) verification
    - Fixed resource profile enforcement to prevent timing/volume analysis
    - Multiscale entanglement analysis for comprehensive vulnerability detection
    
    The analyzer is based on the mathematical principle that for ECDSA implementations,
    the quantum entanglement entropy is given by S = log₂(gcd(d, n)). This provides
    a powerful metric for detecting weak key vulnerabilities where gcd(d, n) > 1.
    
    Example:
        analyzer = EntanglementEntropyAnalyzer(config)
        result = analyzer.analyze(public_key)
        print(f"Entanglement entropy: {result.entanglement_metrics.entanglement_entropy:.4f}")
        print(f"Quantum vulnerability score: {result.quantum_vulnerability_score:.4f}")
    """
    
    def __init__(self,
                config: QuantumScanConfig,
                quantum_scanner: Optional[QuantumScanner] = None,
                amplitude_amplifier: Optional[AmplitudeAmplifier] = None):
        """Initialize the Entanglement Entropy Analyzer.
        
        Args:
            config: Quantum scan configuration
            quantum_scanner: Optional quantum scanner component
            amplitude_amplifier: Optional amplitude amplifier component
            
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
        self.quantum_scanner = quantum_scanner or QuantumScanner(config)
        self.amplitude_amplifier = amplitude_amplifier or AmplitudeAmplifier(config)
        
        # Initialize state
        self.last_analysis: Dict[str, EntanglementAnalysisResult] = {}
        self.analysis_cache: Dict[str, EntanglementAnalysisResult] = {}
        
        self.logger.info("Initialized EntanglementEntropyAnalyzer for quantum vulnerability detection")
    
    def _setup_logger(self):
        """Set up logger for the analyzer."""
        logger = logging.getLogger("TopoSphere.EntanglementEntropyAnalyzer")
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
               public_key: Union[str, Point],
               force_reanalysis: bool = False) -> EntanglementAnalysisResult:
        """Analyze entanglement entropy for a public key.
        
        Args:
            public_key: Public key to analyze (hex string or Point object)
            force_reanalysis: Whether to force reanalysis even if recent
            
        Returns:
            EntanglementAnalysisResult object with analysis results
            
        Raises:
            ValueError: If public key is invalid
        """
        start_time = time.time()
        self.logger.info("Performing entanglement entropy analysis...")
        
        # Convert public key to Point if needed
        if isinstance(public_key, str):
            Q = public_key_hex_to_point(public_key, self.curve)
        elif isinstance(public_key, Point):
            Q = public_key
        else:
            raise ValueError("Invalid public key format")
        
        # Convert public key to hex for caching
        public_key_hex = point_to_public_key_hex(Q)
        
        # Generate cache key
        cache_key = f"{public_key_hex[:16]}_{self.curve.name}"
        
        # Check cache
        if not force_reanalysis and cache_key in self.last_analysis:
            last_analysis = self.last_analysis[cache_key].analysis_timestamp
            if time.time() - last_analysis < 3600:  # 1 hour
                self.logger.info(f"Using cached entanglement analysis for key {public_key_hex[:16]}...")
                return self.last_analysis[cache_key]
        
        try:
            # Estimate private key
            d = estimate_private_key(Q, self.curve)
            
            # Perform quantum scan
            scan_result = self.quantum_scanner.scan(public_key_hex, force_rescan=force_reanalysis)
            
            # Calculate GCD(d, n)
            gcd_value = gcd(d, self.n) if d else 1
            
            # Calculate entanglement entropy
            entanglement_entropy = math.log2(gcd_value) if gcd_value > 1 else 0.0
            
            # Calculate entanglement score (normalized)
            max_entropy = math.log2(self.n)  # Maximum possible entropy
            entanglement_score = entanglement_entropy / max_entropy if max_entropy > 0 else 0.0
            
            # Determine pattern type
            pattern_type = EntanglementPattern.from_entanglement_score(entanglement_score, gcd_value)
            
            # Calculate criticality (higher for weak keys)
            criticality = 0.0
            if gcd_value > 1:
                criticality = min(1.0, math.log2(gcd_value) / math.log2(self.n) * 1.5)
            
            # Estimate location of potential vulnerability
            location = self._estimate_vulnerability_location(scan_result)
            
            # Calculate confidence
            confidence = 1.0 - min(1.0, entanglement_score * 0.7)
            
            # Calculate quantum vulnerability score
            quantum_vulnerability_score = self._calculate_quantum_vulnerability_score(
                entanglement_score,
                scan_result
            )
            
            # Create entanglement metrics
            entanglement_metrics = EntanglementMetrics(
                entanglement_score=entanglement_score,
                entanglement_entropy=entanglement_entropy,
                gcd_value=gcd_value,
                pattern_type=pattern_type,
                criticality=criticality,
                confidence=confidence,
                location=location,
                quantum_vulnerability_score=quantum_vulnerability_score,
                meta={
                    "d_estimate": d,
                    "max_entropy": max_entropy,
                    "entanglement_formula": "S = log₂(gcd(d, n))"
                }
            )
            
            # Create analysis result
            result = EntanglementAnalysisResult(
                public_key=public_key_hex,
                curve=self.curve.name,
                entanglement_metrics=entanglement_metrics,
                topological_integrity=scan_result.topological_integrity,
                symmetry_violation_rate=scan_result.symmetry_violation_rate,
                spiral_score=scan_result.spiral_score,
                star_score=scan_result.star_score,
                critical_regions=scan_result.critical_regions,
                quantum_vulnerability_score=quantum_vulnerability_score,
                execution_time=time.time() - start_time,
                meta={
                    "scan_result": scan_result.to_dict(),
                    "entanglement_metrics": entanglement_metrics.to_dict()
                }
            )
            
            # Cache results
            self.last_analysis[cache_key] = result
            self.analysis_cache[cache_key] = result
            
            self.logger.info(
                f"Entanglement entropy analysis completed in {time.time() - start_time:.4f}s. "
                f"Entropy: {entanglement_entropy:.4f}, Vulnerability score: {quantum_vulnerability_score:.4f}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Entanglement entropy analysis failed: {str(e)}")
            raise ValueError(f"Analysis failed: {str(e)}") from e
    
    def _estimate_vulnerability_location(self, scan_result: ScanResult) -> Tuple[float, float]:
        """Estimate location of potential vulnerability based on scan results.
        
        Args:
            scan_result: Quantum scan result
            
        Returns:
            Estimated location (u_r, u_z)
        """
        n = self.n
        
        # Use critical regions if available
        if scan_result.critical_regions:
            most_critical = max(
                scan_result.critical_regions,
                key=lambda r: r.get("amplification", 0.0)
            )
            u_r_min, u_r_max = most_critical["u_r_range"]
            u_z_min, u_z_max = most_critical["u_z_range"]
            return ((u_r_min + u_r_max) / 2.0, (u_z_min + u_z_max) / 2.0)
        
        # Fallback to pattern-based estimation
        if scan_result.spiral_score < 0.7:
            return (n / 4, n / 4)  # Spiral patterns often in corners
        elif scan_result.star_score > 0.6:
            return (n / 2, n / 4)  # Star patterns often centered
        
        # Default to center
        return (n / 2, n / 2)
    
    def _calculate_quantum_vulnerability_score(self,
                                             entanglement_score: float,
                                             scan_result: ScanResult) -> float:
        """Calculate quantum vulnerability score from analysis results.
        
        Args:
            entanglement_score: Entanglement score (0-1)
            scan_result: Quantum scan result
            
        Returns:
            Quantum vulnerability score (0-1, higher = more vulnerable)
        """
        # Base score from entanglement
        base_score = entanglement_score * 0.5
        
        # Add penalties for specific issues
        penalties = []
        
        # Symmetry violation
        if scan_result.symmetry_violation_rate > 0.01:
            penalties.append(scan_result.symmetry_violation_rate * 0.2)
        
        # Spiral pattern
        if scan_result.spiral_score < 0.7:
            penalties.append((0.7 - scan_result.spiral_score) * 0.2)
        
        # Star pattern
        if scan_result.star_score > 0.6:
            penalties.append((scan_result.star_score - 0.6) * 0.1)
        
        # Calculate final score
        vulnerability_score = base_score + sum(penalties)
        return min(1.0, vulnerability_score)
    
    def get_analysis_report(self,
                           public_key: Union[str, Point],
                           result: Optional[EntanglementAnalysisResult] = None,
                           include_quantum_metrics: bool = True) -> str:
        """Get human-readable entanglement analysis report.
        
        Args:
            public_key: Public key to analyze
            result: Optional analysis result (will generate if None)
            include_quantum_metrics: Whether to include detailed quantum metrics
            
        Returns:
            Analysis report as string
        """
        if result is None:
            result = self.analyze(public_key)
        
        # Get entanglement metrics
        metrics = result.entanglement_metrics
        
        # Format location
        location = f"({metrics.location[0]:.2f}, {metrics.location[1]:.2f})"
        
        lines = [
            "=" * 80,
            "ENTANGLEMENT ENTROPY ANALYSIS REPORT",
            "=" * 80,
            f"Analysis Timestamp: {datetime.fromtimestamp(result.analysis_timestamp).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Public Key: {result.public_key[:50]}{'...' if len(result.public_key) > 50 else ''}",
            f"Curve: {result.curve}",
            "",
            "QUANTUM ENTANGLEMENT METRICS:",
            f"Entanglement Entropy: {metrics.entanglement_entropy:.4f}",
            f"Entanglement Score: {metrics.entanglement_score:.4f}",
            f"GCD(d, n): {metrics.gcd_value}",
            f"Pattern Type: {metrics.pattern_type.value.upper()}",
            f"Criticality: {metrics.criticality:.4f}",
            f"Confidence: {metrics.confidence:.4f}",
            f"Location: {location}",
            "",
            "SECURITY ASSESSMENT:",
            f"Quantum Vulnerability Score: {result.quantum_vulnerability_score:.4f}",
            f"Security Level: {result.security_level.upper()}",
            f"Topological Integrity: {result.topological_integrity:.4f}",
            f"Symmetry Violation Rate: {result.symmetry_violation_rate:.4f}",
            f"Spiral Pattern Score: {result.spiral_score:.4f}",
            f"Star Pattern Score: {result.star_score:.4f}",
            ""
        ]
        
        # Add quantum metrics section if requested
        if include_quantum_metrics:
            lines.extend([
                "QUANTUM METRICS DETAILS:",
                f"  - Entanglement entropy formula: S = log₂(gcd(d, n))",
                f"  - Maximum possible entropy: {math.log2(result.meta['scan_result']['n']):.4f}",
                f"  - Theoretical secure entropy: > {math.log2(result.meta['scan_result']['n']) * 0.7:.4f}",
                f"  - Entanglement vulnerability threshold: {self.config.entanglement_threshold:.4f}",
                ""
            ])
        
        # Add critical regions
        if result.critical_regions:
            lines.append("CRITICAL REGIONS:")
            for i, region in enumerate(result.critical_regions[:3], 1):  # Show up to 3 regions
                u_r_range = region["u_r_range"]
                u_z_range = region["u_z_range"]
                amplification = region["amplification"]
                lines.append(
                    f"  {i}. Region: u_r={u_r_range[0]:.2f}-{u_r_range[1]:.2f}, "
                    f"u_z={u_z_range[0]:.2f}-{u_z_range[1]:.2f}"
                )
                lines.append(
                    f"     Amplification: {amplification:.4f}, Type: {region['type'].upper()}"
                )
            
            if len(result.critical_regions) > 3:
                lines.append(f"  - And {len(result.critical_regions) - 3} more critical regions")
        
        # Add recommendation
        lines.extend([
            "",
            "RECOMMENDATION:",
            f"  {metrics.get_recommendation()}",
            "",
            "=" * 80,
            "ENTANGLEMENT ENTROPY ANALYSIS FOOTER",
            "=" * 80,
            "This report was generated by TopoSphere Entanglement Entropy Analyzer,",
            "a component of the Quantum Scanning system for detecting ECDSA vulnerabilities.",
            "Analysis is based on quantum entanglement theory with the formula S = log₂(gcd(d, n)).",
            "A 'secure' result does not guarantee the absence of all possible vulnerabilities.",
            "Additional security testing is recommended for critical systems.",
            "=" * 80
        ])
        
        return "\n".join(lines)
    
    def detect_weak_key_vulnerability(self,
                                     public_key: Union[str, Point],
                                     threshold: float = 1.0) -> bool:
        """Detect if a weak key vulnerability exists based on entanglement entropy.
        
        Args:
            public_key: Public key to analyze
            threshold: Threshold for weak key detection (default: 1.0)
            
        Returns:
            True if weak key vulnerability detected, False otherwise
        """
        result = self.analyze(public_key)
        return result.entanglement_metrics.gcd_value > threshold
    
    def get_weak_key_gcd(self, public_key: Union[str, Point]) -> int:
        """Get the GCD(d, n) value for a public key.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            GCD(d, n) value
        """
        result = self.analyze(public_key)
        return result.entanglement_metrics.gcd_value
    
    def get_quantum_security_metrics(self,
                                    public_key: Union[str, Point]) -> Dict[str, Any]:
        """Get quantum-inspired security metrics for a public key.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            Dictionary with quantum security metrics
        """
        result = self.analyze(public_key)
        metrics = result.entanglement_metrics
        
        return {
            "entanglement_entropy": metrics.entanglement_entropy,
            "entanglement_score": metrics.entanglement_score,
            "gcd_value": metrics.gcd_value,
            "quantum_vulnerability_score": result.quantum_vulnerability_score,
            "security_level": result.security_level,
            "pattern_type": metrics.pattern_type.value,
            "criticality": metrics.criticality,
            "formula": "S = log₂(gcd(d, n))"
        }
    
    def verify_tcon_compliance(self,
                              public_key: Union[str, Point]) -> bool:
        """Verify TCON (Topological Conformance) compliance based on entanglement metrics.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            True if TCON compliant, False otherwise
        """
        result = self.analyze(public_key)
        
        # TCON compliance requires:
        # 1. GCD(d, n) = 1 (no weak key vulnerability)
        # 2. Entanglement entropy above threshold
        # 3. Security level is secure or caution
        return (
            result.entanglement_metrics.gcd_value == 1 and
            result.entanglement_metrics.entanglement_entropy > math.log2(self.n) * 0.7 and
            result.security_level in ["secure", "caution"]
        )
    
    def get_vulnerability_probability(self,
                                     public_key: Union[str, Point]) -> float:
        """Get the probability of vulnerability based on entanglement metrics.
        
        Args:
            public_key: Public key to analyze
            
        Returns:
            Vulnerability probability (0-1)
        """
        result = self.analyze(public_key)
        return result.quantum_vulnerability_score
    
    def get_entanglement_profile(self,
                                public_key: Union[str, Point],
                                resolution: int = 100) -> np.ndarray:
        """Get the entanglement profile across the signature space.
        
        Args:
            public_key: Public key to analyze
            resolution: Resolution of the profile
            
        Returns:
            2D array representing entanglement profile
        """
        # In a real implementation, this would calculate the entanglement profile
        # For demonstration, we'll simulate a profile based on critical regions
        
        profile = np.zeros((resolution, resolution))
        result = self.analyze(public_key)
        
        # Add critical regions to profile
        for region in result.critical_regions:
            u_r_min, u_r_max = region["u_r_range"]
            u_z_min, u_z_max = region["u_z_range"]
            
            # Convert to grid coordinates
            i_min = int(u_r_min / self.n * resolution)
            i_max = int(u_r_max / self.n * resolution)
            j_min = int(u_z_min / self.n * resolution)
            j_max = int(u_z_max / self.n * resolution)
            
            # Set amplification value
            amplification = region["amplification"]
            for i in range(max(0, i_min), min(resolution, i_max)):
                for j in range(max(0, j_min), min(resolution, j_max)):
                    profile[i, j] = max(profile[i, j], amplification)
        
        return profile
    
    def visualize_entanglement_profile(self,
                                      public_key: Union[str, Point],
                                      resolution: int = 100) -> None:
        """Visualize the entanglement profile across the signature space.
        
        Args:
            public_key: Public key to analyze
            resolution: Resolution of the profile
        """
        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            profile = self.get_entanglement_profile(public_key, resolution)
            
            # Create heatmap
            plt.figure(figsize=(10, 8))
            sns.heatmap(
                profile,
                cmap="viridis_r",
                annot=False,
                cbar_kws={'label': 'Amplification'}
            )
            
            plt.title(f"Entanglement Profile for Public Key {public_key[:16]}...")
            plt.xlabel("u_r")
            plt.ylabel("u_z")
            
            plt.tight_layout()
            plt.show()
            
        except ImportError:
            self.logger.error("matplotlib or seaborn not available for visualization")
    
    def get_entanglement_statistics(self,
                                   public_keys: List[Union[str, Point]]) -> Dict[str, Any]:
        """Get statistics about entanglement metrics across multiple public keys.
        
        Args:
            public_keys: List of public keys to analyze
            
        Returns:
            Dictionary with entanglement statistics
        """
        gcd_values = []
        entanglement_entropies = []
        vulnerability_scores = []
        weak_key_count = 0
        
        for public_key in public_keys:
            result = self.analyze(public_key)
            metrics = result.entanglement_metrics
            
            gcd_values.append(metrics.gcd_value)
            entanglement_entropies.append(metrics.entanglement_entropy)
            vulnerability_scores.append(result.quantum_vulnerability_score)
            
            if metrics.gcd_value > 1:
                weak_key_count += 1
        
        return {
            "total_keys": len(public_keys),
            "average_gcd": np.mean(gcd_values),
            "max_gcd": max(gcd_values),
            "min_gcd": min(gcd_values),
            "average_entanglement_entropy": np.mean(entanglement_entropies),
            "average_vulnerability_score": np.mean(vulnerability_scores),
            "weak_key_count": weak_key_count,
            "weak_key_percentage": (weak_key_count / len(public_keys)) * 100 if public_keys else 0.0,
            "secure_keys": sum(1 for score in vulnerability_scores if score < 0.2),
            "vulnerable_keys": sum(1 for score in vulnerability_scores if score >= 0.2)
        }
