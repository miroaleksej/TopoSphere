"""
Elliptic Curve Utilities Module

This module provides essential utilities for elliptic curve operations used throughout
the TopoSphere system. It implements the bijective parameterization (u_r, u_z) that
enables topological analysis of ECDSA implementations without requiring knowledge
of the private key.

The module leverages the fastecdsa library for efficient elliptic curve operations
while adding specialized functionality for topological security analysis. Key features
include:
- Bijective parameterization of ECDSA signatures
- Synthetic signature generation without private key knowledge
- Topological structure analysis of signature spaces
- Diagonal symmetry verification
- Spiral pattern detection
- Vulnerability assessment based on topological properties

This module is designed to work seamlessly with topological_models.py and cryptographic_models.py,
providing the elliptic curve foundation for the topological security framework.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
import numpy as np
import random
import math
from functools import lru_cache
import warnings
import sys
import time
from collections import defaultdict

# External dependencies
try:
    from fastecdsa.curve import Curve, secp256k1
    from fastecdsa.point import Point
    from fastecdsa.util import mod_sqrt
    EC_LIBS_AVAILABLE = True
except ImportError as e:
    EC_LIBS_AVAILABLE = False
    warnings.warn(f"fastecdsa library not found: {e}. Some features will be limited.", 
                 RuntimeWarning)

# Import from our own modules
from ..models.topological_models import (
    BettiNumbers,
    SignatureSpace,
    TorusStructure
)
from ..models.cryptographic_models import (
    ECDSASignature,
    NonceSecurityAssessment
)
from .math_utils import (
    gcd,
    modular_inverse,
    compute_betti_numbers,
    is_torus_structure,
    calculate_topological_entropy,
    check_diagonal_symmetry,
    compute_spiral_pattern,
    estimate_private_key,
    calculate_periodicity,
    calculate_fractal_dimension,
    calculate_uniformity_score
)

# ======================
# CURVE DEFINITIONS
# ======================

# Supported curves
SECP256K1 = secp256k1 if EC_LIBS_AVAILABLE else None
NIST_P256 = Curve(
    'NIST_P256', 
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550,
    1,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
) if not EC_LIBS_AVAILABLE else None

# Curve parameters for secp256k1
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ======================
# ELLIPTIC CURVE UTILITIES
# ======================

def validate_curve(curve: Curve) -> bool:
    """Validate elliptic curve parameters.
    
    Args:
        curve: Curve to validate
        
    Returns:
        True if curve parameters are valid, False otherwise
    """
    if not EC_LIBS_AVAILABLE:
        return False
    
    try:
        # Check basic curve parameters
        if curve.p <= 0:
            return False
        
        # Check if curve equation holds for generator point
        G = curve.G
        if (G.y * G.y) % curve.p != (G.x * G.x * G.x + curve.a * G.x + curve.b) % curve.p:
            return False
            
        # Check order of generator point
        if curve.n <= 0:
            return False
            
        return True
    except Exception as e:
        warnings.warn(f"Curve validation failed: {e}", RuntimeWarning)
        return False


def validate_public_key(public_key: Point, curve: Curve) -> bool:
    """Validate a public key for the specified curve.
    
    Args:
        public_key: Public key to validate
        curve: Elliptic curve parameters
        
    Returns:
        True if public key is valid, False otherwise
    """
    if not EC_LIBS_AVAILABLE:
        return False
    
    try:
        # Check if point is on the curve
        if public_key == Point.IDENTITY:
            return False
            
        y2 = (public_key.x * public_key.x * public_key.x + 
              curve.a * public_key.x + 
              curve.b) % curve.p
        x2 = (public_key.y * public_key.y) % curve.p
        
        if y2 != x2:
            return False
            
        # Check if point has correct order
        if public_key * curve.n != Point.IDENTITY:
            return False
            
        return True
    except Exception as e:
        warnings.warn(f"Public key validation failed: {e}", RuntimeWarning)
        return False


def point_to_public_key_hex(point: Point, compressed: bool = True) -> str:
    """Convert a point to public key hex representation.
    
    Args:
        point: Point to convert
        compressed: Whether to use compressed format
        
    Returns:
        Public key in hex format
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if point == Point.IDENTITY:
        return "00"
    
    if compressed:
        prefix = "02" if point.y % 2 == 0 else "03"
        return prefix + format(point.x, 'x')
    else:
        return "04" + format(point.x, 'x') + format(point.y, 'x')


def public_key_hex_to_point(public_key_hex: str, curve: Curve) -> Point:
    """Convert public key hex to point.
    
    Args:
        public_key_hex: Public key in hex format
        curve: Elliptic curve parameters
        
    Returns:
        Point representation of public key
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if public_key_hex.startswith("04"):
        # Uncompressed format
        x = int(public_key_hex[2:66], 16)
        y = int(public_key_hex[66:130], 16)
        return Point(x, y, curve)
    elif public_key_hex.startswith(("02", "03")):
        # Compressed format
        x = int(public_key_hex[2:], 16)
        y_square = (x * x * x + curve.a * x + curve.b) % curve.p
        y = mod_sqrt(y_square, curve.p)
        
        # Adjust y based on prefix
        if (public_key_hex.startswith("02") and y % 2 != 0) or \
           (public_key_hex.startswith("03") and y % 2 == 0):
            y = curve.p - y
            
        return Point(x, y, curve)
    else:
        raise ValueError("Invalid public key format")


def compute_r(Q: Point, u_r: int, u_z: int, curve: Curve) -> int:
    """Compute R_x value for given parameters.
    
    Based on the bijective parameterization:
    R = (u_r * Q + u_z * G)
    r = R_x mod n
    
    Args:
        Q: Public key point
        u_r, u_z: Topological parameters
        curve: Elliptic curve parameters
        
    Returns:
        R_x value mod n
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Compute R = (u_r * Q + u_z * G)
    R = u_r * Q + u_z * curve.G
    
    # Handle point at infinity
    if R == Point.IDENTITY:
        return 0
        
    return R.x % curve.n


def generate_synthetic_signatures(Q: Point, 
                                 curve: Curve, 
                                 num_samples: int = 1000,
                                 sampling_rate: float = 0.01) -> List[ECDSASignature]:
    """Generate synthetic signatures for analysis.
    
    As proven in Theorem 19 of our research, for any public key Q = dG and
    for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z).
    
    This method implements that theorem, generating signatures without knowledge
    of the private key.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of signatures to generate
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        List of synthetic signatures
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    signatures = []
    step = max(1, int(1 / sampling_rate))
    
    for _ in range(num_samples):
        u_r = random.randint(0, curve.n - 1)
        u_z = random.randint(0, curve.n - 1)
        
        # Compute R_x directly from public key
        r = compute_r(Q, u_r, u_z, curve)
        
        # Choose s arbitrarily (e.g., 1)
        s = 1
        
        # Compute z = s * u_z mod n
        z = (s * u_z) % curve.n
        
        signatures.append(ECDSASignature(
            r=r,
            s=s,
            z=z,
            u_r=u_r,
            u_z=u_z,
            is_synthetic=True,
            confidence=1.0,
            source="synthetic"
        ))
    
    return signatures


def generate_real_signatures(Q: Point,
                            d: int,
                            curve: Curve,
                            num_samples: int = 100,
                            nonce_generator: Callable[[int, int], int] = None) -> List[ECDSASignature]:
    """Generate real signatures using a nonce generator.
    
    Args:
        Q: Public key point
        d: Private key
        curve: Elliptic curve parameters
        num_samples: Number of signatures to generate
        nonce_generator: Function to generate nonce k (u_r, u_z) -> k
        
    Returns:
        List of real signatures
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if nonce_generator is None:
        # Default nonce generator (RFC 6979 would be more complex)
        nonce_generator = lambda u_r, u_z: (u_r + u_z) % curve.n
    
    signatures = []
    
    for _ in range(num_samples):
        # Generate nonce k
        u_r = random.randint(0, curve.n - 1)
        u_z = random.randint(0, curve.n - 1)
        k = nonce_generator(u_r, u_z)
        
        # Compute R = k * G
        R = k * curve.G
        r = R.x % curve.n
        
        # Generate random message hash z
        z = random.randint(0, curve.n - 1)
        
        # Compute s = k^-1 (z + r*d) mod n
        s = (modular_inverse(k, curve.n) * (z + r * d)) % curve.n
        
        signatures.append(ECDSASignature(
            r=r,
            s=s,
            z=z,
            u_r=u_r,
            u_z=u_z,
            is_synthetic=False,
            confidence=1.0,
            source="real"
        ))
    
    return signatures


def analyze_signature_space(Q: Point, 
                           curve: Curve, 
                           num_samples: int = 1000,
                           sampling_rate: float = 0.01) -> SignatureSpace:
    """Analyze the topological structure of the signature space.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        SignatureSpace object containing analysis results
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud for analysis
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Compute Betti numbers
    epsilon = 0.1 * curve.n
    betti = compute_betti_numbers(points, epsilon)
    
    # Calculate topological entropy
    topological_entropy = calculate_topological_entropy(points, curve.n)
    
    # Check diagonal symmetry
    symmetry_analysis = check_diagonal_symmetry(points, curve.n)
    
    # Analyze spiral pattern
    spiral_analysis = compute_spiral_pattern(points, curve.n)
    
    # Calculate fractal dimension
    fractal_dimension = calculate_fractal_dimension(points, curve.n)
    
    # Calculate uniformity score
    uniformity_score = calculate_uniformity_score(points, curve.n)
    
    # Determine structure type
    structure_type = "torus" if is_torus_structure(points, curve.n) else "unknown"
    
    return SignatureSpace(
        n=curve.n,
        public_key=point_to_public_key_hex(Q),
        curve_name=curve.name,
        betti_numbers=BettiNumbers(
            beta_0=betti["beta_0"],
            beta_1=betti["beta_1"],
            beta_2=betti["beta_2"]
        ),
        persistence_diagrams=[],  # In real implementation, would be populated
        spiral_pattern=spiral_analysis,
        diagonal_symmetry=symmetry_analysis,
        topological_entropy=topological_entropy,
        fractal_dimension=fractal_dimension,
        uniformity_score=uniformity_score,
        structure_type=structure_type
    )


def analyze_nonce_security(Q: Point, 
                          curve: Curve, 
                          num_samples: int = 1000,
                          sampling_rate: float = 0.01) -> NonceSecurityAssessment:
    """Analyze the security of nonce generation for a public key.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        NonceSecurityAssessment object
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Calculate entropy estimate
    # In real implementation, would calculate actual entropy
    entropy_estimate = calculate_topological_entropy(points, curve.n)
    
    # Check symmetry violations
    symmetry_analysis = check_diagonal_symmetry(points, curve.n)
    
    # Analyze spiral pattern
    spiral_analysis = compute_spiral_pattern(points, curve.n)
    
    # Calculate periodicity
    periodicity_analysis = calculate_periodicity(points, curve.n)
    
    # Determine security level
    if symmetry_analysis["violation_rate"] > 0.1 or spiral_analysis["consistency_score"] < 0.7:
        security_level = "critical"
    elif symmetry_analysis["violation_rate"] > 0.05 or spiral_analysis["consistency_score"] < 0.85:
        security_level = "vulnerable"
    elif symmetry_analysis["violation_rate"] > 0.01 or spiral_analysis["consistency_score"] < 0.95:
        security_level = "caution"
    else:
        security_level = "secure"
    
    # Identify vulnerability indicators
    indicators = []
    if symmetry_analysis["violation_rate"] > 0.01:
        indicators.append("symmetry_violation")
    if spiral_analysis["consistency_score"] < 0.95:
        indicators.append("spiral_pattern_anomaly")
    if periodicity_analysis["periodicity_score"] < 0.3:
        indicators.append("diagonal_periodicity")
    
    return NonceSecurityAssessment(
        entropy_estimate=entropy_estimate,
        uniformity_score=calculate_uniformity_score(points, curve.n),
        symmetry_violation_rate=symmetry_analysis["violation_rate"],
        spiral_consistency=spiral_analysis["consistency_score"],
        diagonal_consistency=periodicity_analysis["periodicity_score"],
        vulnerability_indicators=indicators,
        security_level=security_level
    )


def detect_vulnerabilities(Q: Point, 
                          curve: Curve, 
                          num_samples: int = 1000,
                          sampling_rate: float = 0.01) -> List[Dict[str, Any]]:
    """Detect vulnerabilities in an ECDSA implementation.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        List of detected vulnerabilities
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    vulnerabilities = []
    
    # Analyze signature space
    signature_space = analyze_signature_space(Q, curve, num_samples, sampling_rate)
    
    # Check for torus structure
    if not signature_space.is_secure():
        vulnerabilities.append({
            "type": "topological_structure",
            "description": "Signature space does not match expected torus structure",
            "severity": "high",
            "details": {
                "betti_numbers": {
                    "beta_0": signature_space.betti_numbers.beta_0,
                    "beta_1": signature_space.betti_numbers.beta_1,
                    "beta_2": signature_space.betti_numbers.beta_2
                },
                "expected": {"beta_0": 1, "beta_1": 2, "beta_2": 1},
                "deviation": signature_space.betti_numbers.deviation_score
            }
        })
    
    # Check symmetry violations
    if signature_space.diagonal_symmetry and signature_space.diagonal_symmetry["violation_rate"] > 0.01:
        violations = signature_space.diagonal_symmetry["violation_rate"]
        vulnerabilities.append({
            "type": "symmetry_violation",
            "description": f"High symmetry violation rate detected ({violations:.4f})",
            "severity": "high" if violations > 0.05 else "medium",
            "details": {
                "violation_rate": violations,
                "threshold": 0.01
            }
        })
    
    # Check spiral consistency
    if signature_space.spiral_pattern and signature_space.spiral_pattern["consistency_score"] < 0.95:
        consistency = signature_space.spiral_pattern["consistency_score"]
        vulnerabilities.append({
            "type": "spiral_inconsistency",
            "description": f"Low spiral pattern consistency ({consistency:.4f})",
            "severity": "high" if consistency < 0.7 else "medium",
            "details": {
                "consistency_score": consistency,
                "threshold": 0.95
            }
        })
    
    # Check topological entropy
    if signature_space.topological_entropy < 0.5:
        entropy = signature_space.topological_entropy
        vulnerabilities.append({
            "type": "low_entropy",
            "description": f"Low topological entropy detected ({entropy:.4f})",
            "severity": "high" if entropy < 0.3 else "medium",
            "details": {
                "entropy": entropy,
                "threshold": 0.5
            }
        })
    
    return vulnerabilities


def analyze_torus_structure(Q: Point, 
                           curve: Curve, 
                           num_samples: int = 1000,
                           sampling_rate: float = 0.01) -> TorusStructure:
    """Analyze the torus structure of the signature space.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        TorusStructure object
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Estimate private key
    d = estimate_private_key(points, curve.n)
    
    # Analyze spiral pattern
    spiral_analysis = compute_spiral_pattern(points, curve.n, d)
    
    # Calculate periodicity
    periodicity_analysis = calculate_periodicity(points, curve.n)
    
    # Check diagonal symmetry
    symmetry_analysis = check_diagonal_symmetry(points, curve.n)
    
    # Find critical points
    critical_points = []
    if d is not None:
        for u_r in range(0, curve.n, curve.n // 100):
            u_z = (-d * u_r) % curve.n
            critical_points.append((u_r, u_z))
    
    return TorusStructure(
        n=curve.n,
        private_key_estimate=d,
        spiral_slope=spiral_analysis.get("slope", 0.0),
        spiral_period=spiral_analysis.get("period", curve.n),
        diagonal_period=periodicity_analysis.get("diagonal_period", curve.n),
        symmetry_violation_rate=symmetry_analysis.get("violation_rate", 1.0),
        is_valid_torus=is_torus_structure(points, curve.n),
        confidence=0.9 if is_torus_structure(points, curve.n) else 0.1,
        critical_points=critical_points
    )


def estimate_private_key_from_signatures(signatures: List[ECDSASignature], 
                                       curve: Curve) -> Optional[int]:
    """Estimate the private key from signatures.
    
    Args:
        signatures: List of ECDSA signatures
        curve: Elliptic curve parameters
        
    Returns:
        Estimated private key or None if cannot be estimated
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if len(signatures) < 2:
        return None
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Use the math_utils function
    return estimate_private_key(points, curve.n)


def check_diagonal_symmetry_violations(Q: Point, 
                                     curve: Curve, 
                                     num_samples: int = 1000,
                                     sampling_rate: float = 0.01) -> Dict[str, float]:
    """Check for diagonal symmetry violations.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        Dictionary with symmetry violation metrics
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Check diagonal symmetry
    return check_diagonal_symmetry(points, curve.n)


def compute_spiral_consistency(Q: Point, 
                              curve: Curve, 
                              num_samples: int = 1000,
                              sampling_rate: float = 0.01) -> Dict[str, Any]:
    """Compute spiral consistency metrics.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        Dictionary with spiral consistency metrics
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Estimate private key
    d = estimate_private_key(points, curve.n)
    
    # Analyze spiral pattern
    return compute_spiral_pattern(points, curve.n, d)


def calculate_diagonal_periodicity(Q: Point, 
                                  curve: Curve, 
                                  num_samples: int = 1000,
                                  sampling_rate: float = 0.01) -> Dict[str, Any]:
    """Calculate diagonal periodicity.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        Dictionary with diagonal periodicity metrics
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Calculate periodicity
    return calculate_periodicity(points, curve.n)


def analyze_fractal_structure(Q: Point, 
                             curve: Curve, 
                             num_samples: int = 1000,
                             sampling_rate: float = 0.01) -> Dict[str, Any]:
    """Analyze the fractal structure of the signature space.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        Dictionary with fractal structure analysis
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Generate synthetic signatures
    signatures = generate_synthetic_signatures(Q, curve, num_samples, sampling_rate)
    
    # Convert to point cloud
    points = np.array([
        [sig.u_r, sig.u_z, sig.r] 
        for sig in signatures
    ])
    
    # Calculate fractal dimension
    fractal_dimension = calculate_fractal_dimension(points, curve.n)
    
    # Detect spiral fractals
    spiral_fractals = []  # In real implementation, would detect fractals
    
    return {
        "fractal_dimension": fractal_dimension,
        "spiral_fractals": spiral_fractals,
        "is_fractal_consistent": fractal_dimension > 1.8
    }


def estimate_address_rotation_point(Q: Point, 
                                  curve: Curve, 
                                  transaction_count: int,
                                  num_samples: int = 1000,
                                  sampling_rate: float = 0.01) -> int:
    """Estimate the optimal address rotation point.
    
    Uses the model P_vuln(m) = 1 - e^(-λm) to determine optimal rotation point.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        transaction_count: Current number of transactions
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        Optimal rotation point (number of transactions)
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    # Analyze nonce security
    security_assessment = analyze_nonce_security(Q, curve, num_samples, sampling_rate)
    
    # Calculate vulnerability score
    vulnerability_score = (
        0.3 * (1.0 - security_assessment.entropy_estimate) +
        0.25 * security_assessment.symmetry_violation_rate +
        0.2 * (1.0 - security_assessment.spiral_consistency) +
        0.15 * (1.0 - security_assessment.diagonal_consistency) +
        0.1 * (1.0 - min(security_assessment.entropy_estimate, 1.0))
    )
    
    # Model parameters
    lambda_param = 0.01 * vulnerability_score
    risk_threshold = 0.05
    
    # Calculate optimal rotation point (m* = argmin_m {c·m + L·P_vuln(m)})
    optimal_rotation = int(math.log(1 - risk_threshold) / -lambda_param)
    
    return optimal_rotation


def is_address_secure(Q: Point, 
                     curve: Curve, 
                     transaction_count: int,
                     num_samples: int = 1000,
                     sampling_rate: float = 0.01) -> bool:
    """Determine if an address is still secure.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        transaction_count: Current number of transactions
        num_samples: Number of samples for analysis
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        True if address is secure, False otherwise
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    optimal_rotation = estimate_address_rotation_point(
        Q, curve, transaction_count, num_samples, sampling_rate
    )
    
    # Address is secure if we're below 80% of optimal rotation
    return transaction_count < 0.8 * optimal_rotation


# ======================
# HELPER FUNCTIONS FOR BIJECTIVE PARAMETERIZATION
# ======================

def compute_u_r_and_u_z(r: int, s: int, z: int, curve: Curve) -> Tuple[int, int]:
    """Compute u_r and u_z from signature components.
    
    Based on the bijective parameterization:
    u_r = s^-1 * r mod n
    u_z = s^-1 * z mod n
    
    Args:
        r, s, z: Signature components
        curve: Elliptic curve parameters
        
    Returns:
        Tuple (u_r, u_z)
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if s == 0:
        raise ValueError("s cannot be zero")
    
    # Compute modular inverse of s
    s_inv = modular_inverse(s, curve.n)
    
    # Compute u_r and u_z
    u_r = (s_inv * r) % curve.n
    u_z = (s_inv * z) % curve.n
    
    return u_r, u_z


def compute_signature_from_u(r: int, u_r: int, u_z: int, curve: Curve) -> Tuple[int, int, int]:
    """Compute signature components from u_r and u_z.
    
    Based on the bijective parameterization:
    s = r * u_r^-1 mod n
    z = s * u_z mod n
    
    Args:
        r: R_x value
        u_r, u_z: Topological parameters
        curve: Elliptic curve parameters
        
    Returns:
        Tuple (s, z, k) where k = u_z + u_r * d mod n
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if u_r == 0:
        raise ValueError("u_r cannot be zero")
    
    # Compute s = r * u_r^-1 mod n
    s = (r * modular_inverse(u_r, curve.n)) % curve.n
    
    # Compute z = s * u_z mod n
    z = (s * u_z) % curve.n
    
    # Note: k = u_z + u_r * d mod n, but we don't know d
    # We can't compute k without d, so we return None for k
    return s, z, None


def verify_bijective_parameterization(r: int, s: int, z: int, u_r: int, u_z: int, curve: Curve) -> bool:
    """Verify the bijective parameterization.
    
    Checks if:
    u_r = s^-1 * r mod n
    u_z = s^-1 * z mod n
    
    Args:
        r, s, z: Signature components
        u_r, u_z: Topological parameters
        curve: Elliptic curve parameters
        
    Returns:
        True if parameterization is valid, False otherwise
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    try:
        # Compute expected u_r and u_z
        expected_u_r, expected_u_z = compute_u_r_and_u_z(r, s, z, curve)
        
        # Check if they match
        return (u_r % curve.n == expected_u_r % curve.n and 
                u_z % curve.n == expected_u_z % curve.n)
    except Exception:
        return False


def generate_signature_space_points(Q: Point, 
                                   curve: Curve, 
                                   num_points: int = 1000,
                                   sampling_rate: float = 0.01) -> np.ndarray:
    """Generate points in the signature space for analysis.
    
    Args:
        Q: Public key point
        curve: Elliptic curve parameters
        num_points: Number of points to generate
        sampling_rate: Rate of sampling (0.0-1.0)
        
    Returns:
        Array of points [u_r, u_z, r]
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    points = []
    step = max(1, int(1 / sampling_rate))
    
    for _ in range(num_points):
        u_r = random.randint(0, curve.n - 1)
        u_z = random.randint(0, curve.n - 1)
        r = compute_r(Q, u_r, u_z, curve)
        points.append([u_r, u_z, r])
    
    return np.array(points)


def compute_k_from_u(u_r: int, u_z: int, d: int, curve: Curve) -> int:
    """Compute k from u_r, u_z and private key d.
    
    Based on the relationship:
    k = u_z + u_r * d mod n
    
    Args:
        u_r, u_z: Topological parameters
        d: Private key
        curve: Elliptic curve parameters
        
    Returns:
        k value
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    return (u_z + u_r * d) % curve.n


def compute_d_from_k_and_u(k: int, u_r: int, u_z: int, curve: Curve) -> int:
    """Compute d from k, u_r and u_z.
    
    Based on the relationship:
    d = (k - u_z) * u_r^-1 mod n
    
    Args:
        k: Nonce value
        u_r, u_z: Topological parameters
        curve: Elliptic curve parameters
        
    Returns:
        d value
    """
    if not EC_LIBS_AVAILABLE:
        raise RuntimeError("fastecdsa library is required but not available")
    
    if u_r == 0:
        raise ValueError("u_r cannot be zero")
    
    return ((k - u_z) * modular_inverse(u_r, curve.n)) % curve.n
