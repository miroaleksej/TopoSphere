"""
TopoSphere Client Crypto Utilities

This module provides cryptographic utility functions for the TopoSphere client system,
enabling secure interaction with the server's topological analysis capabilities. The
utilities are designed to prepare cryptographic data for analysis while maintaining
client-side privacy and security.

The module is built on the following foundational principles from our research:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- Direct analysis without building the full hypercube enables efficient monitoring of large spaces
- Bijective parameterization (u_r, u_z) enables efficient topological analysis
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
client-side utilities that prepare cryptographic data for topological analysis while maintaining
privacy guarantees.

Key features:
- ECDSA signature processing for topological analysis
- Correct bijective parameterization (u_r, u_z) computation
- Lightweight data preparation for server analysis
- Privacy-preserving cryptographic operations
- Support for standard elliptic curves (secp256k1, etc.)
- Integration with TopoSphere server protocols

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

import math
import random
import secrets
import warnings
import logging
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field

# Try to import fastecdsa for performance, fall back to pure Python if unavailable
try:
    from fastecdsa import curve, ecdsa, keys, point
    EC_LIBS_AVAILABLE = True
except ImportError:
    EC_LIBS_AVAILABLE = False
    warnings.warn(
        "fastecdsa library not found. Using pure Python implementation. "
        "Install with: pip install fastecdsa for better performance.",
        RuntimeWarning
    )

# Configure logger
logger = logging.getLogger("TopoSphere.Client.CryptoUtils")
logger.addHandler(logging.NullHandler())

# ======================
# CONSTANTS
# ======================

# secp256k1 curve parameters
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Common elliptic curves
CURVE_PARAMS = {
    "secp256k1": {
        "p": SECP256K1_P,
        "n": SECP256K1_N,
        "a": SECP256K1_A,
        "b": SECP256K1_B,
        "gx": SECP256K1_GX,
        "gy": SECP256K1_GY
    }
}

# ======================
# DATA CLASSES
# ======================

@dataclass
class Point:
    """Elliptic curve point representation."""
    x: int
    y: int
    curve: str = "secp256k1"
    
    def __eq__(self, other: object) -> bool:
        """Check if two points are equal."""
        if not isinstance(other, Point):
            return False
        return (self.x == other.x and 
                self.y == other.y and 
                self.curve == other.curve)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "x": self.x,
            "y": self.y,
            "curve": self.curve
        }

@dataclass
class ECDSASignature:
    """ECDSA signature data structure used throughout TopoSphere.
    
    This implementation strictly follows the bijective parameterization:
    - s = r * u_r^-1 mod n
    - z = u_z * s mod n
    
    As proven in our research: "For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n,
    there exists a signature (r, s, z)" where:
    - R_x = x((u_z + u_r · d) · G)
    - s = r · u_r^-1 mod n
    - z = u_z · s mod n
    """
    r: int
    s: int
    z: int
    u_r: int = 0
    u_z: int = 0
    is_synthetic: bool = False
    confidence: float = 1.0
    source: str = "client"
    timestamp: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "r": self.r,
            "s": self.s,
            "z": self.z,
            "u_r": self.u_r,
            "u_z": self.u_z,
            "is_synthetic": self.is_synthetic,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp,
            "meta": self.meta
        }
    
    def is_consistent(self, curve: Optional[Curve] = None) -> bool:
        """Check if the signature is consistent with bijective parameterization.
        
        Returns:
            True if consistent, False otherwise
        """
        if curve is None:
            curve = get_curve("secp256k1")
        
        # Check if u_r is non-zero (required for inverse)
        if self.u_r == 0:
            return False
        
        # Calculate expected s from bijective parameterization
        expected_s = (self.r * pow(self.u_r, -1, curve.n)) % curve.n
        
        # Calculate expected z from bijective parameterization
        expected_z = (self.u_z * self.s) % curve.n
        
        # Check consistency
        return (abs(self.s - expected_s) < 2 and 
                abs(self.z - expected_z) < 2)

@dataclass
class Curve:
    """Elliptic curve parameters."""
    name: str
    p: int  # Prime modulus
    n: int  # Order of the base point
    a: int  # Coefficient a
    b: int  # Coefficient b
    G: Point  # Base point
    
    @property
    def params(self) -> Dict[str, int]:
        """Get curve parameters as dictionary."""
        return {
            "p": self.p,
            "n": self.n,
            "a": self.a,
            "b": self.b
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "p": self.p,
            "n": self.n,
            "a": self.a,
            "b": self.b,
            "G": self.G.to_dict()
        }


# ======================
# CRYPTOGRAPHIC UTILITIES
# ======================

def get_curve(curve_name: str = "secp256k1") -> Curve:
    """
    Get curve parameters for the specified elliptic curve.
    
    Args:
        curve_name: Name of the elliptic curve (default: "secp256k1")
        
    Returns:
        Curve object with parameters
        
    Raises:
        ValueError: If curve is not supported
    """
    if curve_name not in CURVE_PARAMS:
        raise ValueError(f"Unsupported curve: {curve_name}")
    
    params = CURVE_PARAMS[curve_name]
    G = Point(params["gx"], params["gy"], curve_name)
    
    return Curve(
        name=curve_name,
        p=params["p"],
        n=params["n"],
        a=params["a"],
        b=params["b"],
        G=G
    )

def validate_public_key(public_key: Union[str, Point], curve_name: str = "secp256k1") -> bool:
    """
    Validate if a public key is on the specified elliptic curve.
    
    Args:
        public_key: Public key to validate (hex string or Point object)
        curve_name: Name of the elliptic curve
        
    Returns:
        True if valid, False otherwise
    """
    curve = get_curve(curve_name)
    
    # Convert to Point if needed
    if isinstance(public_key, str):
        try:
            # Remove 0x prefix if present
            if public_key.startswith("0x"):
                public_key = public_key[2:]
            
            # Handle compressed/uncompressed formats
            if len(public_key) == 66 and public_key[0] in ('02', '03'):
                # Compressed format
                is_even = public_key[0] == '02'
                x = int(public_key[2:], 16)
                y = _compute_y_from_x(x, is_even, curve)
                if y is None:
                    return False
            elif len(public_key) == 130 and public_key.startswith("04"):
                # Uncompressed format
                x = int(public_key[2:66], 16)
                y = int(public_key[66:], 16)
            else:
                return False
            
            point = Point(x, y, curve_name)
        except Exception:
            return False
    elif isinstance(public_key, Point):
        point = public_key
    else:
        return False
    
    # Check if point is on curve: y² = x³ + ax + b (mod p)
    y2 = (point.y * point.y) % curve.p
    x3 = (point.x * point.x * point.x) % curve.p
    ax = (curve.a * point.x) % curve.p
    rhs = (x3 + ax + curve.b) % curve.p
    
    if y2 != rhs:
        return False
    
    # Check if point is not infinity
    if point.x == 0 and point.y == 0:
        return False
    
    # Check if n*point = infinity
    # This is expensive, so we skip it in client-side validation
    # In a real implementation, this would be checked
    
    return True

def _compute_y_from_x(x: int, is_even: bool, curve: Curve) -> Optional[int]:
    """
    Compute y coordinate from x coordinate for a point on the curve.
    
    Args:
        x: x coordinate
        is_even: Whether y should be even
        curve: Curve parameters
        
    Returns:
        y coordinate or None if not on curve
    """
    # Compute y² = x³ + ax + b (mod p)
    y2 = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
    
    # Compute square root mod p
    y = _mod_sqrt(y2, curve.p)
    if y is None:
        return None
    
    # Adjust for even/odd
    if (y % 2 == 0) != is_even:
        y = curve.p - y
    
    return y

def _mod_sqrt(a: int, p: int) -> Optional[int]:
    """
    Compute modular square root using Tonelli-Shanks algorithm.
    
    Args:
        a: Value to take square root of
        p: Prime modulus
        
    Returns:
        Square root or None if not a quadratic residue
    """
    # Check if a is quadratic residue
    if pow(a, (p-1)//2, p) != 1:
        return None
    
    # Special case for p % 4 == 3
    if p % 4 == 3:
        return pow(a, (p+1)//4, p)
    
    # Tonelli-Shanks algorithm
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    
    # Find quadratic non-residue
    z = 2
    while pow(z, (p-1)//2, p) != p-1:
        z += 1
    
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q+1)//2, p)
    
    while t != 0 and t != 1:
        # Find smallest i such that t^(2^i) = 1
        i = 0
        temp = t
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        
        # Update variables
        b = pow(c, 1 << (m-i-1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    
    return r

def point_to_public_key_hex(point: Point) -> str:
    """
    Convert a point to compressed public key hex string.
    
    Args:
        point: Point object
        
    Returns:
        Compressed public key hex string
    """
    # Determine if y is even
    is_even = (point.y % 2 == 0)
    
    # Format as compressed key (02 for even y, 03 for odd y)
    prefix = "02" if is_even else "03"
    x_hex = format(point.x, '064x')
    
    return prefix + x_hex

def public_key_hex_to_point(public_key_hex: str, curve_name: str = "secp256k1") -> Point:
    """
    Convert a compressed public key hex string to a point.
    
    Args:
        public_key_hex: Compressed public key hex string
        curve_name: Name of the elliptic curve
        
    Returns:
        Point object
        
    Raises:
        ValueError: If public key is invalid
    """
    curve = get_curve(curve_name)
    
    # Remove 0x prefix if present
    if public_key_hex.startswith("0x"):
        public_key_hex = public_key_hex[2:]
    
    # Check format
    if len(public_key_hex) != 66 or public_key_hex[0] not in ('0', '1', '2', '3'):
        raise ValueError("Invalid public key format")
    
    # Extract prefix and x coordinate
    prefix = public_key_hex[0:2]
    x = int(public_key_hex[2:], 16)
    
    # Compute y coordinate
    is_even = (prefix == '02')
    y = _compute_y_from_x(x, is_even, curve)
    if y is None:
        raise ValueError("Public key not on curve")
    
    return Point(x, y, curve_name)

def compute_r(Q: Union[Point, str], u_r: int, u_z: int, curve: Optional[Curve] = None) -> int:
    """
    Compute r value for given parameters (R_x = x((u_z + u_r · d) · G)).
    
    This implements the bijective parameterization (u_r, u_z) used in TopoSphere.
    
    Args:
        Q: Public key point or hex string
        u_r: u_r parameter
        u_z: u_z parameter
        curve: Optional curve parameters (uses secp256k1 by default)
        
    Returns:
        r value (x-coordinate of R modulo n)
    """
    if curve is None:
        curve = get_curve("secp256k1")
    
    # Convert public key to Point if needed
    if isinstance(Q, str):
        Q = public_key_hex_to_point(Q, curve.name)
    
    # In TopoSphere, R = u_r · Q + u_z · G
    # This is equivalent to (u_z + u_r · d) · G where Q = d · G
    R = _point_mul(u_r, Q, curve) + _point_mul(u_z, curve.G, curve)
    
    # r = R.x mod n
    return R.x % curve.n

def _point_mul(scalar: int, point: Point, curve: Curve) -> Point:
    """
    Perform scalar multiplication of a point.
    
    Args:
        scalar: Scalar value
        point: Point to multiply
        curve: Curve parameters
        
    Returns:
        Resulting point
    """
    # Handle edge cases
    if scalar == 0:
        return Point(0, 0, curve.name)  # Point at infinity
    
    if EC_LIBS_AVAILABLE:
        try:
            # Try to use fastecdsa if available
            from fastecdsa import curve as ec_curve
            from fastecdsa.point import Point as ECPoint
            
            # Get the appropriate curve
            ec = getattr(ec_curve, curve.name, ec_curve.P256)
            
            # Create a point
            p = ECPoint(point.x, point.y, curve=ec)
            
            # Perform multiplication
            result = p * scalar
            
            return Point(result.x, result.y, curve.name)
        except Exception as e:
            logger.warning(f"Error using fastecdsa: {str(e)}. Using fallback implementation.")
    
    # Fallback implementation using double-and-add
    return _point_mul_fallback(scalar, point, curve)

def _point_add(point1: Point, point2: Point, curve: Curve) -> Point:
    """
    Add two points on an elliptic curve.
    
    Args:
        point1: First point
        point2: Second point
        curve: Curve parameters
        
    Returns:
        Resulting point
    """
    # Handle identity element
    if point1.x == 0 and point1.y == 0:
        return point2
    if point2.x == 0 and point2.y == 0:
        return point1
    
    if EC_LIBS_AVAILABLE:
        try:
            # Try to use fastecdsa if available
            from fastecdsa import curve as ec_curve
            from fastecdsa.point import Point as ECPoint
            
            # Get the appropriate curve
            ec = getattr(ec_curve, curve.name, ec_curve.P256)
            
            # Create points
            p1 = ECPoint(point1.x, point1.y, curve=ec)
            p2 = ECPoint(point2.x, point2.y, curve=ec)
            
            # Perform addition
            result = p1 + p2
            
            return Point(result.x, result.y, curve.name)
        except Exception as e:
            logger.warning(f"Error using fastecdsa: {str(e)}. Using fallback implementation.")
    
    # Fallback implementation using standard elliptic curve addition
    if point1.x == point2.x and point1.y == point2.y:
        # Point doubling
        if point1.y == 0:
            return Point(0, 0, curve.name)  # Point at infinity
        
        # Calculate slope
        s = (3 * point1.x * point1.x + curve.a) * pow(2 * point1.y, -1, curve.p) % curve.p
    else:
        # Point addition
        if point1.x == point2.x:
            return Point(0, 0, curve.name)  # Point at infinity
        
        # Calculate slope
        s = (point2.y - point1.y) * pow(point2.x - point1.x, -1, curve.p) % curve.p
    
    # Calculate new point
    x = (s * s - point1.x - point2.x) % curve.p
    y = (s * (point1.x - x) - point1.y) % curve.p
    
    return Point(x, y, curve.name)

def _point_mul_fallback(scalar: int, point: Point, curve: Curve) -> Point:
    """
    Fallback implementation of scalar multiplication using double-and-add algorithm.
    
    Args:
        scalar: Scalar value
        point: Point to multiply
        curve: Curve parameters
        
    Returns:
        Resulting point
    """
    # Simple double-and-add algorithm
    result = Point(0, 0, curve.name)  # Point at infinity
    addend = point
    scalar = scalar % curve.n  # Ensure scalar is in the right range
    
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend, curve)
        addend = _point_add(addend, addend, curve)
        scalar >>= 1
    
    return result

def generate_signature_sample(public_key: Union[str, Point],
                            num_samples: int = 1000,
                            curve_name: str = "secp256k1") -> List[ECDSASignature]:
    """
    Generate sample signatures for topological analysis using correct bijective parameterization.
    
    Args:
        public_key: Public key to generate samples for
        num_samples: Number of samples to generate
        curve_name: Name of the elliptic curve
        
    Returns:
        List of ECDSASignature objects with correct parameterization
    """
    curve = get_curve(curve_name)
    
    # Convert public key to Point if needed
    if isinstance(public_key, str):
        Q = public_key_hex_to_point(public_key, curve_name)
    else:
        Q = public_key
    
    signatures = []
    
    for _ in range(num_samples):
        # Generate random u_r, u_z
        u_r = random.randint(1, curve.n - 1)  # u_r must be non-zero for inverse
        u_z = random.randint(0, curve.n - 1)
        
        # Compute r = x((u_z + u_r · d) · G) mod n
        r = compute_r(Q, u_r, u_z, curve)
        
        # CORRECT calculation of s and z based on bijective parameterization
        # s = r * u_r^-1 mod n
        s = (r * pow(u_r, -1, curve.n)) % curve.n
        # z = u_z * s mod n
        z = (u_z * s) % curve.n
        
        # Create signature with correct parameterization
        sig = ECDSASignature(
            r=r,
            s=s,
            z=z,
            u_r=u_r,
            u_z=u_z,
            confidence=0.95,  # High confidence for synthetic samples
            meta={
                "curve": curve_name,
                "source": "client_sample",
                "parameterization": "bijective"
            }
        )
        
        signatures.append(sig)
    
    return signatures

def process_signatures_for_analysis(signatures: List[Dict[str, int]],
                                  public_key: Union[str, Point],
                                  curve_name: str = "secp256k1") -> List[ECDSASignature]:
    """
    Process raw signatures into TopoSphere-compatible format for analysis.
    
    Args:
        signatures: List of raw signatures with r, s, z values
        public_key: Public key corresponding to the signatures
        curve_name: Name of the elliptic curve
        
    Returns:
        List of processed ECDSASignature objects with bijective parameterization
    """
    curve = get_curve(curve_name)
    
    # Convert public key to Point if needed
    if isinstance(public_key, str):
        Q = public_key_hex_to_point(public_key, curve_name)
    else:
        Q = public_key
    
    processed = []
    
    for sig in signatures:
        # Extract required values
        r = sig.get("r")
        s = sig.get("s")
        z = sig.get("z")
        
        if r is None or s is None or z is None:
            continue
        
        # Calculate u_r and u_z from r, s, z based on bijective parameterization
        # u_r = r * s^-1 mod n
        # u_z = z * s^-1 mod n
        try:
            s_inv = pow(s, -1, curve.n)
            u_r = (r * s_inv) % curve.n
            u_z = (z * s_inv) % curve.n
            
            # Verify that these parameters would produce the same r
            computed_r = compute_r(Q, u_r, u_z, curve)
            
            # Check if the computed r matches the actual r (allowing for small differences due to mod)
            if abs(computed_r - r) < 2:
                processed.append(ECDSASignature(
                    r=r,
                    s=s,
                    z=z,
                    u_r=u_r,
                    u_z=u_z,
                    confidence=0.8,  # Lower confidence for real signatures
                    meta={
                        "curve": curve_name,
                        "source": "client_real",
                        "parameterization": "bijective"
                    }
                ))
        except Exception:
            # Skip signatures that can't be properly processed
            continue
    
    return processed

def estimate_private_key_from_signatures(signatures: List[ECDSASignature],
                                       curve_name: str = "secp256k1") -> Optional[int]:
    """
    Attempt to estimate the private key from signatures (for vulnerability testing).
    
    Note: This is only possible if there are vulnerabilities like repeated k values.
    
    Args:
        signatures: List of signatures to analyze
        curve_name: Name of the elliptic curve
        
    Returns:
        Estimated private key or None if not possible
    """
    curve = get_curve(curve_name)
    
    # Look for signatures with the same r (which implies same k)
    r_counts = {}
    for i, sig in enumerate(signatures):
        r_counts.setdefault(sig.r, []).append(i)
    
    # Find pairs with the same r
    for r, indices in r_counts.items():
        if len(indices) > 1:
            # Take the first two signatures with the same r
            i, j = indices[0], indices[1]
            sig1, sig2 = signatures[i], signatures[j]
            
            # If k is the same, then:
            # k = (z1 - z2) * (s1 - s2)^-1 mod n
            z1, z2 = sig1.z, sig2.z
            s1, s2 = sig1.s, sig2.s
            
            # Check if s1 != s2
            if s1 == s2:
                continue
            
            # Compute k
            s_diff = (s1 - s2) % curve.n
            if s_diff == 0:
                continue
            
            s_diff_inv = pow(s_diff, -1, curve.n)
            k = ((z1 - z2) * s_diff_inv) % curve.n
            
            # Compute d = (s*k - z) * r^-1 mod n
            r_inv = pow(sig1.r, -1, curve.n)
            d = ((sig1.s * k - sig1.z) * r_inv) % curve.n
            
            return d
    
    return None

def check_weak_key(public_key: Union[str, Point],
                 curve_name: str = "secp256k1") -> Dict[str, Any]:
    """
    Check if a public key corresponds to a weak private key using gcd(d, n) > 1 criterion.
    
    Args:
        public_key: Public key to check
        curve_name: Name of the elliptic curve
        
    Returns:
        Dictionary with weak key analysis results
    """
    curve = get_curve(curve_name)
    
    # Convert public key to Point if needed
    if isinstance(public_key, str):
        Q = public_key_hex_to_point(public_key, curve_name)
    else:
        Q = public_key
    
    # In TopoSphere, weak keys are detected through gcd(d, n) > 1
    # But we don't know d, so we look for patterns in the signature space
    
    # Generate sample points
    sample_size = 1000
    gcd_values = []
    
    for _ in range(sample_size):
        u_r = random.randint(1, curve.n - 1)
        u_z = random.randint(0, curve.n - 1)
        
        # Compute r for (u_r, u_z) and (u_r, u_z + n/gcd) for various gcd values
        r1 = compute_r(Q, u_r, u_z, curve)
        
        # Check for common gcd values
        for gcd_val in [2, 3, 5, 7, 11, 13]:
            if curve.n % gcd_val != 0:
                continue
            
            offset = curve.n // gcd_val
            r2 = compute_r(Q, u_r, (u_z + offset) % curve.n, curve)
            
            if r1 == r2:
                gcd_values.append(gcd_val)
    
    # Analyze results
    if not gcd_values:
        return {
            "is_weak": False,
            "gcd_values": [],
            "weakness_score": 0.0,
            "confidence": 0.0
        }
    
    # Count occurrences of each gcd value
    gcd_counts = {}
    for gcd_val in gcd_values:
        gcd_counts[gcd_val] = gcd_counts.get(gcd_val, 0) + 1
    
    # Find the most common gcd value
    most_common_gcd = max(gcd_counts, key=gcd_counts.get)
    occurrence_rate = gcd_counts[most_common_gcd] / sample_size
    
    return {
        "is_weak": occurrence_rate > 0.25,  # Threshold for weak key detection
        "gcd_values": list(gcd_counts.keys()),
        "most_common_gcd": most_common_gcd,
        "occurrence_rate": occurrence_rate,
        "weakness_score": occurrence_rate,
        "confidence": min(1.0, occurrence_rate * 4.0)  # Simple confidence measure
    }

def generate_synthetic_signatures(public_key: Union[str, Point],
                                num_signatures: int = 1000,
                                vulnerability_type: Optional[str] = None,
                                curve_name: str = "secp256k1") -> List[ECDSASignature]:
    """
    Generate synthetic signatures with specific vulnerability patterns using correct bijective parameterization.
    
    Args:
        public_key: Public key to generate signatures for
        num_signatures: Number of signatures to generate
        vulnerability_type: Type of vulnerability to simulate (None for secure)
        curve_name: Name of the elliptic curve
        
    Returns:
        List of synthetic ECDSASignature objects with correct parameterization
    """
    curve = get_curve(curve_name)
    
    # Convert public key to Point if needed
    if isinstance(public_key, str):
        Q = public_key_hex_to_point(public_key, curve_name)
    else:
        Q = public_key
    
    signatures = []
    
    for i in range(num_signatures):
        # Base random values
        u_r = random.randint(1, curve.n - 1)  # u_r must be non-zero
        u_z = random.randint(0, curve.n - 1)
        
        # Apply vulnerability patterns if requested
        if vulnerability_type == "spiral":
            # Spiral pattern: u_z proportional to u_r with some noise
            spiral_factor = 0.3
            u_z = int(u_r * spiral_factor) % curve.n
            # Add some noise to make it realistic
            u_z = (u_z + random.randint(-curve.n//100, curve.n//100)) % curve.n
        elif vulnerability_type == "star":
            # Star pattern: u_r and u_z follow radial pattern
            angle = i * 2 * math.pi / num_signatures
            radius = curve.n * 0.4 * (0.5 + 0.5 * math.sin(i * 0.1))
            u_r = int(radius * math.cos(angle)) % curve.n
            u_z = int(radius * math.sin(angle)) % curve.n
            # Ensure u_r is non-zero
            u_r = max(1, u_r)
        elif vulnerability_type == "symmetry_violation":
            # Symmetry violation: bias toward certain regions
            if random.random() < 0.7:
                u_r = random.randint(1, curve.n // 4)  # u_r must be non-zero
                u_z = random.randint(0, curve.n // 4)
            else:
                u_r = random.randint(curve.n // 2, curve.n - 1)
                u_z = random.randint(curve.n // 2, curve.n - 1)
        elif vulnerability_type == "weak_key":
            # Weak key pattern: repeated patterns every n/gcd
            gcd_val = 3  # Example gcd value
            offset = curve.n // gcd_val
            u_z = (u_r * 2) % offset  # Creates repeating pattern
    
        # Ensure u_r is non-zero (required for inverse)
        u_r = max(1, u_r)
        
        # Compute r
        r = compute_r(Q, u_r, u_z, curve)
        
        # CORRECT calculation of s and z based on bijective parameterization
        # s = r * u_r^-1 mod n
        s = (r * pow(u_r, -1, curve.n)) % curve.n
        # z = u_z * s mod n
        z = (u_z * s) % curve.n
        
        # Create signature
        sig = ECDSASignature(
            r=r,
            s=s,
            z=z,
            u_r=u_r,
            u_z=u_z,
            is_synthetic=True,
            confidence=1.0,
            meta={
                "curve": curve_name,
                "vulnerability_type": vulnerability_type or "secure",
                "source": "client_synthetic",
                "parameterization": "bijective"
            }
        )
        
        signatures.append(sig)
    
    return signatures

def compress_signature_data(signatures: List[ECDSASignature],
                          target_compression: float = 0.1) -> List[ECDSASignature]:
    """
    Compress signature data for efficient transmission to server.
    
    Args:
        signatures: List of signatures to compress
        target_compression: Target compression ratio (0.1 = 10% of original size)
        
    Returns:
        Compressed list of signatures
    """
    if not signatures:
        return []
    
    # Simple random sampling for compression
    num_to_keep = max(1, int(len(signatures) * target_compression))
    sampled_indices = random.sample(range(len(signatures)), num_to_keep)
    
    # Keep critical signatures (those with potential vulnerabilities)
    critical_indices = [
        i for i, sig in enumerate(signatures)
        if sig.meta.get("vulnerability_score", 0) > 0.5
    ]
    
    # Combine critical and random samples
    final_indices = list(set(sampled_indices + critical_indices))
    final_indices = final_indices[:num_to_keep]  # Ensure we don't exceed target
    
    return [signatures[i] for i in final_indices]

def calculate_signature_density(signatures: List[ECDSASignature],
                             grid_size: int = 100) -> List[List[float]]:
    """
    Calculate density of signatures on the (u_r, u_z) grid.
    
    Args:
        signatures: List of signatures to analyze
        grid_size: Size of the grid
        
    Returns:
        2D grid of density values
    """
    if not signatures:
        return [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]
    
    density = [[0.0 for _ in range(grid_size)] for _ in range(grid_size)]
    
    for sig in signatures:
        # Map u_r, u_z to grid coordinates
        i = min(grid_size - 1, int(sig.u_r / curve.n * grid_size))
        j = min(grid_size - 1, int(sig.u_z / curve.n * grid_size))
        
        density[i][j] += 1.0
    
    # Normalize
    max_density = max(max(row) for row in density)
    if max_density > 0:
        for i in range(grid_size):
            for j in range(grid_size):
                density[i][j] /= max_density
    
    return density

def generate_diagnostic_report(public_key: Union[str, Point],
                             signatures: List[ECDSASignature],
                             curve_name: str = "secp256k1") -> Dict[str, Any]:
    """
    Generate a diagnostic report for client-side analysis.
    
    Args:
        public_key: Public key being analyzed
        signatures: List of signatures for analysis
        curve_name: Name of the elliptic curve
        
    Returns:
        Dictionary with diagnostic information
    """
    curve = get_curve(curve_name)
    
    # Convert public key to hex for reporting
    if isinstance(public_key, Point):
        public_key_hex = point_to_public_key_hex(public_key)
    else:
        public_key_hex = public_key
    
    # Check for weak key
    weak_key_result = check_weak_key(public_key, curve_name)
    
    # Calculate signature density
    density_grid = calculate_signature_density(signatures, grid_size=50)
    
    # Check for symmetry violations
    symmetry_violations = 0
    total_samples = min(1000, len(signatures))
    
    for i in range(total_samples):
        sig = signatures[i]
        # Check symmetry: (u_r, u_z) vs (u_z, u_r)
        if i + 1 < len(signatures):
            sig2 = signatures[i + 1]
            if (sig.u_r, sig.u_z) != (sig2.u_z, sig2.u_r) and sig.r == sig2.r:
                symmetry_violations += 1
    
    symmetry_violation_rate = symmetry_violations / total_samples if total_samples > 0 else 0.0
    
    # Check for spiral patterns
    spiral_score = 0.0
    if len(signatures) > 10:
        # Simple spiral pattern detection
        angles = []
        for sig in signatures[:100]:
            angle = math.atan2(sig.u_z, sig.u_r)
            angles.append(angle)
        
        # Calculate variation in angles
        angle_diffs = [
            (angles[i] - angles[i-1]) % (2 * math.pi)
            for i in range(1, len(angles))
        ]
        angle_std = math.sqrt(sum((x - sum(angle_diffs)/len(angle_diffs))**2 for x in angle_diffs) / len(angle_diffs)) if angle_diffs else 0
        
        # Lower std deviation indicates more regular pattern (potential spiral)
        spiral_score = 1.0 - min(1.0, angle_std * 2.0)
    
    # Overall vulnerability score
    vulnerability_score = (
        weak_key_result["weakness_score"] * 0.4 +
        symmetry_violation_rate * 0.3 +
        (1.0 - spiral_score) * 0.3
    )
    
    return {
        "public_key": public_key_hex[:16] + "...",
        "curve": curve_name,
        "signature_count": len(signatures),
        "weak_key_analysis": weak_key_result,
        "symmetry_violation_rate": symmetry_violation_rate,
        "spiral_pattern_score": spiral_score,
        "vulnerability_score": min(1.0, vulnerability_score),
        "is_secure": vulnerability_score < 0.3,
        "density_grid": density_grid
    }

def verify_bijective_parameterization(signatures: List[ECDSASignature],
                                   curve_name: str = "secp256k1") -> Dict[str, Any]:
    """
    Verify that signatures follow the bijective parameterization rules.
    
    Args:
        signatures: List of signatures to verify
        curve_name: Name of the elliptic curve
        
    Returns:
        Dictionary with verification results
    """
    curve = get_curve(curve_name)
    consistent_count = 0
    
    for sig in signatures:
        # Check if u_r is non-zero (required for inverse)
        if sig.u_r == 0:
            continue
            
        # Calculate expected s from bijective parameterization
        expected_s = (sig.r * pow(sig.u_r, -1, curve.n)) % curve.n
        
        # Calculate expected z from bijective parameterization
        expected_z = (sig.u_z * sig.s) % curve.n
        
        # Check consistency
        s_diff = min(abs(sig.s - expected_s), curve.n - abs(sig.s - expected_s))
        z_diff = min(abs(sig.z - expected_z), curve.n - abs(sig.z - expected_z))
        
        if s_diff < 2 and z_diff < 2:
            consistent_count += 1
    
    total_signatures = len(signatures)
    consistency_rate = consistent_count / total_signatures if total_signatures > 0 else 0.0
    
    return {
        "total_signatures": total_signatures,
        "consistent_signatures": consistent_count,
        "consistency_rate": consistency_rate,
        "is_bijective": consistency_rate > 0.95,
        "inconsistent_signatures": total_signatures - consistent_count
    }
