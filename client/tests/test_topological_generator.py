"""
TopoSphere Client Topological Generator Tests

This module contains comprehensive tests for the Topological Generator component of the
TopoSphere client system. The tests verify the correct implementation of the bijective
parameterization and the generation of secure nonce values for ECDSA signing.

The tests are based on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)."

The tests verify the following key properties:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- Bijective parameterization (u_r, u_z) enables secure nonce generation
- Proper calculation of r = x((u_z + u_r · d) · G) mod n
- Correct derivation of s and z from u_r and u_z
- Detection of weak key patterns through gcd(d, n) > 1

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." These tests ensure that the topological generator
implements this principle correctly.

Version: 1.0.0
"""

import pytest
import math
import random
import numpy as np
from typing import Dict, List, Tuple, Optional
import time

# Import from our system
from client.core.topological_generator import TopologicalGenerator
from client.utils.crypto_utils import (
    Point,
    ECDSASignature,
    get_curve,
    validate_public_key,
    point_to_public_key_hex,
    public_key_hex_to_point,
    compute_r,
    compute_s,
    compute_z
)
from client.utils.differential_privacy import DifferentialPrivacy

# Test configuration
TEST_CURVE = "secp256k1"
TEST_NUM_SAMPLES = 100
SECP256K1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

@pytest.fixture
def topological_generator():
    """Fixture to create a topological generator for testing."""
    return TopologicalGenerator(curve_name=TEST_CURVE)

@pytest.fixture
def sample_public_key():
    """Fixture to create a sample public key for testing."""
    curve = get_curve(TEST_CURVE)
    # Create a point on the curve (simplified for testing)
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    return point_to_public_key_hex(Point(x, y, TEST_CURVE))

@pytest.fixture
def weak_public_key():
    """Fixture to create a weak public key for testing (gcd(d, n) > 1)."""
    curve = get_curve(TEST_CURVE)
    # Create a point with weak private key (d = n/3)
    weak_d = SECP256K1_N // 3
    Q = curve.G * weak_d
    return point_to_public_key_hex(Point(Q.x, Q.y, TEST_CURVE))

def test_generator_initialization(topological_generator):
    """Test that the topological generator initializes correctly."""
    assert topological_generator is not None
    assert topological_generator.curve_name == TEST_CURVE
    assert topological_generator.curve is not None
    assert topological_generator.n == SECP256K1_N
    assert topological_generator.differential_privacy is not None
    assert topological_generator.nonce_manager is not None
    assert topological_generator.security_recommender is not None

def test_secure_u_r_generation(topological_generator):
    """Test that secure u_r values are generated with gcd(u_r, n) = 1."""
    for _ in range(TEST_NUM_SAMPLES):
        u_r = topological_generator._generate_secure_u_r()
        assert 1 <= u_r < topological_generator.n
        assert math.gcd(u_r, topological_generator.n) == 1

def test_signature_generation(topological_generator, sample_public_key):
    """Test that signatures are correctly generated using the bijective parameterization."""
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    assert len(signatures) == TEST_NUM_SAMPLES
    for sig in signatures:
        # Verify bijective parameterization: s = r * u_r^-1 mod n
        u_r_inv = pow(sig.u_r, -1, topological_generator.n)
        expected_s = (sig.r * u_r_inv) % topological_generator.n
        assert abs(sig.s - expected_s) < 2  # Allow for small rounding differences
        
        # Verify bijective parameterization: z = u_z * s mod n
        expected_z = (sig.u_z * sig.s) % topological_generator.n
        assert abs(sig.z - expected_z) < 2
        
        # Verify R = u_r * Q + u_z * G
        computed_r = compute_r(sample_public_key, sig.u_r, sig.u_z, TEST_CURVE)
        assert abs(sig.r - computed_r) < 2

def test_spiral_pattern_generation(topological_generator, sample_public_key):
    """Test that spiral pattern signatures are correctly generated."""
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral"
    )
    
    # Check for spiral pattern characteristics
    angles = []
    for sig in signatures:
        angle = math.atan2(sig.u_z, sig.u_r)
        angles.append(angle)
    
    # Calculate variation in angles
    angle_diffs = [
        (angles[i] - angles[i-1]) % (2 * math.pi)
        for i in range(1, len(angles))
    ]
    angle_std = np.std(angle_diffs) if angle_diffs else 0
    
    # Spiral patterns should have low angle variation
    assert angle_std < 0.5

def test_star_pattern_generation(topological_generator, sample_public_key):
    """Test that star pattern signatures are correctly generated."""
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="star"
    )
    
    # Check for star pattern characteristics
    # Star patterns should have points concentrated at specific angles
    angles = [math.atan2(sig.u_z, sig.u_r) for sig in signatures]
    
    # Calculate circular variance
    mean_angle = np.angle(np.mean(np.exp(1j * np.array(angles))))
    deviations = [(angle - mean_angle + np.pi) % (2 * np.pi) - np.pi for angle in angles]
    circular_variance = 1 - np.abs(np.mean(np.exp(1j * np.array(deviations))))
    
    # Star patterns should have high circular variance
    assert circular_variance > 0.5

def test_weak_key_detection(topological_generator, weak_public_key):
    """Test that weak key patterns are correctly detected."""
    # Generate signatures with a weak key
    signatures = topological_generator.generate_signatures(
        weak_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Check for weak key characteristics
    gcd_values = []
    for i in range(0, len(signatures) - 1, 2):
        sig1, sig2 = signatures[i], signatures[i+1]
        if sig1.r == sig2.r and sig1.u_r != sig2.u_r:
            # For weak keys, (u_z2 - u_z1) / (u_r1 - u_r2) should be a rational multiple of n/gcd
            try:
                ratio = (sig2.u_z - sig1.u_z) / (sig1.u_r - sig2.u_r)
                # Check if ratio is close to a rational multiple of n
                for gcd_val in [2, 3, 5, 7, 11, 13]:
                    if topological_generator.n % gcd_val == 0:
                        multiple = ratio / (topological_generator.n / gcd_val)
                        if abs(multiple - round(multiple)) < 0.1:
                            gcd_values.append(gcd_val)
            except:
                pass
    
    # Should detect the weak key pattern (gcd = 3 in our weak key)
    assert 3 in gcd_values

def test_symmetry_violation_detection(topological_generator, sample_public_key):
    """Test that symmetry violation patterns are correctly detected."""
    # Generate signatures with symmetry violation
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="symmetry_violation"
    )
    
    # Check for symmetry violations
    symmetry_violations = 0
    for i in range(0, len(signatures) - 1, 2):
        sig1, sig2 = signatures[i], signatures[i+1]
        # For symmetric implementations, (u_r, u_z) should have similar properties to (u_z, u_r)
        if (sig1.u_r, sig1.u_z) != (sig2.u_z, sig2.u_r) and sig1.r == sig2.r:
            symmetry_violations += 1
    
    # Symmetry violation patterns should have high symmetry violations
    assert symmetry_violations > TEST_NUM_SAMPLES * 0.5

def test_differential_privacy_integration(topological_generator, sample_public_key):
    """Test that differential privacy is correctly integrated."""
    # Generate signatures with differential privacy
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        apply_privacy=True
    )
    
    # Verify that privacy parameters are set
    assert topological_generator.differential_privacy is not None
    
    # Verify that noise has been added (comparing to non-private generation)
    non_private_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        apply_privacy=False
    )
    
    differences = 0
    for sig_priv, sig_non_priv in zip(signatures, non_private_signatures):
        if (sig_priv.u_r != sig_non_priv.u_r or 
            sig_priv.u_z != sig_non_priv.u_z or
            sig_priv.r != sig_non_priv.r):
            differences += 1
    
    # Should have some differences due to noise
    assert differences > 0

def test_torus_structure(topological_generator, sample_public_key):
    """Test that the generated signature space forms a torus structure."""
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Extract u_r, u_z values
    u_r_values = [sig.u_r for sig in signatures]
    u_z_values = [sig.u_z for sig in signatures]
    
    # Check for torus structure characteristics
    # For a torus, the space should be uniform when mapped to a circle
    angles_r = [(2 * math.pi * u_r) / topological_generator.n for u_r in u_r_values]
    angles_z = [(2 * math.pi * u_z) / topological_generator.n for u_z in u_z_values]
    
    # Calculate uniformity of the angles
    def calculate_uniformity(angles):
        sorted_angles = sorted(angles)
        gaps = [
            (sorted_angles[i] - sorted_angles[i-1]) % (2 * math.pi)
            for i in range(1, len(sorted_angles))
        ]
        gaps.append((sorted_angles[0] + 2 * math.pi - sorted_angles[-1]) % (2 * math.pi))
        mean_gap = 2 * math.pi / len(angles)
        variance = sum((gap - mean_gap) ** 2 for gap in gaps) / len(gaps)
        return 1 - (variance / (mean_gap ** 2))
    
    uniformity_r = calculate_uniformity(angles_r)
    uniformity_z = calculate_uniformity(angles_z)
    
    # Torus structure should have high uniformity
    assert uniformity_r > 0.7
    assert uniformity_z > 0.7

def test_vulnerability_prediction(topological_generator, sample_public_key):
    """Test that vulnerability predictions are accurate."""
    # Generate secure signatures
    secure_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Generate vulnerable signatures (spiral pattern)
    spiral_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral"
    )
    
    # Get vulnerability scores
    secure_score = topological_generator.predict_vulnerability(secure_signatures)
    spiral_score = topological_generator.predict_vulnerability(spiral_signatures)
    
    # Spiral patterns should have higher vulnerability scores
    assert spiral_score > secure_score
    assert secure_score < 0.3  # Secure implementations should have low vulnerability score
    assert spiral_score > 0.5  # Vulnerable implementations should have higher vulnerability score

def test_nonce_regeneration(topological_generator, sample_public_key):
    """Test that nonce regeneration works correctly for secure signing."""
    # Generate initial nonce
    nonce1 = topological_generator.generate_nonce(sample_public_key)
    
    # Regenerate nonce with same parameters
    nonce2 = topological_generator.generate_nonce(sample_public_key)
    
    # Nonces should be different
    assert nonce1 != nonce2
    
    # Verify that both nonces are secure (gcd(nonce, n) = 1)
    assert math.gcd(nonce1, topological_generator.n) == 1
    assert math.gcd(nonce2, topological_generator.n) == 1

def test_public_key_validation(topological_generator, sample_public_key):
    """Test that public key validation works correctly."""
    # Valid public key should pass validation
    assert topological_generator.validate_public_key(sample_public_key)
    
    # Invalid public key should fail validation
    invalid_key = "02" + "0" * 64  # Invalid point (not on curve)
    assert not topological_generator.validate_public_key(invalid_key)
    
    # Invalid format should fail validation
    invalid_format = "12345"  # Not a valid public key format
    assert not topological_generator.validate_public_key(invalid_format)
    
    # Compressed format with invalid prefix
    invalid_prefix = "04" + "0" * 64  # Should be 02 or 03 for compressed format
    assert not topological_generator.validate_public_key(invalid_prefix)

def test_edge_cases(topological_generator, sample_public_key):
    """Test edge cases for the topological generator."""
    # Test with minimum signature count
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=1
    )
    assert len(signatures) == 1
    
    # Test with maximum signature count
    max_signatures = 10000
    start_time = time.time()
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=max_signatures
    )
    generation_time = time.time() - start_time
    assert len(signatures) == max_signatures
    assert generation_time < 10.0  # Should generate 10k signatures in under 10 seconds
    
    # Test with invalid vulnerability type
    with pytest.raises(ValueError):
        topological_generator.generate_signatures(
            sample_public_key,
            num_signatures=10,
            vulnerability_type="invalid_type"
        )
    
    # Test with zero signatures
    with pytest.raises(ValueError):
        topological_generator.generate_signatures(
            sample_public_key,
            num_signatures=0
        )

def test_bijective_parameterization_consistency(topological_generator, sample_public_key):
    """Test that the bijective parameterization is consistent across different operations."""
    # Generate signatures
    signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # For each signature, verify that converting to (u_r, u_z) and back gives the same signature
    for sig in signatures:
        # Convert to (u_r, u_z)
        u_r = (sig.r * pow(sig.s, -1, topological_generator.n)) % topological_generator.n
        u_z = (sig.z * pow(sig.s, -1, topological_generator.n)) % topological_generator.n
        
        # Convert back to (r, s, z)
        r = compute_r(sample_public_key, u_r, u_z, TEST_CURVE)
        s = (r * pow(u_r, -1, topological_generator.n)) % topological_generator.n
        z = (u_z * s) % topological_generator.n
        
        # Verify consistency
        assert abs(sig.r - r) < 2
        assert abs(sig.s - s) < 2
        assert abs(sig.z - z) < 2

def test_tcon_compliance(topological_generator, sample_public_key):
    """Test that TCON (Topological Conformance) compliance is correctly verified."""
    # Generate secure signatures
    secure_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Generate vulnerable signatures (spiral pattern)
    spiral_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral"
    )
    
    # Check TCON compliance
    secure_compliance = topological_generator.verify_tcon_compliance(secure_signatures)
    spiral_compliance = topological_generator.verify_tcon_compliance(spiral_signatures)
    
    # Secure implementations should be TCON compliant
    assert secure_compliance["is_compliant"]
    assert secure_compliance["vulnerability_score"] < 0.2
    
    # Vulnerable implementations should not be TCON compliant
    assert not spiral_compliance["is_compliant"]
    assert spiral_compliance["vulnerability_score"] > 0.5

def test_quantum_security_metrics(topological_generator, sample_public_key, weak_public_key):
    """Test that quantum-inspired security metrics are correctly calculated."""
    # Generate secure signatures
    secure_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Generate weak key signatures
    weak_signatures = topological_generator.generate_signatures(
        weak_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Get quantum security metrics
    secure_metrics = topological_generator.get_quantum_security_metrics(secure_signatures)
    weak_metrics = topological_generator.get_quantum_security_metrics(weak_signatures)
    
    # Secure implementations should have good quantum metrics
    assert secure_metrics["entanglement_entropy"] > math.log2(topological_generator.n) * 0.7
    assert secure_metrics["quantum_risk_score"] < 0.3
    
    # Weak key implementations should have poor quantum metrics
    assert weak_metrics["entanglement_entropy"] < math.log2(topological_generator.n) * 0.3
    assert weak_metrics["quantum_risk_score"] > 0.7

def test_vulnerability_remediation(topological_generator, sample_public_key):
    """Test that vulnerability remediation recommendations are appropriate."""
    # Generate vulnerable signatures (spiral pattern)
    spiral_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral"
    )
    
    # Get remediation recommendations
    recommendations = topological_generator.get_remediation_recommendations(spiral_signatures)
    
    # Check for appropriate recommendations
    assert any("spiral" in rec.lower() for rec in recommendations)
    assert any("random number generator" in rec.lower() for rec in recommendations)
    assert any("linear congruential" in rec.lower() for rec in recommendations)

def test_nonce_manager_integration(topological_generator, sample_public_key):
    """Test that the nonce manager is correctly integrated."""
    # Generate nonces
    nonce1 = topological_generator.generate_nonce(sample_public_key)
    nonce2 = topological_generator.generate_nonce(sample_public_key)
    
    # Verify nonce uniqueness
    assert nonce1 != nonce2
    
    # Verify nonce history
    nonce_history = topological_generator.nonce_manager.get_nonce_history()
    assert len(nonce_history) >= 2
    assert nonce1 in nonce_history
    assert nonce2 in nonce_history
    
    # Verify nonce quality analysis
    quality_report = topological_generator.nonce_manager.analyze_nonce_quality()
    assert "quality_score" in quality_report
    assert "pattern_type" in quality_report
    assert "recommendation" in quality_report

def test_security_recommender(topological_generator, sample_public_key):
    """Test that the security recommender provides appropriate recommendations."""
    # Generate secure signatures
    secure_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES
    )
    
    # Generate vulnerable signatures (spiral pattern)
    spiral_signatures = topological_generator.generate_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral"
    )
    
    # Get recommendations for secure implementation
    secure_recommendations = topological_generator.security_recommender.get_recommendations(
        secure_signatures,
        is_secure=True
    )
    assert any("no action required" in rec.lower() for rec in secure_recommendations)
    
    # Get recommendations for vulnerable implementation
    vulnerable_recommendations = topological_generator.security_recommender.get_recommendations(
        spiral_signatures,
        is_secure=False
    )
    assert any("spiral pattern" in rec.lower() for rec in vulnerable_recommendations)
    assert any("replace" in rec.lower() for rec in vulnerable_recommendations)
