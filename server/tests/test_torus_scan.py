"""
TopoSphere Server TorusScan Tests

This module contains comprehensive tests for the TorusScan component of the
TopoSphere server system. The tests verify the correct implementation of the
adaptive topological scanning algorithm, amplitude amplification, and vulnerability
detection based on topological analysis.

The tests are based on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "Quantum-inspired amplitude amplification enables efficient identification of vulnerability patterns."

The tests verify the following key properties:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- TorusScan correctly identifies vulnerabilities through amplitude amplification
- Diagonal symmetry verification accurately detects implementation flaws
- Spiral pattern analysis identifies structured vulnerabilities
- TCON verification ensures topological conformance
- Quadtree implementation enables efficient resource allocation

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." These tests ensure that the TorusScan
implementation adheres to this principle by providing mathematically rigorous vulnerability detection.

Version: 1.0.0
"""

import pytest
import math
import random
import numpy as np
import time
from typing import Dict, List, Tuple, Optional, Any
from unittest.mock import MagicMock, patch

# Import from our system
from server.modules.torus_scan import (
    TorusScan,
    SpiralAnalysis,
    SymmetryChecker,
    CollisionDetector,
    AmplitudeAmplifier,
    TopologicalAnomalyMapper
)
from server.config.server_config import ServerConfig
from server.core.dynamic_compute_router import DynamicComputeRouter
from server.modules.tcon_analysis import ConformanceChecker
from server.modules.quantum_scanning import EntanglementEntropyAnalyzer
from shared.models.topological_models import (
    BettiNumbers,
    TopologicalAnalysisResult,
    PersistentCycle,
    TopologicalPattern
)
from shared.models.cryptographic_models import ECDSASignature
from shared.utils.elliptic_curve import (
    get_curve,
    compute_r,
    public_key_hex_to_point,
    point_to_public_key_hex
)
from client.utils.crypto_utils import (
    generate_signature_sample,
    generate_synthetic_signatures,
    compute_s,
    compute_z
)

# Test configuration
TEST_CURVE = "secp256k1"
TEST_NUM_SAMPLES = 100
SECP256K1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
MIN_SECURE_BETTI = {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0}
AMPLIFICATION_FACTOR = 1.5

@pytest.fixture
def server_config():
    """Fixture to create a server configuration for testing."""
    return ServerConfig(
        curve=TEST_CURVE,
        log_level="DEBUG",
        log_to_console=False,
        max_analysis_time=300.0,
        max_memory_usage=0.8
    )

@pytest.fixture
def dynamic_compute_router():
    """Fixture to create a dynamic compute router for testing."""
    return DynamicComputeRouter()

@pytest.fixture
def torus_scan(server_config, dynamic_compute_router):
    """Fixture to create a TorusScan instance for testing."""
    return TorusScan(
        config=server_config,
        compute_router=dynamic_compute_router
    )

@pytest.fixture
def sample_public_key():
    """Fixture to create a sample public key for testing."""
    curve = get_curve(TEST_CURVE)
    # Create a point on the curve
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    return point_to_public_key_hex(Point(x, y, TEST_CURVE))

@pytest.fixture
def secure_signatures(sample_public_key):
    """Fixture to create secure signatures for testing."""
    return generate_signature_sample(
        sample_public_key,
        num_samples=TEST_NUM_SAMPLES,
        curve_name=TEST_CURVE
    )

@pytest.fixture
def spiral_signatures(sample_public_key):
    """Fixture to create signatures with spiral pattern vulnerability."""
    return generate_synthetic_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral",
        curve_name=TEST_CURVE
    )

@pytest.fixture
def star_signatures(sample_public_key):
    """Fixture to create signatures with star pattern vulnerability."""
    return generate_synthetic_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="star",
        curve_name=TEST_CURVE
    )

@pytest.fixture
def symmetry_violation_signatures(sample_public_key):
    """Fixture to create signatures with symmetry violation vulnerability."""
    return generate_synthetic_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="symmetry_violation",
        curve_name=TEST_CURVE
    )

@pytest.fixture
def weak_key_signatures():
    """Fixture to create signatures with a weak key (gcd(d, n) > 1)."""
    # Create a weak key (d = n/3)
    weak_d = SECP256K1_N // 3
    curve = get_curve(TEST_CURVE)
    Q = curve.G * weak_d
    weak_public_key = point_to_public_key_hex(Point(Q.x, Q.y, TEST_CURVE))
    
    # Generate signatures
    return generate_signature_sample(
        weak_public_key,
        num_samples=TEST_NUM_SAMPLES,
        curve_name=TEST_CURVE
    )

def test_torus_scan_initialization(torus_scan, server_config):
    """Test that TorusScan initializes correctly."""
    assert torus_scan is not None
    assert torus_scan.config == server_config
    assert torus_scan.compute_router is not None
    assert torus_scan.spiral_analysis is not None
    assert torus_scan.symmetry_checker is not None
    assert torus_scan.collision_detector is not None
    assert torus_scan.amplitude_amplifier is not None
    assert torus_scan.anomaly_mapper is not None
    assert torus_scan.conformance_checker is not None
    assert torus_scan.entanglement_analyzer is not None
    assert torus_scan.logger is not None
    assert torus_scan.last_analysis == {}
    assert torus_scan.analysis_cache == {}
    assert torus_scan.analysis_history == []
    assert torus_scan.grid_size > 0
    assert torus_scan.amplification_factor == AMPLIFICATION_FACTOR

def test_secure_signature_analysis(torus_scan, secure_signatures):
    """Test that secure signatures are correctly analyzed as secure."""
    scan_result = torus_scan.scan(secure_signatures)
    
    # Verify scan results
    assert scan_result is not None
    assert scan_result.vulnerability_score < 0.2
    assert scan_result.is_secure is True
    assert scan_result.security_level == "secure"
    assert scan_result.amplitude_profile is not None
    assert scan_result.amplitude_profile["max_amplitude"] < 0.3
    assert scan_result.symmetry_violation_rate < 0.05
    assert scan_result.spiral_score > 0.7
    assert scan_result.star_score < 0.3
    assert scan_result.critical_regions == []
    assert scan_result.topological_integrity > 0.8
    assert scan_result.entanglement_metrics is not None
    assert scan_result.entanglement_metrics.entanglement_score < 0.3
    
    # Verify Betti numbers match expected torus structure
    assert abs(scan_result.betti_numbers.beta_0 - MIN_SECURE_BETTI["beta_0"]) < 0.3
    assert abs(scan_result.betti_numbers.beta_1 - MIN_SECURE_BETTI["beta_1"]) < 0.5
    assert abs(scan_result.betti_numbers.beta_2 - MIN_SECURE_BETTI["beta_2"]) < 0.3

def test_spiral_pattern_detection(torus_scan, spiral_signatures):
    """Test that spiral pattern vulnerabilities are correctly identified."""
    scan_result = torus_scan.scan(spiral_signatures)
    
    # Verify spiral pattern detection
    assert scan_result.vulnerability_score > 0.5
    assert scan_result.is_secure is False
    assert scan_result.security_level == "vulnerable"
    assert scan_result.spiral_score < 0.5
    assert scan_result.symmetry_violation_rate > 0.05
    assert scan_result.amplitude_profile["max_amplitude"] > 0.6
    assert len(scan_result.critical_regions) > 0
    
    # Verify critical regions have spiral characteristics
    for region in scan_result.critical_regions:
        assert region["type"] in ["spiral", "high_density"]
        assert region["amplification"] > 0.5
        assert "u_r_range" in region
        assert "u_z_range" in region
        u_r_min, u_r_max = region["u_r_range"]
        u_z_min, u_z_max = region["u_z_range"]
        assert u_r_max > u_r_min
        assert u_z_max > u_z_min

def test_star_pattern_detection(torus_scan, star_signatures):
    """Test that star pattern vulnerabilities are correctly identified."""
    scan_result = torus_scan.scan(star_signatures)
    
    # Verify star pattern detection
    assert scan_result.vulnerability_score > 0.5
    assert scan_result.is_secure is False
    assert scan_result.security_level == "vulnerable"
    assert scan_result.star_score > 0.6
    assert scan_result.spiral_score > 0.6  # Star patterns may still have some spiral structure
    assert scan_result.amplitude_profile["max_amplitude"] > 0.6
    assert len(scan_result.critical_regions) > 0
    
    # Verify critical regions have star characteristics
    for region in scan_result.critical_regions:
        assert region["type"] in ["star", "high_density"]
        assert region["amplification"] > 0.5
        assert "u_r_range" in region
        assert "u_z_range" in region

def test_symmetry_violation_detection(torus_scan, symmetry_violation_signatures):
    """Test that symmetry violation vulnerabilities are correctly identified."""
    scan_result = torus_scan.scan(symmetry_violation_signatures)
    
    # Verify symmetry violation detection
    assert scan_result.vulnerability_score > 0.5
    assert scan_result.is_secure is False
    assert scan_result.security_level == "vulnerable"
    assert scan_result.symmetry_violation_rate > 0.1
    assert scan_result.amplitude_profile["max_amplitude"] > 0.5
    assert len(scan_result.critical_regions) > 0
    
    # Verify critical regions have symmetry violation characteristics
    for region in scan_result.critical_regions:
        assert region["type"] in ["symmetry_violation", "high_density"]
        assert region["amplification"] > 0.5

def test_weak_key_detection(torus_scan, weak_key_signatures):
    """Test that weak key vulnerabilities are correctly identified."""
    scan_result = torus_scan.scan(weak_key_signatures)
    
    # Verify weak key detection
    assert scan_result.vulnerability_score > 0.7
    assert scan_result.is_secure is False
    assert scan_result.security_level == "critical"
    assert scan_result.entanglement_metrics is not None
    assert scan_result.entanglement_metrics.gcd_value > 1
    assert scan_result.entanglement_metrics.entanglement_entropy > 0.0
    assert scan_result.entanglement_metrics.vulnerability_score > 0.7
    assert scan_result.weak_key_gcd == scan_result.entanglement_metrics.gcd_value

def test_diagonal_symmetry_check(torus_scan, secure_signatures, spiral_signatures):
    """Test that diagonal symmetry check correctly identifies vulnerabilities."""
    # Secure signatures should have low symmetry violation rate
    secure_symmetry = torus_scan.symmetry_checker.check_symmetry(secure_signatures)
    assert secure_symmetry["violation_rate"] < 0.05
    assert secure_symmetry["is_symmetric"] is True
    
    # Vulnerable signatures should have high symmetry violation rate
    vulnerable_symmetry = torus_scan.symmetry_checker.check_symmetry(spiral_signatures)
    assert vulnerable_symmetry["violation_rate"] > 0.1
    assert vulnerable_symmetry["is_symmetric"] is False
    
    # Verify symmetry violation rate calculation
    assert secure_symmetry["violation_rate"] <= vulnerable_symmetry["violation_rate"]

def test_spiral_analysis(torus_scan, secure_signatures, spiral_signatures):
    """Test that spiral analysis correctly identifies patterns."""
    # Secure signatures should have high spiral score (low spiral pattern)
    secure_spiral = torus_scan.spiral_analysis.analyze_spiral_pattern(secure_signatures)
    assert secure_spiral["spiral_score"] > 0.7
    assert secure_spiral["has_spiral_pattern"] is False
    
    # Vulnerable signatures should have low spiral score (high spiral pattern)
    vulnerable_spiral = torus_scan.spiral_analysis.analyze_spiral_pattern(spiral_signatures)
    assert vulnerable_spiral["spiral_score"] < 0.5
    assert vulnerable_spiral["has_spiral_pattern"] is True
    
    # Verify spiral score calculation
    assert secure_spiral["spiral_score"] > vulnerable_spiral["spiral_score"]

def test_amplitude_amplification(torus_scan, secure_signatures, spiral_signatures):
    """Test that amplitude amplification correctly identifies critical regions."""
    # Secure signatures should have uniform amplitude
    secure_amplitude = torus_scan.amplitude_amplifier.amplify_amplitude(secure_signatures)
    assert max(secure_amplitude.values()) < 0.3
    assert min(secure_amplitude.values()) > 0.0
    assert np.std(list(secure_amplitude.values())) < 0.1
    
    # Vulnerable signatures should have amplified regions
    vulnerable_amplitude = torus_scan.amplitude_amplifier.amplify_amplitude(spiral_signatures)
    assert max(vulnerable_amplitude.values()) > 0.6
    assert np.std(list(vulnerable_amplitude.values())) > 0.2
    
    # Verify amplification factor
    assert max(vulnerable_amplitude.values()) > max(secure_amplitude.values()) * AMPLIFICATION_FACTOR

def test_tcon_compliance(torus_scan, secure_signatures, spiral_signatures):
    """Test that TCON compliance is correctly verified."""
    # Secure signatures should be TCON compliant
    secure_compliance = torus_scan.conformance_checker.check_conformance(secure_signatures)
    assert secure_compliance["is_compliant"] is True
    assert secure_compliance["vulnerability_score"] < 0.2
    assert secure_compliance["betti_deviation"] < 0.5
    
    # Vulnerable signatures should not be TCON compliant
    vulnerable_compliance = torus_scan.conformance_checker.check_conformance(spiral_signatures)
    assert vulnerable_compliance["is_compliant"] is False
    assert vulnerable_compliance["vulnerability_score"] > 0.5
    assert vulnerable_compliance["betti_deviation"] > 0.5

def test_quadtree_integration(torus_scan, secure_signatures):
    """Test that quadtree implementation works correctly."""
    # Build quadtree
    quadtree = torus_scan.anomaly_mapper.build_quadtree(secure_signatures)
    
    # Verify quadtree structure
    assert quadtree is not None
    assert quadtree.bounds == (0, SECP256K1_N, 0, SECP256K1_N)
    assert len(quadtree.children) == 4 or len(quadtree.children) == 0
    
    # Verify quadtree traversal
    nodes = []
    torus_scan.anomaly_mapper._traverse_quadtree(quadtree, nodes.append)
    assert len(nodes) > 0
    for node in nodes:
        assert node.bounds[0] <= node.bounds[1]
        assert node.bounds[2] <= node.bounds[3]
        assert node.density >= 0.0
    
    # Verify critical regions detection
    critical_regions = torus_scan.anomaly_mapper.get_critical_regions(secure_signatures)
    assert isinstance(critical_regions, list)
    for region in critical_regions:
        assert "u_r_range" in region
        assert "u_z_range" in region
        assert "density" in region
        assert "type" in region

def test_collision_detection(torus_scan, secure_signatures, spiral_signatures):
    """Test that collision detection works correctly."""
    # Secure signatures should have low collision rate
    secure_collisions = torus_scan.collision_detector.detect_collisions(secure_signatures)
    assert secure_collisions["collision_rate"] < 0.05
    assert secure_collisions["is_vulnerable"] is False
    
    # Vulnerable signatures should have high collision rate
    vulnerable_collisions = torus_scan.collision_detector.detect_collisions(spiral_signatures)
    assert vulnerable_collisions["collision_rate"] > 0.1
    assert vulnerable_collisions["is_vulnerable"] is True
    
    # Verify collision rate calculation
    assert secure_collisions["collision_rate"] <= vulnerable_collisions["collision_rate"]

def test_entanglement_entropy_analysis(torus_scan, weak_key_signatures):
    """Test that entanglement entropy analysis detects weak keys."""
    # Analyze weak key signatures
    analysis = torus_scan.entanglement_analyzer.analyze(weak_key_signatures[0].public_key)
    
    # Verify weak key detection
    assert analysis.entanglement_metrics.gcd_value > 1
    assert analysis.entanglement_metrics.entanglement_entropy > 0.0
    assert analysis.quantum_vulnerability_score > 0.7
    assert analysis.security_level == "critical"

def test_bijective_parameterization(torus_scan, secure_signatures):
    """Test that the bijective parameterization is consistent."""
    curve = get_curve(TEST_CURVE)
    
    for sig in secure_signatures:
        # Verify bijective parameterization: s = r * u_r^-1 mod n
        u_r_inv = pow(sig.u_r, -1, curve.n)
        expected_s = (sig.r * u_r_inv) % curve.n
        assert abs(sig.s - expected_s) < 2
        
        # Verify bijective parameterization: z = u_z * s mod n
        expected_z = (sig.u_z * sig.s) % curve.n
        assert abs(sig.z - expected_z) < 2
        
        # Verify R = u_r * Q + u_z * G
        computed_r = compute_r(sig.public_key, sig.u_r, sig.u_z, TEST_CURVE)
        assert abs(sig.r - computed_r) < 2

def test_torus_structure(torus_scan, secure_signatures):
    """Test that secure signatures form a torus structure."""
    scan_result = torus_scan.scan(secure_signatures)
    
    # Verify torus structure
    assert scan_result.topological_pattern == TopologicalPattern.TORUS
    assert scan_result.torus_confidence > 0.7
    assert scan_result.betti_numbers.beta_0 == pytest.approx(1.0, abs=0.3)
    assert scan_result.betti_numbers.beta_1 == pytest.approx(2.0, abs=0.5)
    assert scan_result.betti_numbers.beta_2 == pytest.approx(1.0, abs=0.3)
    
    # Verify topological entropy
    assert scan_result.topological_entropy > math.log(curve.n) * 0.7
    
    # Verify uniformity
    assert scan_result.uniformity_score > 0.7

def test_vulnerability_scoring(torus_scan, secure_signatures, spiral_signatures):
    """Test that vulnerability scoring is accurate across different patterns."""
    # Secure signatures
    secure_score = torus_scan._calculate_vulnerability_score(
        symmetry_violation_rate=0.02,
        spiral_score=0.8,
        star_score=0.2,
        topological_integrity=0.9
    )
    assert secure_score < 0.2
    
    # Spiral pattern
    spiral_score = torus_scan._calculate_vulnerability_score(
        symmetry_violation_rate=0.12,
        spiral_score=0.3,
        star_score=0.2,
        topological_integrity=0.5
    )
    assert spiral_score > 0.5
    
    # Star pattern
    star_score = torus_scan._calculate_vulnerability_score(
        symmetry_violation_rate=0.1,
        spiral_score=0.7,
        star_score=0.8,
        topological_integrity=0.5
    )
    assert star_score > 0.5
    
    # Symmetry violation
    symmetry_score = torus_scan._calculate_vulnerability_score(
        symmetry_violation_rate=0.15,
        spiral_score=0.7,
        star_score=0.2,
        topological_integrity=0.6
    )
    assert symmetry_score > 0.5

def test_analysis_caching(torus_scan, secure_signatures):
    """Test that analysis results are properly cached."""
    public_key = secure_signatures[0].public_key
    
    # First analysis (should compute)
    start_time = time.time()
    analysis1 = torus_scan.scan(secure_signatures)
    time1 = time.time() - start_time
    
    # Second analysis (should use cache)
    start_time = time.time()
    analysis2 = torus_scan.scan(secure_signatures)
    time2 = time.time() - start_time
    
    # Verify cache hit
    assert time2 < time1 * 0.1  # Second analysis should be much faster
    
    # Verify cached results are the same
    assert analysis1.vulnerability_score == analysis2.vulnerability_score
    assert analysis1.betti_numbers.beta_0 == analysis2.betti_numbers.beta_0
    assert analysis1.betti_numbers.beta_1 == analysis2.betti_numbers.beta_1
    assert analysis1.betti_numbers.beta_2 == analysis2.betti_numbers.beta_2
    
    # Verify cache expiration
    torus_scan.last_analysis = {}  # Clear cache
    start_time = time.time()
    analysis3 = torus_scan.scan(secure_signatures)
    time3 = time.time() - start_time
    
    # Should take similar time to first analysis
    assert time3 > time1 * 0.8

def test_edge_cases(torus_scan, sample_public_key):
    """Test edge cases for the TorusScan component."""
    # Test with empty signatures
    with pytest.raises(ValueError):
        torus_scan.scan([])
    
    # Test with invalid public key
    invalid_signatures = [
        ECDSASignature(
            r=1, s=2, z=3, u_r=4, u_z=5, 
            public_key="invalid_key_format"
        )
    ]
    with pytest.raises(ValueError):
        torus_scan.scan(invalid_signatures)
    
    # Test with single signature
    single_signature = generate_signature_sample(
        sample_public_key,
        num_samples=1,
        curve_name=TEST_CURVE
    )
    analysis = torus_scan.scan(single_signature)
    assert analysis is not None
    assert 0.0 <= analysis.vulnerability_score <= 1.0
    
    # Test with maximum signatures
    max_signatures = 10000
    max_signature = generate_signature_sample(
        sample_public_key,
        num_samples=max_signatures,
        curve_name=TEST_CURVE
    )
    start_time = time.time()
    analysis = torus_scan.scan(max_signature)
    analysis_time = time.time() - start_time
    assert analysis is not None
    assert analysis_time < 30.0  # Should analyze 10k signatures in under 30 seconds

def test_resource_constrained_analysis(torus_scan, secure_signatures):
    """Test that analysis works under resource constraints."""
    # Mock resource constraints
    with patch.object(torus_scan.compute_router, 'get_available_resources') as mock_resources:
        # Test with low CPU
        mock_resources.return_value = {'cpu': 0.1, 'memory': 0.5, 'time': 10.0}
        low_cpu_result = torus_scan.scan(secure_signatures)
        assert low_cpu_result.vulnerability_score >= 0.0
        assert low_cpu_result.analysis_method == "resource_constrained"
        
        # Test with low memory
        mock_resources.return_value = {'cpu': 0.5, 'memory': 0.1, 'time': 10.0}
        low_memory_result = torus_scan.scan(secure_signatures)
        assert low_memory_result.vulnerability_score >= 0.0
        assert low_memory_result.analysis_method == "resource_constrained"
        
        # Test with low time
        mock_resources.return_value = {'cpu': 0.5, 'memory': 0.5, 'time': 1.0}
        low_time_result = torus_scan.scan(secure_signatures)
        assert low_time_result.vulnerability_score >= 0.0
        assert low_time_result.analysis_method == "resource_constrained"

def test_vulnerability_remediation(torus_scan, spiral_signatures):
    """Test that vulnerability remediation recommendations are appropriate."""
    # Get remediation recommendations
    recommendations = torus_scan.get_remediation_recommendations(spiral_signatures)
    
    # Check for appropriate recommendations
    assert any("spiral" in rec.lower() for rec in recommendations)
    assert any("random number generator" in rec.lower() for rec in recommendations)
    assert any("linear congruential" in rec.lower() for rec in recommendations)

def test_report_generation(torus_scan, secure_signatures, spiral_signatures):
    """Test that analysis reports are correctly generated."""
    # Generate report for secure signatures
    secure_report = torus_scan.generate_analysis_report(secure_signatures)
    assert "SECURE" in secure_report
    assert "Vulnerability Score: 0.0" not in secure_report  # Should be low but not zero
    assert "Topological Pattern: TORUS" in secure_report
    assert "Recommendation: No critical vulnerabilities detected" in secure_report
    
    # Generate report for vulnerable signatures
    vulnerable_report = torus_scan.generate_analysis_report(spiral_signatures)
    assert "VULNERABLE" in vulnerable_report
    assert "Vulnerability Score:" in vulnerable_report
    assert "Topological Pattern:" in vulnerable_report
    assert "spiral pattern" in vulnerable_report.lower()

def test_amplification_step_adjustment(torus_scan, secure_signatures, spiral_signatures):
    """Test that amplification step adjustment works correctly."""
    # Test with secure signatures
    secure_steps = torus_scan._determine_amplification_steps(secure_signatures)
    assert 5 <= secure_steps <= 15  # Fewer steps for secure implementations
    
    # Test with vulnerable signatures
    vulnerable_steps = torus_scan._determine_amplification_steps(spiral_signatures)
    assert 15 <= vulnerable_steps <= 30  # More steps for vulnerable implementations
    
    # Verify step adjustment logic
    assert vulnerable_steps > secure_steps

def test_dynamic_step_size(torus_scan, secure_signatures, spiral_signatures):
    """Test that dynamic step size adjustment works correctly."""
    # Test with secure signatures
    secure_step = torus_scan._determine_step_size(secure_signatures)
    assert 1000 <= secure_step <= 5000  # Larger steps for secure implementations
    
    # Test with vulnerable signatures
    vulnerable_step = torus_scan._determine_step_size(spiral_signatures)
    assert 100 <= vulnerable_step <= 1000  # Smaller steps for vulnerable implementations
    
    # Verify step size adjustment logic
    assert secure_step > vulnerable_step

def test_torus_scan_integration(torus_scan, secure_signatures):
    """Test the complete TorusScan workflow."""
    # Perform full scan
    scan_result = torus_scan.scan(secure_signatures)
    
    # Verify workflow steps
    assert scan_result.analysis_timestamp > 0
    assert scan_result.execution_time > 0
    assert scan_result.topological_integrity > 0.8
    assert scan_result.symmetry_violation_rate < 0.05
    assert scan_result.spiral_score > 0.7
    assert scan_result.star_score < 0.3
    assert scan_result.amplitude_profile is not None
    assert scan_result.entanglement_metrics is not None
    assert scan_result.vulnerability_score < 0.2
    assert scan_result.is_secure is True

def test_vulnerability_localization(torus_scan, spiral_signatures):
    """Test that vulnerabilities are precisely localized."""
    scan_result = torus_scan.scan(spiral_signatures)
    
    # Verify critical regions
    assert len(scan_result.critical_regions) > 0
    for region in scan_result.critical_regions:
        # Verify region properties
        assert "u_r_range" in region
        assert "u_z_range" in region
        assert "amplification" in region
        assert "type" in region
        assert region["amplification"] > 0.5
        
        # Verify region makes sense for spiral pattern
        if region["type"] == "spiral":
            u_r_min, u_r_max = region["u_r_range"]
            u_z_min, u_z_max = region["u_z_range"]
            # Spiral patterns typically follow diagonal or curved regions
            assert abs((u_r_max - u_r_min) - (u_z_max - u_z_min)) < max(
                u_r_max - u_r_min, 
                u_z_max - u_z_min
            ) * 0.5

def test_persistent_homology(torus_scan, secure_signatures):
    """Test that persistent homology correctly identifies topological features."""
    # Get persistence diagrams
    persistence_diagrams = torus_scan.conformance_checker.betti_calculator.compute_persistence_diagrams(secure_signatures)
    
    # Verify persistence diagrams
    assert len(persistence_diagrams) == 3  # H0, H1, H2
    assert len(persistence_diagrams[0]) > 0  # H0 should have at least one component
    assert len(persistence_diagrams[1]) >= 2  # H1 should have at least two cycles for torus
    assert len(persistence_diagrams[2]) >= 1  # H2 should have at least one void for torus
    
    # Verify persistent cycles
    persistent_cycles = torus_scan.conformance_checker.betti_calculator.extract_persistent_cycles(
        persistence_diagrams,
        secure_signatures
    )
    assert len(persistent_cycles) > 0
    for cycle in persistent_cycles:
        assert cycle.dimension in [0, 1, 2]
        assert cycle.persistence > 0.0
        assert 0.0 <= cycle.stability <= 1.0
        assert len(cycle.representative_points) > 0

def test_analysis_history(torus_scan, secure_signatures):
    """Test that analysis history is correctly maintained."""
    # Perform multiple analyses
    for _ in range(5):
        torus_scan.scan(secure_signatures)
        time.sleep(0.1)  # Ensure different timestamps
    
    # Verify history
    history = torus_scan.get_analysis_history()
    assert len(history) == 5
    for i in range(1, 5):
        assert history[i].analysis_timestamp >= history[i-1].analysis_timestamp
    
    # Verify latest analysis
    latest = torus_scan.get_latest_analysis()
    assert latest is not None
    assert latest == history[-1]
    
    # Verify average vulnerability
    avg_vulnerability = torus_scan.get_average_vulnerability()
    assert 0.0 <= avg_vulnerability <= 1.0

def test_torus_structure_verification(torus_scan, secure_signatures, spiral_signatures):
    """Test that torus structure verification works correctly."""
    # Verify secure signatures form a torus
    secure_torus = torus_scan.conformance_checker.verify_torus_structure(secure_signatures)
    assert secure_torus["is_torus"] is True
    assert secure_torus["confidence"] > 0.7
    
    # Verify vulnerable signatures don't form a proper torus
    vulnerable_torus = torus_scan.conformance_checker.verify_torus_structure(spiral_signatures)
    assert vulnerable_torus["is_torus"] is False
    assert vulnerable_torus["confidence"] < 0.5
    
    # Verify Betti number expectations
    assert secure_torus["expected_betti"]["beta_0"] == 1.0
    assert secure_torus["expected_betti"]["beta_1"] == 2.0
    assert secure_torus["expected_betti"]["beta_2"] == 1.0

def test_quantum_security_metrics(torus_scan, secure_signatures, weak_key_signatures):
    """Test that quantum-inspired security metrics are correctly calculated."""
    # Secure signatures
    secure_metrics = torus_scan.get_quantum_security_metrics(secure_signatures)
    assert secure_metrics["entanglement_entropy"] > math.log(SECP256K1_N) * 0.7
    assert secure_metrics["quantum_risk_score"] < 0.3
    
    # Weak key signatures
    weak_key_metrics = torus_scan.get_quantum_security_metrics(weak_key_signatures)
    assert weak_key_metrics["entanglement_entropy"] < math.log(SECP256K1_N) * 0.3
    assert weak_key_metrics["quantum_risk_score"] > 0.7

def test_adaptive_amplification(torus_scan, secure_signatures, spiral_signatures):
    """Test that adaptive amplification works correctly."""
    # Test with secure signatures
    secure_amplification = torus_scan._get_adaptive_amplification(secure_signatures)
    assert 0.1 <= secure_amplification <= 0.5
    
    # Test with vulnerable signatures
    vulnerable_amplification = torus_scan._get_adaptive_amplification(spiral_signatures)
    assert 0.7 <= vulnerable_amplification <= 1.0
    
    # Verify amplification adjustment logic
    assert vulnerable_amplification > secure_amplification
