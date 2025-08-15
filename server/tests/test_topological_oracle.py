"""
TopoSphere Server Topological Oracle Tests

This module contains comprehensive tests for the Topological Oracle component of the
TopoSphere server system. The tests verify the correct implementation of topological
analysis, vulnerability detection, and TCON (Topological Conformance) verification.

The tests are based on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "Direct analysis without building the full hypercube enables efficient monitoring of large spaces."

The tests verify the following key properties:
- For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
- Topological Oracle correctly identifies vulnerabilities through pattern recognition
- TCON verification accurately assesses topological conformance
- Integration with Dynamic Compute Router optimizes resource usage
- Entanglement entropy analysis detects weak key vulnerabilities

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." These tests ensure that the Topological Oracle
implements this principle correctly.

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
from server.core.topological_oracle import TopologicalOracle
from server.config.server_config import ServerConfig
from server.core.dynamic_compute_router import DynamicComputeRouter
from server.modules.torus_scan import SpiralAnalysis, SymmetryChecker
from server.modules.tcon_analysis import BettiCalculator, ConformanceChecker
from server.modules.quantum_scanning import QuantumScanner, EntanglementEntropyAnalyzer
from server.modules.predictive_analysis import PredictiveAnalyzer
from server.utils.differential_privacy import DifferentialPrivacy
from server.utils.secure_random import SecureRandom
from shared.models.topological_models import (
    BettiNumbers,
    TopologicalAnalysisResult,
    TopologicalPattern,
    PersistentCycle
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
    generate_synthetic_signatures
)

# Test configuration
TEST_CURVE = "secp256k1"
TEST_NUM_SAMPLES = 100
SECP256K1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
MIN_SECURE_BETTI = {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0}

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
def topological_oracle(server_config, dynamic_compute_router):
    """Fixture to create a topological oracle for testing."""
    return TopologicalOracle(
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
def vulnerable_signatures(sample_public_key):
    """Fixture to create vulnerable signatures for testing (spiral pattern)."""
    return generate_synthetic_signatures(
        sample_public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral",
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

def test_oracle_initialization(topological_oracle, server_config):
    """Test that the topological oracle initializes correctly."""
    assert topological_oracle is not None
    assert topological_oracle.config == server_config
    assert topological_oracle.compute_router is not None
    assert topological_oracle.spiral_analysis is not None
    assert topological_oracle.symmetry_checker is not None
    assert topological_oracle.betti_calculator is not None
    assert topological_oracle.conformance_checker is not None
    assert topological_oracle.quantum_scanner is not None
    assert topological_oracle.entanglement_analyzer is not None
    assert topological_oracle.predictive_analyzer is not None
    assert topological_oracle.differential_privacy is not None
    assert topological_oracle.secure_random is not None
    assert topological_oracle.logger is not None
    assert topological_oracle.last_analysis == {}
    assert topological_oracle.analysis_cache == {}
    assert topological_oracle.analysis_history == []

def test_secure_signature_analysis(topological_oracle, secure_signatures):
    """Test that secure signatures are correctly analyzed as secure."""
    analysis = topological_oracle.analyze_signatures(secure_signatures)
    
    # Verify analysis results
    assert analysis is not None
    assert analysis.betti_numbers is not None
    assert analysis.topological_pattern == TopologicalPattern.TORUS
    assert analysis.torus_confidence > 0.7
    assert analysis.vulnerability_score < 0.2
    assert analysis.security_level == "secure"
    assert analysis.is_secure is True
    assert analysis.anomaly_score < 0.3
    assert analysis.symmetry_violation_rate < 0.05
    assert analysis.spiral_score > 0.7
    assert analysis.star_score < 0.3
    assert analysis.critical_regions == []
    
    # Verify Betti numbers match expected torus structure
    assert abs(analysis.betti_numbers.beta_0 - MIN_SECURE_BETTI["beta_0"]) < 0.3
    assert abs(analysis.betti_numbers.beta_1 - MIN_SECURE_BETTI["beta_1"]) < 0.5
    assert abs(analysis.betti_numbers.beta_2 - MIN_SECURE_BETTI["beta_2"]) < 0.3

def test_vulnerable_signature_analysis(topological_oracle, vulnerable_signatures):
    """Test that vulnerable signatures (spiral pattern) are correctly identified."""
    analysis = topological_oracle.analyze_signatures(vulnerable_signatures)
    
    # Verify analysis results
    assert analysis is not None
    assert analysis.topological_pattern != TopologicalPattern.TORUS
    assert analysis.torus_confidence < 0.5
    assert analysis.vulnerability_score > 0.5
    assert analysis.security_level == "vulnerable"
    assert analysis.is_secure is False
    assert analysis.anomaly_score > 0.6
    assert analysis.symmetry_violation_rate > 0.05
    assert analysis.spiral_score < 0.5
    assert analysis.star_score < 0.3
    
    # Verify critical regions are detected
    assert len(analysis.critical_regions) > 0
    for region in analysis.critical_regions:
        assert "type" in region
        assert "amplification" in region
        assert "u_r_range" in region
        assert "u_z_range" in region
        assert region["amplification"] > 0.5

def test_weak_key_analysis(topological_oracle, weak_key_signatures):
    """Test that weak key signatures are correctly identified."""
    analysis = topological_oracle.analyze_signatures(weak_key_signatures)
    
    # Verify analysis results
    assert analysis is not None
    assert analysis.vulnerability_score > 0.7
    assert analysis.security_level == "critical"
    assert analysis.is_secure is False
    assert analysis.anomaly_score > 0.8
    
    # Verify entanglement entropy analysis
    entanglement_metrics = topological_oracle.entanglement_analyzer.get_entanglement_metrics(
        weak_key_signatures[0].public_key
    )
    assert entanglement_metrics.gcd_value > 1
    assert entanglement_metrics.entanglement_entropy > 0.0
    assert entanglement_metrics.vulnerability_score > 0.7

def test_tcon_compliance(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that TCON compliance is correctly verified."""
    # Secure signatures should be TCON compliant
    secure_compliance = topological_oracle.verify_tcon_compliance(secure_signatures)
    assert secure_compliance["is_compliant"] is True
    assert secure_compliance["vulnerability_score"] < 0.2
    assert secure_compliance["betti_deviation"] < 0.5
    
    # Vulnerable signatures should not be TCON compliant
    vulnerable_compliance = topological_oracle.verify_tcon_compliance(vulnerable_signatures)
    assert vulnerable_compliance["is_compliant"] is False
    assert vulnerable_compliance["vulnerability_score"] > 0.5
    assert vulnerable_compliance["betti_deviation"] > 0.5

def test_symmetry_analysis(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that symmetry analysis correctly identifies violations."""
    # Secure signatures should have low symmetry violation rate
    secure_symmetry = topological_oracle.symmetry_checker.check_symmetry(secure_signatures)
    assert secure_symmetry["violation_rate"] < 0.05
    assert secure_symmetry["is_symmetric"] is True
    
    # Vulnerable signatures should have high symmetry violation rate
    vulnerable_symmetry = topological_oracle.symmetry_checker.check_symmetry(vulnerable_signatures)
    assert vulnerable_symmetry["violation_rate"] > 0.1
    assert vulnerable_symmetry["is_symmetric"] is False

def test_spiral_analysis(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that spiral analysis correctly identifies patterns."""
    # Secure signatures should have high spiral score (low spiral pattern)
    secure_spiral = topological_oracle.spiral_analysis.analyze_spiral_pattern(secure_signatures)
    assert secure_spiral["spiral_score"] > 0.7
    assert secure_spiral["is_spiral_pattern"] is False
    
    # Vulnerable signatures should have low spiral score (high spiral pattern)
    vulnerable_spiral = topological_oracle.spiral_analysis.analyze_spiral_pattern(vulnerable_signatures)
    assert vulnerable_spiral["spiral_score"] < 0.5
    assert vulnerable_spiral["is_spiral_pattern"] is True

def test_betti_number_calculation(topological_oracle, secure_signatures):
    """Test that Betti numbers are correctly calculated."""
    betti_calculator = topological_oracle.betti_calculator
    betti_numbers = betti_calculator.calculate_betti_numbers(secure_signatures)
    
    # Verify Betti numbers match expected torus structure
    assert isinstance(betti_numbers, BettiNumbers)
    assert 0.7 <= betti_numbers.beta_0 <= 1.3
    assert 1.5 <= betti_numbers.beta_1 <= 2.5
    assert 0.7 <= betti_numbers.beta_2 <= 1.3
    assert 0.7 <= betti_numbers.stability_score <= 1.0

def test_quantum_scanning(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that quantum scanning correctly identifies vulnerabilities."""
    # Secure signatures should have low vulnerability score
    secure_scan = topological_oracle.quantum_scanner.scan(secure_signatures[0].public_key)
    assert secure_scan.vulnerability_score < 0.2
    assert secure_scan.is_secure is True
    
    # Vulnerable signatures should have high vulnerability score
    vulnerable_scan = topological_oracle.quantum_scanner.scan(vulnerable_signatures[0].public_key)
    assert vulnerable_scan.vulnerability_score > 0.5
    assert vulnerable_scan.is_secure is False

def test_entanglement_entropy_analysis(topological_oracle, weak_key_signatures):
    """Test that entanglement entropy analysis detects weak keys."""
    analyzer = topological_oracle.entanglement_analyzer
    public_key = weak_key_signatures[0].public_key
    
    # Analyze entanglement
    analysis = analyzer.analyze(public_key)
    
    # Verify weak key detection
    assert analysis.entanglement_metrics.gcd_value > 1
    assert analysis.entanglement_metrics.entanglement_entropy > 0.0
    assert analysis.quantum_vulnerability_score > 0.7
    assert analysis.security_level == "critical"

def test_predictive_analysis(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that predictive analysis correctly forecasts risks."""
    # Secure signatures should have low risk forecast
    secure_forecast = topological_oracle.predict_vulnerabilities(secure_signatures)
    assert secure_forecast.risk_score < 0.3
    assert secure_forecast.confidence > 0.7
    assert secure_forecast.trend_value < 0.0
    
    # Vulnerable signatures should have high risk forecast
    vulnerable_forecast = topological_oracle.predict_vulnerabilities(vulnerable_signatures)
    assert vulnerable_forecast.risk_score > 0.6
    assert vulnerable_forecast.confidence > 0.7
    assert vulnerable_forecast.trend_value > 0.0

def test_differential_privacy_integration(topological_oracle, secure_signatures):
    """Test that differential privacy is correctly integrated."""
    # Analyze with privacy
    private_analysis = topological_oracle.analyze_signatures(
        secure_signatures,
        apply_privacy=True
    )
    
    # Analyze without privacy
    regular_analysis = topological_oracle.analyze_signatures(
        secure_signatures,
        apply_privacy=False
    )
    
    # Verify privacy parameters
    assert private_analysis.privacy_parameters is not None
    assert private_analysis.privacy_parameters.epsilon > 0.0
    assert private_analysis.privacy_parameters.delta >= 0.0
    
    # Verify noise has been added (comparing to non-private analysis)
    differences = 0
    if private_analysis.betti_numbers.beta_0 != regular_analysis.betti_numbers.beta_0:
        differences += 1
    if private_analysis.betti_numbers.beta_1 != regular_analysis.betti_numbers.beta_1:
        differences += 1
    if private_analysis.betti_numbers.beta_2 != regular_analysis.betti_numbers.beta_2:
        differences += 1
    if private_analysis.symmetry_violation_rate != regular_analysis.symmetry_violation_rate:
        differences += 1
    if private_analysis.spiral_score != regular_analysis.spiral_score:
        differences += 1
    
    # Should have some differences due to noise
    assert differences > 0
    
    # Verify privacy budget usage
    assert private_analysis.epsilon_consumed > 0.0
    assert private_analysis.delta_consumed >= 0.0
    assert private_analysis.is_privacy_strong or private_analysis.is_privacy_moderate

def test_secure_random_integration(topological_oracle):
    """Test that secure random integration works correctly."""
    # Generate secure random sequence
    sequence = topological_oracle.secure_random.generate_secure_sequence(1000, SECP256K1_N)
    
    # Analyze quality
    analysis = topological_oracle.secure_random.analyze_random_sequence(sequence, SECP256K1_N)
    
    # Verify quality
    assert analysis.quality_score > 0.7
    assert analysis.quality_level in ["excellent", "good"]
    assert analysis.pattern_type == "uniform"
    assert analysis.symmetry_violation_rate < 0.05
    assert analysis.spiral_score > 0.7
    assert analysis.star_score < 0.3

def test_dynamic_resource_allocation(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that dynamic resource allocation works correctly."""
    # Track resource usage
    start_cpu = topological_oracle.compute_router.get_cpu_usage()
    start_memory = topological_oracle.compute_router.get_memory_usage()
    
    # Analyze secure signatures
    start_time = time.time()
    topological_oracle.analyze_signatures(secure_signatures)
    secure_time = time.time() - start_time
    
    # Analyze vulnerable signatures
    start_time = time.time()
    topological_oracle.analyze_signatures(vulnerable_signatures)
    vulnerable_time = time.time() - start_time
    
    # Verify resource allocation
    end_cpu = topological_oracle.compute_router.get_cpu_usage()
    end_memory = topological_oracle.compute_router.get_memory_usage()
    
    # Vulnerable signatures should take more time to analyze
    assert vulnerable_time > secure_time * 0.8  # Allow for some variation
    
    # Verify resource usage stayed within limits
    assert end_cpu - start_cpu < 0.3  # Less than 30% CPU increase
    assert end_memory - start_memory < 0.2  # Less than 20% memory increase

def test_analysis_caching(topological_oracle, secure_signatures):
    """Test that analysis results are properly cached."""
    public_key = secure_signatures[0].public_key
    
    # First analysis (should compute)
    start_time = time.time()
    analysis1 = topological_oracle.analyze_signatures(secure_signatures)
    time1 = time.time() - start_time
    
    # Second analysis (should use cache)
    start_time = time.time()
    analysis2 = topological_oracle.analyze_signatures(secure_signatures)
    time2 = time.time() - start_time
    
    # Verify cache hit
    assert time2 < time1 * 0.1  # Second analysis should be much faster
    
    # Verify cached results are the same
    assert analysis1.vulnerability_score == analysis2.vulnerability_score
    assert analysis1.betti_numbers.beta_0 == analysis2.betti_numbers.beta_0
    assert analysis1.betti_numbers.beta_1 == analysis2.betti_numbers.beta_1
    assert analysis1.betti_numbers.beta_2 == analysis2.betti_numbers.beta_2
    
    # Verify cache expiration
    topological_oracle.last_analysis = {}  # Clear cache
    start_time = time.time()
    analysis3 = topological_oracle.analyze_signatures(secure_signatures)
    time3 = time.time() - start_time
    
    # Should take similar time to first analysis
    assert time3 > time1 * 0.8

def test_edge_cases(topological_oracle, sample_public_key):
    """Test edge cases for the topological oracle."""
    # Test with empty signatures
    with pytest.raises(ValueError):
        topological_oracle.analyze_signatures([])
    
    # Test with invalid public key
    invalid_signatures = [
        ECDSASignature(
            r=1, s=2, z=3, u_r=4, u_z=5, 
            public_key="invalid_key_format"
        )
    ]
    with pytest.raises(ValueError):
        topological_oracle.analyze_signatures(invalid_signatures)
    
    # Test with single signature
    single_signature = generate_signature_sample(
        sample_public_key,
        num_samples=1,
        curve_name=TEST_CURVE
    )
    analysis = topological_oracle.analyze_signatures(single_signature)
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
    analysis = topological_oracle.analyze_signatures(max_signature)
    analysis_time = time.time() - start_time
    assert analysis is not None
    assert analysis_time < 30.0  # Should analyze 10k signatures in under 30 seconds

def test_bijective_parameterization(topological_oracle, secure_signatures):
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

def test_torus_structure(topological_oracle, secure_signatures):
    """Test that secure signatures form a torus structure."""
    analysis = topological_oracle.analyze_signatures(secure_signatures)
    
    # Verify torus structure
    assert analysis.topological_pattern == TopologicalPattern.TORUS
    assert analysis.torus_confidence > 0.7
    assert analysis.betti_numbers.beta_0 == pytest.approx(1.0, abs=0.3)
    assert analysis.betti_numbers.beta_1 == pytest.approx(2.0, abs=0.5)
    assert analysis.betti_numbers.beta_2 == pytest.approx(1.0, abs=0.3)
    
    # Verify topological entropy
    assert analysis.topological_entropy > math.log(curve.n) * 0.7
    
    # Verify uniformity
    assert analysis.uniformity_score > 0.7

def test_vulnerability_detection(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that vulnerability detection is accurate across different patterns."""
    # Spiral pattern
    spiral_signatures = generate_synthetic_signatures(
        secure_signatures[0].public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="spiral",
        curve_name=TEST_CURVE
    )
    spiral_analysis = topological_oracle.analyze_signatures(spiral_signatures)
    assert spiral_analysis.vulnerability_score > 0.5
    assert spiral_analysis.spiral_score < 0.5
    
    # Star pattern
    star_signatures = generate_synthetic_signatures(
        secure_signatures[0].public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="star",
        curve_name=TEST_CURVE
    )
    star_analysis = topological_oracle.analyze_signatures(star_signatures)
    assert star_analysis.vulnerability_score > 0.5
    assert star_analysis.star_score > 0.6
    
    # Symmetry violation
    symmetry_signatures = generate_synthetic_signatures(
        secure_signatures[0].public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="symmetry_violation",
        curve_name=TEST_CURVE
    )
    symmetry_analysis = topological_oracle.analyze_signatures(symmetry_signatures)
    assert symmetry_analysis.vulnerability_score > 0.5
    assert symmetry_analysis.symmetry_violation_rate > 0.1
    
    # Weak key
    weak_key_signatures = generate_synthetic_signatures(
        secure_signatures[0].public_key,
        num_signatures=TEST_NUM_SAMPLES,
        vulnerability_type="weak_key",
        curve_name=TEST_CURVE
    )
    weak_key_analysis = topological_oracle.analyze_signatures(weak_key_signatures)
    assert weak_key_analysis.vulnerability_score > 0.7
    assert weak_key_analysis.entanglement_metrics.gcd_value > 1

def test_persistent_homology(topological_oracle, secure_signatures):
    """Test that persistent homology correctly identifies topological features."""
    # Get persistence diagrams
    persistence_diagrams = topological_oracle.betti_calculator.compute_persistence_diagrams(secure_signatures)
    
    # Verify persistence diagrams
    assert len(persistence_diagrams) == 3  # H0, H1, H2
    assert len(persistence_diagrams[0]) > 0  # H0 should have at least one component
    assert len(persistence_diagrams[1]) >= 2  # H1 should have at least two cycles for torus
    assert len(persistence_diagrams[2]) >= 1  # H2 should have at least one void for torus
    
    # Verify persistent cycles
    persistent_cycles = topological_oracle.betti_calculator.extract_persistent_cycles(
        persistence_diagrams,
        secure_signatures
    )
    assert len(persistent_cycles) > 0
    for cycle in persistent_cycles:
        assert cycle.dimension in [0, 1, 2]
        assert cycle.persistence > 0.0
        assert 0.0 <= cycle.stability <= 1.0
        assert len(cycle.representative_points) > 0

def test_analysis_history(topological_oracle, secure_signatures):
    """Test that analysis history is correctly maintained."""
    # Perform multiple analyses
    for _ in range(5):
        topological_oracle.analyze_signatures(secure_signatures)
        time.sleep(0.1)  # Ensure different timestamps
    
    # Verify history
    history = topological_oracle.get_analysis_history()
    assert len(history) == 5
    for i in range(1, 5):
        assert history[i].analysis_timestamp >= history[i-1].analysis_timestamp
    
    # Verify latest analysis
    latest = topological_oracle.get_latest_analysis()
    assert latest is not None
    assert latest == history[-1]
    
    # Verify average vulnerability
    avg_vulnerability = topological_oracle.get_average_vulnerability()
    assert 0.0 <= avg_vulnerability <= 1.0

def test_resource_constrained_analysis(topological_oracle, secure_signatures):
    """Test that analysis works under resource constraints."""
    # Mock resource constraints
    with patch.object(topological_oracle.compute_router, 'get_available_resources') as mock_resources:
        # Test with low CPU
        mock_resources.return_value = {'cpu': 0.1, 'memory': 0.5, 'time': 10.0}
        low_cpu_analysis = topological_oracle.analyze_signatures(secure_signatures)
        assert low_cpu_analysis.vulnerability_score >= 0.0
        assert low_cpu_analysis.analysis_method == "resource_constrained"
        
        # Test with low memory
        mock_resources.return_value = {'cpu': 0.5, 'memory': 0.1, 'time': 10.0}
        low_memory_analysis = topological_oracle.analyze_signatures(secure_signatures)
        assert low_memory_analysis.vulnerability_score >= 0.0
        assert low_memory_analysis.analysis_method == "resource_constrained"
        
        # Test with low time
        mock_resources.return_value = {'cpu': 0.5, 'memory': 0.5, 'time': 1.0}
        low_time_analysis = topological_oracle.analyze_signatures(secure_signatures)
        assert low_time_analysis.vulnerability_score >= 0.0
        assert low_time_analysis.analysis_method == "resource_constrained"

def test_quantum_security_metrics(topological_oracle, secure_signatures, weak_key_signatures):
    """Test that quantum-inspired security metrics are correctly calculated."""
    # Secure signatures
    secure_metrics = topological_oracle.get_quantum_security_metrics(secure_signatures)
    assert secure_metrics["entanglement_entropy"] > math.log(SECP256K1_N) * 0.7
    assert secure_metrics["quantum_risk_score"] < 0.3
    
    # Weak key signatures
    weak_key_metrics = topological_oracle.get_quantum_security_metrics(weak_key_signatures)
    assert weak_key_metrics["entanglement_entropy"] < math.log(SECP256K1_N) * 0.3
    assert weak_key_metrics["quantum_risk_score"] > 0.7

def test_vulnerability_remediation(topological_oracle, vulnerable_signatures):
    """Test that vulnerability remediation recommendations are appropriate."""
    # Get remediation recommendations
    recommendations = topological_oracle.get_remediation_recommendations(vulnerable_signatures)
    
    # Check for appropriate recommendations
    assert any("spiral" in rec.lower() for rec in recommendations)
    assert any("random number generator" in rec.lower() for rec in recommendations)
    assert any("linear congruential" in rec.lower() for rec in recommendations)

def test_oracle_report_generation(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that oracle reports are correctly generated."""
    # Generate report for secure signatures
    secure_report = topological_oracle.generate_analysis_report(secure_signatures)
    assert "SECURE" in secure_report
    assert "Vulnerability Score: 0.0" not in secure_report  # Should be low but not zero
    assert "Topological Pattern: TORUS" in secure_report
    assert "Recommendation: No critical vulnerabilities detected" in secure_report
    
    # Generate report for vulnerable signatures
    vulnerable_report = topological_oracle.generate_analysis_report(vulnerable_signatures)
    assert "VULNERABLE" in vulnerable_report
    assert "Vulnerability Score:" in vulnerable_report
    assert "Topological Pattern:" in vulnerable_report
    assert "spiral pattern" in vulnerable_report.lower()

def test_torus_scan_integration(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that TorusScan integration works correctly."""
    # Test with secure signatures
    secure_scan = topological_oracle.torus_scan.scan(secure_signatures)
    assert secure_scan.vulnerability_score < 0.2
    assert secure_scan.is_secure is True
    assert secure_scan.spiral_score > 0.7
    assert secure_scan.symmetry_violation_rate < 0.05
    
    # Test with vulnerable signatures
    vulnerable_scan = topological_oracle.torus_scan.scan(vulnerable_signatures)
    assert vulnerable_scan.vulnerability_score > 0.5
    assert vulnerable_scan.is_secure is False
    assert vulnerable_scan.spiral_score < 0.5
    assert vulnerable_scan.symmetry_violation_rate > 0.05

def test_dynamic_analysis(topological_oracle, secure_signatures):
    """Test that dynamic analysis adapts to changing conditions."""
    # Initial analysis
    initial_analysis = topological_oracle.analyze_signatures(secure_signatures)
    
    # Simulate changing conditions (e.g., resource constraints)
    with patch.object(topological_oracle.compute_router, 'get_available_resources') as mock_resources:
        mock_resources.return_value = {'cpu': 0.2, 'memory': 0.2, 'time': 5.0}
        
        # Analysis under constrained resources
        constrained_analysis = topological_oracle.analyze_signatures(secure_signatures)
        
        # Verify adaptation
        assert constrained_analysis.analysis_method == "resource_constrained"
        assert constrained_analysis.vulnerability_score >= initial_analysis.vulnerability_score * 0.8
        assert constrained_analysis.execution_time < initial_analysis.execution_time * 0.5

def test_prediction_accuracy(topological_oracle, secure_signatures, vulnerable_signatures):
    """Test that prediction accuracy is correctly measured."""
    # Train predictive analyzer
    topological_oracle.predictive_analyzer.train_model([secure_signatures, vulnerable_signatures])
    
    # Test prediction accuracy
    secure_accuracy = topological_oracle.predictive_analyzer.get_prediction_accuracy(secure_signatures)
    vulnerable_accuracy = topological_oracle.predictive_analyzer.get_prediction_accuracy(vulnerable_signatures)
    
    # Secure signatures should have high prediction accuracy
    assert secure_accuracy > 0.8
    
    # Vulnerable signatures should have high prediction accuracy
    assert vulnerable_accuracy > 0.8
    
    # Verify cross-validation
    cv_accuracy = topological_oracle.predictive_analyzer.cross_validate()
    assert 0.7 <= cv_accuracy <= 1.0
