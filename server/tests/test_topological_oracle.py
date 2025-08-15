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
    
    # Should
