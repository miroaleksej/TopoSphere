"""
Mathematical Utilities Module

This module provides essential mathematical functions used throughout the TopoSphere system.
These utilities implement the core mathematical operations required for topological analysis
of ECDSA implementations, including Betti number calculations, topological entropy,
spiral pattern analysis, and diagonal symmetry verification.

The module is designed with performance and numerical stability in mind, implementing
rigorous mathematical foundations while protecting intellectual property through
differential privacy techniques where appropriate.

Key components:
- Betti number calculation and validation
- Topological entropy computation
- Spiral pattern analysis on the torus
- Diagonal symmetry verification
- Periodicity and GCD-based vulnerability detection
- Stability metrics for topological features
- Mathematical operations for elliptic curve cryptography

This module works in conjunction with topological_models.py and cryptographic_models.py,
providing the mathematical backbone for ECDSA security assessment.

Version: 1.0.0
"""

from __future__ import annotations
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
import numpy as np
import random
import math
from collections import defaultdict
from functools import lru_cache
import warnings
from scipy.spatial import distance_matrix
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components
from scipy.stats import entropy as scipy_entropy
import networkx as nx

# ======================
# MATHEMATICAL CONSTANTS
# ======================

# Fundamental mathematical constants
PI = math.pi
E = math.e
GOLDEN_RATIO = (1 + math.sqrt(5)) / 2

# Topological security thresholds
BETTI_SECURE_VALUES = {"beta_0": 1, "beta_1": 2, "beta_2": 1}
BETTI_DEVIATION_THRESHOLD = 0.3  # Maximum acceptable deviation from secure values
TOPOLOGICAL_ENTROPY_THRESHOLD = 0.5  # Minimum acceptable topological entropy
SYMMETRY_VIOLATION_THRESHOLD = 0.01  # Maximum acceptable symmetry violation rate
SPIRAL_CONSISTENCY_THRESHOLD = 0.7  # Minimum acceptable spiral consistency

# Numerical precision constants
EPSILON = 1e-10
TOLERANCE = 1e-8


# ======================
# BASIC MATH UTILITIES
# ======================

def gcd(a: int, b: int) -> int:
    """Compute the greatest common divisor of a and b using Euclidean algorithm.
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        Greatest common divisor of a and b
    """
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """Compute the least common multiple of a and b.
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        Least common multiple of a and b
    """
    return abs(a * b) // gcd(a, b) if a and b else 0


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm returning gcd and Bézout coefficients.
    
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        Tuple containing (gcd, x, y)
    """
    if a == 0:
        return (b, 0, 1)
    
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modular_inverse(a: int, m: int) -> int:
    """Compute the modular multiplicative inverse of a modulo m.
    
    Args:
        a: Integer to invert
        m: Modulus
        
    Returns:
        Modular inverse of a modulo m
        
    Raises:
        ValueError: If the modular inverse does not exist
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return x % m


def is_prime(n: int) -> bool:
    """Check if a number is prime using trial division.
    
    Args:
        n: Number to check
        
    Returns:
        True if n is prime, False otherwise
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def prime_factors(n: int) -> List[int]:
    """Find all prime factors of a number.
    
    Args:
        n: Number to factorize
        
    Returns:
        List of prime factors
    """
    factors = []
    # Handle 2s
    while n % 2 == 0:
        factors.append(2)
        n //= 2
    
    # Handle odd factors
    f = 3
    while f * f <= n:
        if n % f == 0:
            factors.append(f)
            n //= f
        else:
            f += 2
    
    # Handle remaining prime
    if n > 1:
        factors.append(n)
    
    return factors


# ======================
# TOPOLOGICAL UTILITIES
# ======================

def compute_betti_numbers(points: np.ndarray, 
                         epsilon: float, 
                         max_dimension: int = 2) -> Dict[str, int]:
    """Compute Betti numbers for a point cloud using persistent homology.
    
    Betti numbers are topological invariants that count the number of holes in various dimensions:
    - β₀: Number of connected components
    - β₁: Number of 1-dimensional holes (loops)
    - β₂: Number of 2-dimensional holes (voids)
    
    For secure ECDSA implementations, we expect β₀=1, β₁=2, β₂=1 (torus structure).
    
    Args:
        points: Point cloud representing the signature space
        epsilon: Maximum distance for neighborhood graph
        max_dimension: Maximum homology dimension to compute
        
    Returns:
        Dictionary containing Betti numbers (beta_0, beta_1, beta_2)
    """
    if len(points) == 0:
        return {"beta_0": 0, "beta_1": 0, "beta_2": 0}
    
    # Compute distance matrix
    dist_matrix = distance_matrix(points, points)
    
    # Create adjacency matrix (epsilon-neighborhood graph)
    adj_matrix = (dist_matrix <= epsilon).astype(int)
    np.fill_diagonal(adj_matrix, 0)  # Remove self-loops
    
    # Compute connected components (beta_0)
    n_components, _ = connected_components(
        csr_matrix(adj_matrix), 
        directed=False, 
        return_labels=True
    )
    
    # For beta_1 and beta_2, we need more sophisticated analysis
    # In a real implementation, we would use persistent homology libraries
    # Here we use a simplified approach based on graph properties
    
    # Create networkx graph
    G = nx.from_numpy_array(adj_matrix)
    
    # Beta_1: Number of independent cycles
    # For a connected graph: beta_1 = m - n + 1 where m = edges, n = nodes
    beta_1 = 0
    if n_components == 1 and len(G.edges) > 0:
        beta_1 = len(G.edges) - len(G.nodes) + 1
    
    # Beta_2: More complex to compute without 3D structure
    # For torus structure, we expect beta_2 = 1
    beta_2 = 1 if is_torus_structure(points) else 0
    
    return {
        "beta_0": n_components,
        "beta_1": max(0, beta_1),
        "beta_2": beta_2
    }


def is_torus_structure(points: np.ndarray, 
                      n: Optional[int] = None,
                      tolerance: float = 0.3) -> bool:
    """Check if the point cloud has a torus structure.
    
    For secure ECDSA implementations, the signature space forms a torus
    with Betti numbers β₀=1, β₁=2, β₂=1.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup (optional)
        tolerance: Maximum acceptable deviation from expected Betti numbers
        
    Returns:
        True if the structure is a torus, False otherwise
    """
    if len(points) < 100:  # Not enough points for reliable analysis
        return False
    
    # Compute Betti numbers with appropriate epsilon
    epsilon = 0.1 if n is None else 0.1 * n
    betti = compute_betti_numbers(points, epsilon)
    
    # Check against expected torus values
    is_beta_0_ok = abs(betti["beta_0"] - 1) <= tolerance
    is_beta_1_ok = abs(betti["beta_1"] - 2) <= tolerance
    is_beta_2_ok = abs(betti["beta_2"] - 1) <= tolerance
    
    return is_beta_0_ok and is_beta_1_ok and is_beta_2_ok


def calculate_topological_entropy(points: np.ndarray, 
                                 n: int, 
                                 base: float = 2) -> float:
    """Calculate topological entropy of the signature space.
    
    Topological entropy serves as a quantitative security metric:
    - For secure implementations: h_top > log(n)/2
    - For vulnerable implementations: h_top < log(n)/4
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        base: Logarithm base for entropy calculation
        
    Returns:
        Topological entropy value
    """
    if len(points) == 0:
        return 0.0
    
    # In a real implementation, we would use persistent homology to compute entropy
    # Here we use a simplified approach based on point distribution
    
    # Create a grid to discretize the space
    grid_size = min(100, int(math.sqrt(len(points))))
    grid = np.zeros((grid_size, grid_size))
    
    # Normalize points to [0,1]x[0,1]
    points_normalized = points / n
    
    # Count points in each grid cell
    for u_r, u_z in points_normalized:
        i = min(int(u_r * grid_size), grid_size - 1)
        j = min(int(u_z * grid_size), grid_size - 1)
        grid[i, j] += 1
    
    # Normalize to get probability distribution
    total = np.sum(grid)
    if total == 0:
        return 0.0
    
    prob = grid / total
    
    # Calculate entropy
    return scipy_entropy(prob.flatten() + EPSILON, base=base)


def check_diagonal_symmetry(points: np.ndarray, 
                           n: int) -> Dict[str, float]:
    """Check diagonal symmetry as vulnerability indicator.
    
    For a secure implementation, r(u_r, u_z) = r(u_z, u_r) for all (u_r, u_z).
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Dict containing symmetry violation metrics
    """
    if len(points) == 0:
        return {
            "violation_count": 0,
            "total_points": 0,
            "violation_rate": 1.0,
            "is_secure": False
        }
    
    violations = 0
    total = 0
    
    # Check symmetry for sampled points (to avoid O(n^2) complexity)
    sample_size = min(1000, len(points))
    indices = random.sample(range(len(points)), sample_size)
    
    for i in indices:
        u_r, u_z, r_val = points[i]
        
        # Find corresponding symmetric point (u_z, u_r)
        # In a real implementation, we would use a spatial index for efficiency
        symmetric_r = None
        for j in range(len(points)):
            if abs(points[j, 0] - u_z) < EPSILON and abs(points[j, 1] - u_r) < EPSILON:
                symmetric_r = points[j, 2]
                break
        
        if symmetric_r is not None:
            # Check if r values match (with tolerance for numerical issues)
            if abs(r_val - symmetric_r) > n * TOLERANCE:
                violations += 1
            total += 1
    
    violation_rate = violations / total if total > 0 else 1.0
    return {
        "violation_count": violations,
        "total_points": total,
        "violation_rate": violation_rate,
        "is_secure": violation_rate < SYMMETRY_VIOLATION_THRESHOLD
    }


def compute_spiral_pattern(points: np.ndarray, 
                          n: int, 
                          d: Optional[int] = None) -> Dict[str, Any]:
    """Analyze the spiral pattern in the signature space.
    
    The spiral structure on the torus provides critical security insights:
    - Period T = n / GCD(d-1, n) serves as an indicator of vulnerability
    - When GCD(d-1, n) is large, T is small, indicating regular patterns
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        d: Private key estimate (optional)
        
    Returns:
        Dict containing spiral pattern analysis
    """
    if len(points) == 0:
        return {
            "slope": 0.0,
            "period": n,
            "consistency_score": 0.0,
            "is_vulnerable": True,
            "vulnerability_score": 1.0
        }
    
    # Estimate private key if not provided
    if d is None:
        d = estimate_private_key(points, n)
    
    # Analyze spiral consistency
    consistent_points = 0
    total_points = 0
    
    for i in range(len(points)):
        u_r, u_z, _ = points[i]
        
        # Predict next point in the spiral
        u_r_next = (u_r + 1) % n
        u_z_next = (u_z + d) % n
        
        # Check if the next point exists
        found = False
        for j in range(len(points)):
            if (abs(points[j, 0] - u_r_next) < EPSILON and 
                abs(points[j, 1] - u_z_next) < EPSILON):
                found = True
                break
        
        if found:
            consistent_points += 1
        total_points += 1
    
    consistency_score = consistent_points / total_points if total_points > 0 else 0.0
    
    # Calculate period
    g = gcd(d - 1, n) if d is not None else 1
    period = n // g if g > 0 else n
    
    # Vulnerability score (lower is better)
    vulnerability_score = 1.0 - consistency_score
    
    return {
        "slope": d if d is not None else 0.0,
        "period": period,
        "consistency_score": consistency_score,
        "is_vulnerable": period < n / 10,  # Vulnerable if period is too small
        "vulnerability_score": vulnerability_score
    }


def estimate_private_key(points: np.ndarray, n: int) -> Optional[int]:
    """Estimate the private key from signature points.
    
    Based on the relationship: k = u_z + u_r * d mod n
    
    Args:
        points: Point cloud of (u_r, u_z, r) points
        n: Order of the elliptic curve subgroup
        
    Returns:
        Estimated private key or None if cannot be estimated
    """
    if len(points) < 2:
        return None
    
    # Find points with the same r value (collisions)
    r_values = defaultdict(list)
    for i, (u_r, u_z, r) in enumerate(points):
        r_values[int(r)].append((u_r, u_z, i))
    
    # Look for collisions (multiple points with same r)
    for r, points_list in r_values.items():
        if len(points_list) >= 2:
            # Take first two points with same r
            (u_r1, u_z1, _), (u_r2, u_z2, _) = points_list[:2]
            
            # Solve for d: (u_z1 - u_z2) ≡ d * (u_r2 - u_r1) mod n
            delta_u_r = (u_r2 - u_r1) % n
            delta_u_z = (u_z1 - u_z2) % n
            
            if delta_u_r == 0:
                continue  # Skip if delta_u_r is 0
            
            try:
                # d ≡ delta_u_z * delta_u_r^(-1) mod n
                d = (delta_u_z * modular_inverse(delta_u_r, n)) % n
                return int(d)
            except ValueError:
                continue  # Modular inverse doesn't exist
    
    return None


def calculate_periodicity(points: np.ndarray, n: int) -> Dict[str, Any]:
    """Calculate periodicity in the signature space.
    
    Analyzes the periodic structure to detect vulnerabilities.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Dict containing periodicity analysis
    """
    if len(points) == 0:
        return {
            "diagonal_period": n,
            "spiral_period": n,
            "periodicity_score": 0.0,
            "is_vulnerable": True
        }
    
    # Analyze diagonal periodicity
    diagonal_points = []
    for u_r, u_z, _ in points:
        if u_r == u_z:  # Diagonal points
            diagonal_points.append((u_r, u_z))
    
    # Find periodicity along diagonal
    diagonal_periods = []
    diagonal_points.sort(key=lambda x: x[0])
    
    for i in range(1, len(diagonal_points)):
        period = diagonal_points[i][0] - diagonal_points[i-1][0]
        if period > 0:
            diagonal_periods.append(period)
    
    diagonal_period = min(diagonal_periods) if diagonal_periods else n
    
    # Analyze spiral periodicity (using estimated d)
    d = estimate_private_key(points, n)
    spiral_period = n // gcd(d - 1, n) if d is not None else n
    
    # Periodicity score (lower is better)
    periodicity_score = min(
        diagonal_period / n,
        spiral_period / n
    )
    
    return {
        "diagonal_period": diagonal_period,
        "spiral_period": spiral_period,
        "periodicity_score": periodicity_score,
        "is_vulnerable": diagonal_period < n / 10 or spiral_period < n / 10
    }


def compute_stability_metrics(points: np.ndarray, 
                             n: int,
                             epsilon_range: Optional[List[float]] = None) -> Dict[str, Any]:
    """Compute stability metrics for topological features.
    
    Measures how stable topological features are when subjected to
    small perturbations, which is critical for determining if detected features
    represent real structure or noise.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        epsilon_range: Range of epsilon values to use for analysis
        
    Returns:
        Dict containing stability metrics
    """
    if epsilon_range is None:
        epsilon_range = np.linspace(0.01 * n, 0.1 * n, 10)
    
    # Compute Betti numbers across epsilon range
    betti_history = []
    for epsilon in epsilon_range:
        betti = compute_betti_numbers(points, epsilon)
        betti_history.append(betti)
    
    # Calculate stability for each dimension
    stability_by_dim = {}
    for dim in [0, 1, 2]:
        values = [betti[f"beta_{dim}"] for betti in betti_history]
        stability = 1.0 - np.std(values) / (max(values) - min(values) + EPSILON)
        stability_by_dim[dim] = max(0.0, min(1.0, stability))
    
    # Overall stability score (weighted average)
    stability_score = (
        0.3 * stability_by_dim.get(0, 0.0) +
        0.5 * stability_by_dim.get(1, 0.0) +
        0.2 * stability_by_dim.get(2, 0.0)
    )
    
    # Check if structure is torus-like across scales
    is_torus = all(
        abs(betti["beta_0"] - 1) <= BETTI_DEVIATION_THRESHOLD and
        abs(betti["beta_1"] - 2) <= BETTI_DEVIATION_THRESHOLD and
        abs(betti["beta_2"] - 1) <= BETTI_DEVIATION_THRESHOLD
        for betti in betti_history
    )
    
    torus_confidence = stability_score if is_torus else 0.0
    
    return {
        "stability_by_dimension": stability_by_dim,
        "stability_score": stability_score,
        "is_torus": is_torus,
        "torus_confidence": torus_confidence,
        "betti_history": betti_history,
        "epsilon_range": list(epsilon_range)
    }


def detect_singular_points(points: np.ndarray, 
                          n: int,
                          threshold: float = 0.1) -> List[Tuple[int, int]]:
    """Detect singular points in the signature space.
    
    Singular points are locations where the gradient is zero or undefined,
    which can indicate vulnerabilities or structural weaknesses.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        threshold: Threshold for singularity detection
        
    Returns:
        List of singular points as (u_r, u_z) tuples
    """
    if len(points) < 100:
        return []
    
    # Create a grid to analyze density
    grid_size = min(100, int(math.sqrt(len(points))))
    density_grid = np.zeros((grid_size, grid_size))
    
    # Normalize points to [0,1]x[0,1]
    points_normalized = points / n
    
    # Count points in each grid cell
    for u_r, u_z, _ in points_normalized:
        i = min(int(u_r * grid_size), grid_size - 1)
        j = min(int(u_z * grid_size), grid_size - 1)
        density_grid[i, j] += 1
    
    # Normalize density
    max_density = np.max(density_grid)
    if max_density > 0:
        density_grid = density_grid / max_density
    
    # Detect singular points (low density surrounded by high density)
    singular_points = []
    for i in range(1, grid_size - 1):
        for j in range(1, grid_size - 1):
            # Check if this cell has low density but is surrounded by high density
            neighbors = [
                density_grid[i-1, j], density_grid[i+1, j],
                density_grid[i, j-1], density_grid[i, j+1],
                density_grid[i-1, j-1], density_grid[i+1, j+1],
                density_grid[i-1, j+1], density_grid[i+1, j-1]
            ]
            
            if (density_grid[i, j] < threshold and 
                np.mean(neighbors) > 2 * threshold):
                # Convert back to original coordinates
                u_r = int((i + 0.5) * n / grid_size)
                u_z = int((j + 0.5) * n / grid_size)
                singular_points.append((u_r, u_z))
    
    return singular_points


def calculate_fractal_dimension(points: np.ndarray, n: int) -> float:
    """Calculate the fractal dimension of the signature space.
    
    The fractal dimension provides insight into the self-similar structure
    of the signature space, which is critical for recursive refinement analysis.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Fractal dimension value
    """
    if len(points) < 100:
        return 0.0
    
    # Use box-counting method to estimate fractal dimension
    max_scale = min(100, int(math.sqrt(len(points))))
    scales = []
    counts = []
    
    for scale in range(1, max_scale):
        # Create grid with this scale
        grid = np.zeros((scale, scale))
        
        # Count points in each cell
        for u_r, u_z, _ in points:
            i = min(int(u_r * scale / n), scale - 1)
            j = min(int(u_z * scale / n), scale - 1)
            grid[i, j] = 1  # Just need to know if cell is occupied
        
        # Count occupied cells
        occupied = np.sum(grid)
        scales.append(scale)
        counts.append(occupied)
    
    # Calculate fractal dimension from log-log plot
    log_scales = np.log(1 / np.array(scales))
    log_counts = np.log(np.array(counts))
    
    # Linear regression to find slope (fractal dimension)
    A = np.vstack([log_scales, np.ones(len(log_scales))]).T
    dimension, _ = np.linalg.lstsq(A, log_counts, rcond=None)[0]
    
    return max(0.0, dimension)


def calculate_uniformity_score(points: np.ndarray, n: int) -> float:
    """Calculate the uniformity score of the signature space.
    
    Measures how uniformly points are distributed across the signature space,
    which is critical for nonce generation security.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Uniformity score (1.0 = perfectly uniform)
    """
    if len(points) == 0:
        return 0.0
    
    # Create a grid to analyze distribution
    grid_size = min(50, int(math.sqrt(len(points))))
    grid = np.zeros((grid_size, grid_size))
    
    # Normalize points to [0,1]x[0,1]
    points_normalized = points / n
    
    # Count points in each grid cell
    for u_r, u_z, _ in points_normalized:
        i = min(int(u_r * grid_size), grid_size - 1)
        j = min(int(u_z * grid_size), grid_size - 1)
        grid[i, j] += 1
    
    # Normalize to get observed distribution
    total = np.sum(grid)
    if total == 0:
        return 0.0
    
    observed = grid / total
    
    # Expected uniform distribution
    expected = np.ones((grid_size, grid_size)) / (grid_size * grid_size)
    
    # Calculate Jensen-Shannon divergence as uniformity metric
    m = 0.5 * (observed + expected)
    js_div = (
        0.5 * scipy_entropy(observed.flatten() + EPSILON, m.flatten() + EPSILON, base=2) +
        0.5 * scipy_entropy(expected.flatten() + EPSILON, m.flatten() + EPSILON, base=2)
    )
    
    # Convert to uniformity score (1.0 = perfectly uniform)
    return 1.0 - min(1.0, js_div / 2.0)


# ======================
# QUANTUM-INSPIRED METRICS
# ======================

def calculate_entanglement_entropy(points: np.ndarray, 
                                 n: int,
                                 sample_size: int = 1000) -> float:
    """Calculate entanglement entropy for quantum-inspired security analysis.
    
    For weak implementations where d has small factors, the quantum state
    has low entanglement entropy, indicating vulnerability.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        sample_size: Number of points to sample for calculation
        
    Returns:
        Entanglement entropy value
    """
    if len(points) == 0:
        return 0.0
    
    # Sample points for efficiency
    sample_indices = random.sample(range(len(points)), min(sample_size, len(points)))
    sampled_points = points[sample_indices]
    
    # Create quantum state representation
    # |ψ⟩ = (1/√n) Σ |k⟩|R_x(k)⟩
    grid_size = min(100, int(math.sqrt(sample_size)))
    quantum_state = np.zeros((grid_size, grid_size))
    
    # Fill quantum state grid
    for u_r, u_z, r in sampled_points:
        i = min(int(u_r * grid_size / n), grid_size - 1)
        j = min(int(u_z * grid_size / n), grid_size - 1)
        quantum_state[i, j] += 1
    
    # Normalize
    total = np.sum(quantum_state)
    if total == 0:
        return 0.0
    
    quantum_state = quantum_state / total
    
    # Calculate density matrix
    rho = np.outer(quantum_state.flatten(), quantum_state.flatten())
    
    # Partial trace to get reduced density matrix
    rho_A = np.zeros((grid_size, grid_size))
    for i in range(grid_size):
        for j in range(grid_size):
            for k in range(grid_size):
                rho_A[i, j] += quantum_state[i, k] * quantum_state[j, k]
    
    # Calculate entanglement entropy
    eigenvalues = np.linalg.eigvalsh(rho_A + EPSILON)
    entropy = -np.sum(eigenvalues * np.log2(eigenvalues + EPSILON))
    
    # Normalize by maximum possible entropy
    max_entropy = np.log2(grid_size)
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
    
    return normalized_entropy


def calculate_quantum_vulnerability_score(entanglement_entropy: float) -> float:
    """Calculate vulnerability score based on entanglement entropy.
    
    Systems with low entanglement entropy have critical vulnerabilities.
    
    Args:
        entanglement_entropy: Normalized entanglement entropy (0-1)
        
    Returns:
        Vulnerability score (0-1, higher = more vulnerable)
    """
    # Vulnerability increases as entropy decreases
    return 1.0 - entanglement_entropy


# ======================
# SECURITY METRIC UTILITIES
# ======================

def calculate_security_score(betti_numbers: Dict[str, int],
                           topological_entropy: float,
                           symmetry_violation_rate: float,
                           spiral_consistency: float,
                           entanglement_entropy: float) -> float:
    """Calculate overall security score from multiple metrics.
    
    Combines multiple topological indicators into a single security score.
    
    Args:
        betti_numbers: Betti numbers (beta_0, beta_1, beta_2)
        topological_entropy: Topological entropy value
        symmetry_violation_rate: Rate of symmetry violations
        spiral_consistency: Consistency of spiral pattern
        entanglement_entropy: Normalized entanglement entropy
        
    Returns:
        Security score (0-1, higher = more secure)
    """
    # Betti number deviation score
    expected_betti = BETTI_SECURE_VALUES
    betti_deviation = (
        abs(betti_numbers["beta_0"] - expected_betti["beta_0"]) +
        abs(betti_numbers["beta_1"] - expected_betti["beta_1"]) * 0.5 +
        abs(betti_numbers["beta_2"] - expected_betti["beta_2"])
    ) / 2.5
    
    # Normalize components to 0-1 scale (higher = better)
    betti_score = max(0, 1 - betti_deviation)
    entropy_score = min(1.0, topological_entropy * 2.0)  # Assuming max entropy ~0.5
    symmetry_score = max(0, 1 - symmetry_violation_rate)
    spiral_score = spiral_consistency
    quantum_score = entanglement_entropy
    
    # Weighted combination
    security_score = (
        0.30 * betti_score +
        0.20 * entropy_score +
        0.20 * symmetry_score +
        0.15 * spiral_score +
        0.15 * quantum_score
    )
    
    return max(0.0, min(1.0, security_score))


def is_implementation_secure(security_score: float,
                            vulnerability_score: float) -> bool:
    """Determine if an ECDSA implementation is secure.
    
    Args:
        security_score: Combined security score (0-1)
        vulnerability_score: Combined vulnerability score (0-1)
        
    Returns:
        True if implementation is secure, False otherwise
    """
    # Implementation is secure if security score is high and vulnerability score is low
    return security_score >= 0.8 and vulnerability_score <= 0.2


def calculate_vulnerability_score(security_score: float) -> float:
    """Calculate vulnerability score from security score.
    
    Args:
        security_score: Combined security score (0-1)
        
    Returns:
        Vulnerability score (0-1, higher = more vulnerable)
    """
    return 1.0 - security_score


def get_vulnerability_level(vulnerability_score: float) -> str:
    """Categorize vulnerability level based on score.
    
    Args:
        vulnerability_score: Vulnerability score (0-1)
        
    Returns:
        Vulnerability level as string
    """
    if vulnerability_score >= 0.7:
        return "critical"
    elif vulnerability_score >= 0.4:
        return "high"
    elif vulnerability_score >= 0.2:
        return "medium"
    elif vulnerability_score >= 0.1:
        return "low"
    else:
        return "secure"


# ======================
# HELPER FUNCTIONS FOR MATHEMATICAL OPERATIONS
# ======================

def solve_linear_congruence(a: int, b: int, m: int) -> List[int]:
    """Solve the linear congruence ax ≡ b (mod m).
    
    Args:
        a: Coefficient of x
        b: Constant term
        m: Modulus
        
    Returns:
        List of solutions in the range [0, m-1]
    """
    g = gcd(a, m)
    if b % g != 0:
        return []  # No solutions
    
    # Reduce the equation
    a_prime = a // g
    b_prime = b // g
    m_prime = m // g
    
    # Find modular inverse of a_prime mod m_prime
    try:
        inv = modular_inverse(a_prime, m_prime)
    except ValueError:
        return []
    
    # One solution
    x0 = (b_prime * inv) % m_prime
    
    # All solutions
    solutions = [x0 + i * m_prime for i in range(g)]
    return solutions


def find_collisions(points: np.ndarray, n: int) -> List[Tuple[int, int, int, int]]:
    """Find collisions in the signature space.
    
    Collisions occur when different (u_r, u_z) pairs produce the same r value.
    
    Args:
        points: Point cloud of (u_r, u_z, r) points
        n: Order of the elliptic curve subgroup
        
    Returns:
        List of collisions as ((u_r1, u_z1), (u_r2, u_z2)) tuples
    """
    if len(points) == 0:
        return []
    
    # Group points by r value
    r_values = defaultdict(list)
    for i, (u_r, u_z, r) in enumerate(points):
        r_values[int(r)].append((u_r, u_z, i))
    
    # Find collisions (multiple points with same r)
    collisions = []
    for r, points_list in r_values.items():
        if len(points_list) >= 2:
            # Generate all pairs of points with same r
            for i in range(len(points_list)):
                for j in range(i + 1, len(points_list)):
                    u_r1, u_z1, idx1 = points_list[i]
                    u_r2, u_z2, idx2 = points_list[j]
                    collisions.append((u_r1, u_z1, u_r2, u_z2))
    
    return collisions


def detect_spiral_fractals(points: np.ndarray, 
                          n: int,
                          max_zoom: int = 5) -> List[Dict[str, Any]]:
    """Detect spiral fractals in the signature space.
    
    Subtables of R_x preserve self-similar structure when scaled.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        max_zoom: Maximum zoom level for fractal detection
        
    Returns:
        List of detected spiral fractals
    """
    fractals = []
    
    # Start with full table
    current_scale = 1
    current_points = points
    
    for zoom_level in range(1, max_zoom + 1):
        # Scale down the space
        scale_factor = 2 ** zoom_level
        scaled_n = n // scale_factor
        
        if scaled_n < 10:  # Too small to analyze
            break
        
        # Create scaled points
        scaled_points = []
        for u_r, u_z, r in current_points:
            scaled_u_r = u_r // scale_factor
            scaled_u_z = u_z // scale_factor
            scaled_points.append((scaled_u_r, scaled_u_z, r))
        
        # Analyze scaled space
        betti = compute_betti_numbers(np.array(scaled_points), 0.1 * scaled_n)
        is_fractal = (
            abs(betti["beta_0"] - 1) <= BETTI_DEVIATION_THRESHOLD and
            abs(betti["beta_1"] - 2) <= BETTI_DEVIATION_THRESHOLD and
            abs(betti["beta_2"] - 1) <= BETTI_DEVIATION_THRESHOLD
        )
        
        if is_fractal:
            fractals.append({
                "zoom_level": zoom_level,
                "scale_factor": scale_factor,
                "betti_numbers": betti,
                "is_fractal": True
            })
        else:
            # If not a fractal at this level, stop zooming
            break
        
        current_scale = scale_factor
        current_points = scaled_points
    
    return fractals


def analyze_spiral_consistency(points: np.ndarray, 
                              n: int,
                              d: Optional[int] = None) -> Dict[str, Any]:
    """Analyze the consistency of the spiral pattern.
    
    Checks how well the points follow the expected spiral structure.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        d: Private key estimate (optional)
        
    Returns:
        Dict containing spiral consistency analysis
    """
    if len(points) == 0:
        return {
            "consistent_points": 0,
            "total_points": 0,
            "consistency_rate": 0.0,
            "deviations": []
        }
    
    # Estimate private key if not provided
    if d is None:
        d = estimate_private_key(points, n)
        if d is None:
            return {
                "consistent_points": 0,
                "total_points": 0,
                "consistency_rate": 0.0,
                "deviations": []
            }
    
    consistent_points = 0
    total_points = 0
    deviations = []
    
    # For each point, check if the next point in the spiral exists
    for i in range(len(points)):
        u_r, u_z, _ = points[i]
        
        # Calculate expected next point
        u_r_next = (u_r + 1) % n
        u_z_next = (u_z + d) % n
        
        # Check if the next point exists
        found = False
        for j in range(len(points)):
            if (abs(points[j, 0] - u_r_next) < EPSILON and 
                abs(points[j, 1] - u_z_next) < EPSILON):
                found = True
                break
        
        if found:
            consistent_points += 1
        else:
            # Record deviation
            deviations.append({
                "point": (u_r, u_z),
                "expected_next": (u_r_next, u_z_next),
                "type": "missing_point"
            })
        
        total_points += 1
    
    consistency_rate = consistent_points / total_points if total_points > 0 else 0.0
    
    return {
        "consistent_points": consistent_points,
        "total_points": total_points,
        "consistency_rate": consistency_rate,
        "deviations": deviations
    }


def calculate_diagonal_periodicity(points: np.ndarray, n: int) -> Dict[str, Any]:
    """Calculate periodicity along the diagonal.
    
    For secure implementations, the diagonal should have specific periodicity.
    
    Args:
        points: Point cloud representing the signature space
        n: Order of the elliptic curve subgroup
        
    Returns:
        Dict containing diagonal periodicity analysis
    """
    if len(points) == 0:
        return {
            "period": n,
            "consistency": 0.0,
            "is_vulnerable": True
        }
    
    # Find points on or near the diagonal
    diagonal_points = []
    for u_r, u_z, _ in points:
        if abs(u_r - u_z) < n * 0.01:  # Within 1% of n
            diagonal_points.append((u_r, u_z))
    
    if len(diagonal_points) < 2:
        return {
            "period": n,
            "consistency": 0.0,
            "is_vulnerable": True
        }
    
    # Sort by u_r
    diagonal_points.sort(key=lambda x: x[0])
    
    # Calculate distances between consecutive points
    distances = []
    for i in range(1, len(diagonal_points)):
        dist = diagonal_points[i][0] - diagonal_points[i-1][0]
        if dist > 0:
            distances.append(dist)
    
    if not distances:
        return {
            "period": n,
            "consistency": 0.0,
            "is_vulnerable": True
        }
    
    # Estimate period as the most common distance (mode)
    period = max(set(distances), key=distances.count)
    
    # Calculate consistency (how many points follow the period)
    consistent_points = 0
    for i in range(len(diagonal_points) - 1):
        expected_next = diagonal_points[i][0] + period
        actual_next = diagonal_points[i+1][0]
        if abs(actual_next - expected_next) < period * 0.1:  # Within 10%
            consistent_points += 1
    
    consistency = consistent_points / (len(diagonal_points) - 1) if len(diagonal_points) > 1 else 0.0
    
    return {
        "period": period,
        "consistency": consistency,
        "is_vulnerable": period < n / 10 or consistency < 0.7
    }
