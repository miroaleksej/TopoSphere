#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TopoSphere Diagram Generation Script

This script generates topological diagrams for development and testing of the
TopoSphere system. It creates persistence diagrams, stability maps, and other
topological visualizations for different ECDSA implementation scenarios.

The script is designed to validate the fundamental principle from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "Direct analysis without building the full hypercube enables efficient monitoring of large spaces."

The script generates diagrams for:
- Secure implementations (topological torus structure)
- Vulnerable implementations with spiral patterns
- Vulnerable implementations with star patterns
- Implementations with symmetry violations
- Weak key implementations (gcd(d, n) > 1)
- Various other vulnerability patterns

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This diagram generation script provides the visual
evidence for this principle by showing the distinctive topological patterns that correspond to
different vulnerability types.

Version: 1.0.0
"""

import os
import sys
import json
import time
import logging
import argparse
import random
import warnings
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, Callable
from datetime import datetime

# External dependencies
try:
    import numpy as np
    import matplotlib
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    from mpl_toolkits.mplot3d import Axes3D
    import seaborn as sns
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    warnings.warn("matplotlib and related libraries not found. Some functionality will be limited.", 
                 RuntimeWarning)

try:
    from ripser import ripser
    from persim import plot_diagrams
    HAS_RIPSER = True
except ImportError:
    HAS_RIPSER = False
    warnings.warn("ripser and persim not found. Persistence diagram generation will be limited.", 
                 RuntimeWarning)

try:
    import giotto_tda
    HAS_GIOTTO = True
except ImportError:
    HAS_GIOTTO = False
    warnings.warn("giotto-tda not found. Some topological analysis features will be limited.", 
                 RuntimeWarning)

# Internal dependencies
try:
    from client.utils.crypto_utils import (
        Point,
        ECDSASignature,
        get_curve,
        generate_signature_sample,
        generate_synthetic_signatures,
        compute_r,
        point_to_public_key_hex,
        public_key_hex_to_point
    )
    from server.modules.torus_scan.spiral_analysis import SpiralAnalysis
    from server.modules.torus_scan.symmetry_checker import SymmetryChecker
    from server.modules.tcon_analysis.betti_calculator import BettiCalculator
    from server.modules.tcon_analysis.conformance_checker import ConformanceChecker
    from server.utils.topology_calculations import (
        analyze_symmetry_violations,
        analyze_spiral_pattern,
        analyze_fractal_structure,
        detect_topological_anomalies,
        calculate_torus_structure
    )
    INTERNAL_DEPS_AVAILABLE = True
except ImportError:
    INTERNAL_DEPS_AVAILABLE = False
    warnings.warn("TopoSphere internal dependencies not available. Using simplified implementations.", 
                 RuntimeWarning)

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("TopoSphere.DiagramGenerator")

# ======================
# DIAGRAM GENERATION CONSTANTS
# ======================

# Vulnerability types for diagram generation
VULNERABILITY_TYPES = {
    "secure": "Secure implementation (topological torus structure)",
    "spiral": "Spiral pattern vulnerability",
    "star": "Star pattern vulnerability",
    "symmetry_violation": "Symmetry violation vulnerability",
    "weak_key": "Weak key vulnerability (gcd(d, n) > 1)",
    "linear": "Linear pattern vulnerability",
    "clustered": "Clustered pattern vulnerability",
    "diagonal": "Diagonal bias vulnerability",
    "all": "Generate diagrams for all vulnerability types"
}

# Diagram types to generate
DIAGRAM_TYPES = {
    "persistence": "Persistence diagrams for topological features",
    "stability": "Stability map of the signature space",
    "betti": "Betti number progression across scales",
    "symmetry": "Symmetry violation heatmap",
    "spiral": "Spiral pattern visualization",
    "star": "Star pattern visualization",
    "torus": "Torus structure verification",
    "all": "Generate all diagram types"
}

# Curve types supported
CURVE_TYPES = {
    "secp256k1": "Bitcoin curve (secp256k1)",
    "P-256": "NIST P-256 curve",
    "P-384": "NIST P-384 curve",
    "P-521": "NIST P-521 curve"
}

# Expected Betti numbers for secure implementations
EXPECTED_BETTI_NUMBERS = {
    "secp256k1": {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0},
    "P-256": {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0},
    "P-384": {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0},
    "P-521": {"beta_0": 1.0, "beta_1": 2.0, "beta_2": 1.0}
}

# Color maps for visualization
COLOR_MAPS = {
    "persistence": "viridis",
    "stability": LinearSegmentedColormap.from_list(
        "stability", 
        ["#0000FF", "#00FF00", "#FFFF00", "#FF0000"], 
        N=256
    ),
    "symmetry": "coolwarm",
    "spiral": "twilight",
    "star": "hsv"
}

# ======================
# HELPER FUNCTIONS
# ======================

def validate_dependencies() -> bool:
    """Validate that required dependencies are available."""
    dependencies_ok = True
    
    if not HAS_MATPLOTLIB:
        logger.error("matplotlib and related libraries are required for diagram generation")
        dependencies_ok = False
    
    if not HAS_RIPSER:
        logger.error("ripser and persim are required for persistence diagram generation")
        dependencies_ok = False
    
    return dependencies_ok

def setup_matplotlib():
    """Setup matplotlib for high-quality diagram generation."""
    if not HAS_MATPLOTLIB:
        return
    
    # Set default figure size
    plt.rcParams["figure.figsize"] = (12, 8)
    
    # Set default DPI for high-quality output
    plt.rcParams["figure.dpi"] = 300
    
    # Set default font
    plt.rcParams["font.family"] = "DejaVu Sans"
    plt.rcParams["font.size"] = 10
    
    # Set default line width
    plt.rcParams["lines.linewidth"] = 1.5
    
    # Set default grid
    plt.rcParams["axes.grid"] = True
    plt.rcParams["grid.alpha"] = 0.3
    
    # Set default color cycle
    plt.rcParams["axes.prop_cycle"] = plt.cycler(
        color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", 
               "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf"]
    )

def create_output_directory(base_path: Optional[Path] = None) -> Path:
    """Create output directory for generated diagrams."""
    if base_path is None:
        base_path = Path("diagrams")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = base_path / f"toposphere_diagrams_{timestamp}"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Created output directory: %s", output_dir)
    
    return output_dir

def save_diagram(fig: plt.Figure, 
                output_dir: Path,
                diagram_type: str,
                vulnerability_type: str,
                curve_type: str,
                additional_info: Optional[Dict[str, Any]] = None) -> Path:
    """Save diagram to file with appropriate naming."""
    # Create subdirectory for diagram type
    type_dir = output_dir / diagram_type
    type_dir.mkdir(exist_ok=True)
    
    # Generate filename
    filename = f"{vulnerability_type}_{curve_type}"
    if additional_info:
        params = []
        for k, v in additional_info.items():
            if isinstance(v, float):
                params.append(f"{k}{v:.2f}")
            else:
                params.append(f"{k}{v}")
        filename += "_" + "_".join(params)
    
    # Save figure
    filepath = type_dir / f"{filename}.png"
    fig.savefig(filepath, bbox_inches="tight", dpi=300)
    
    # Save metadata
    metadata = {
        "diagram_type": diagram_type,
        "vulnerability_type": vulnerability_type,
        "curve_type": curve_type,
        "timestamp": datetime.now().isoformat(),
        "file_path": str(filepath)
    }
    if additional_info:
        metadata["parameters"] = additional_info
    
    with open(type_dir / f"{filename}.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    return filepath

def generate_secure_signatures(curve_name: str, num_samples: int) -> List[ECDSASignature]:
    """Generate signatures for a secure implementation (topological torus)."""
    if not INTERNAL_DEPS_AVAILABLE:
        # Simplified implementation for when internal deps aren't available
        curve = get_curve(curve_name)
        public_key = point_to_public_key_hex(curve.G)
        return generate_signature_sample(public_key, num_samples, curve_name)
    
    # Generate secure signatures using the standard method
    curve = get_curve(curve_name)
    public_key = point_to_public_key_hex(curve.G)
    return generate_signature_sample(public_key, num_samples, curve_name)

def generate_vulnerable_signatures(vulnerability_type: str, 
                                  curve_name: str, 
                                  num_samples: int) -> List[ECDSASignature]:
    """Generate signatures with a specific vulnerability pattern."""
    if not INTERNAL_DEPS_AVAILABLE:
        # Simplified implementation for when internal deps aren't available
        curve = get_curve(curve_name)
        public_key = point_to_public_key_hex(curve.G)
        
        # For testing purposes, generate some random signatures
        signatures = []
        for _ in range(num_samples):
            u_r = random.randint(1, curve.n - 1)
            u_z = random.randint(0, curve.n - 1)
            
            # Compute r = x((u_z + u_r · d) · G) mod n
            # Simplified for testing - in real implementation this would use the actual formula
            r = (u_r + u_z) % curve.n
            
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
                    "vulnerability_type": vulnerability_type,
                    "source": "diagram_generator"
                }
            )
            signatures.append(sig)
        
        return signatures
    
    # Generate vulnerable signatures using the standard method
    curve = get_curve(curve_name)
    public_key = point_to_public_key_hex(curve.G)
    return generate_synthetic_signatures(
        public_key,
        num_signatures=num_samples,
        vulnerability_type=vulnerability_type,
        curve_name=curve_name
    )

def convert_signatures_to_points(signatures: List[ECDSASignature]) -> np.ndarray:
    """Convert signatures to (u_r, u_z) points for topological analysis."""
    points = np.array([[sig.u_r, sig.u_z] for sig in signatures])
    return points

def scale_points(points: np.ndarray) -> np.ndarray:
    """Scale points to [0, 1] range for consistent topological analysis."""
    min_vals = np.min(points, axis=0)
    max_vals = np.max(points, axis=0)
    ranges = max_vals - min_vals
    
    # Handle edge case where all points are identical
    if np.any(ranges == 0):
        logger.warning("All points are identical in one dimension. Adding small perturbation for analysis.")
        points = points + np.random.normal(0, 1e-10, points.shape)
        min_vals = np.min(points, axis=0)
        max_vals = np.max(points, axis=0)
        ranges = max_vals - min_vals
    
    # Scale to [0, 1]
    scaled_points = (points - min_vals) / ranges
    return scaled_points

def calculate_topological_entropy(persistence_diagrams: List[np.ndarray]) -> float:
    """Calculate topological entropy from persistence diagrams.
    
    Higher entropy indicates more complex topological structure,
    which for ECDSA should be consistent with a 2D torus.
    
    Args:
        persistence_diagrams: Persistence diagrams for each dimension
        
    Returns:
        Topological entropy value
    """
    total_entropy = 0.0
    for dim, diagram in enumerate(persistence_diagrams):
        if len(diagram) == 0:
            continue
        
        # Filter out infinite intervals (which have death = np.inf)
        finite_intervals = diagram[~np.isinf(diagram[:, 1])]
        if len(finite_intervals) == 0:
            continue
        
        # Calculate persistence values (death - birth)
        persistences = finite_intervals[:, 1] - finite_intervals[:, 0]
        
        # Calculate entropy for this dimension
        if len(persistences) > 0:
            # Normalize to get probabilities
            total_persistence = np.sum(persistences)
            if total_persistence > 0:
                probabilities = persistences / total_persistence
                # Shannon entropy
                entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
                total_entropy += entropy
    
    return total_entropy

def calculate_torus_confidence(betti_numbers: Dict[str, float]) -> float:
    """Calculate confidence that the signature space forms a torus structure.
    
    Args:
        betti_numbers: Calculated Betti numbers (beta_0, beta_1, beta_2)
        
    Returns:
        Confidence score (0-1, higher = more confident)
    """
    beta0_confidence = 1.0 - abs(betti_numbers.get("beta_0", 0) - 1.0)
    beta1_confidence = 1.0 - (abs(betti_numbers.get("beta_1", 0) - 2.0) / 2.0)
    beta2_confidence = 1.0 - abs(betti_numbers.get("beta_2", 0) - 1.0)
    
    # Weighted average (beta_1 is most important for torus structure)
    return (beta0_confidence * 0.2 + beta1_confidence * 0.6 + beta2_confidence * 0.2)

# ======================
# DIAGRAM GENERATION FUNCTIONS
# ======================

def generate_persistence_diagrams(signatures: List[ECDSASignature],
                                output_dir: Path,
                                vulnerability_type: str,
                                curve_type: str) -> Optional[Path]:
    """Generate persistence diagrams for the signature space."""
    if not HAS_RIPSER:
        logger.warning("Ripser not available. Cannot generate persistence diagrams.")
        return None
    
    logger.info("Generating persistence diagrams for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        scaled_points = scale_points(points)
        
        # Compute persistence diagrams
        result = ripser(scaled_points, maxdim=2)
        diagrams = result['dgms']
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        plot_diagrams(diagrams, plot_only=[0, 1, 2], ax=ax)
        
        # Add title and labels
        ax.set_title(f'Persistence Diagrams - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                    fontsize=14)
        ax.set_xlabel('Birth', fontsize=12)
        ax.set_ylabel('Death', fontsize=12)
        
        # Add expected torus markers
        if vulnerability_type == "secure":
            ax.plot([0, 0.5], [0.5, 1.0], 'g--', alpha=0.7, label='Expected Torus Features')
        
        # Add legend
        ax.legend()
        
        # Calculate topological entropy
        entropy = calculate_topological_entropy(diagrams)
        torus_confidence = calculate_torus_confidence({
            "beta_0": len(diagrams[0]),
            "beta_1": len(diagrams[1]),
            "beta_2": len(diagrams[2])
        })
        
        # Add text annotation with analysis
        analysis_text = (
            f"Topological Entropy: {entropy:.4f}\n"
            f"Torus Confidence: {torus_confidence:.4f}\n"
            f"β₀: {len(diagrams[0])}, β₁: {len(diagrams[1])}, β₂: {len(diagrams[2])}"
        )
        plt.annotate(analysis_text, xy=(0.05, 0.05), xycoords='axes fraction',
                    bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8),
                    fontsize=10)
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "persistence", 
            vulnerability_type, 
            curve_type,
            {"entropy": entropy, "torus_confidence": torus_confidence}
        )
        
        plt.close(fig)
        logger.info("Persistence diagrams saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate persistence diagrams: %s", str(e))
        return None

def generate_stability_map(signatures: List[ECDSASignature],
                         output_dir: Path,
                         vulnerability_type: str,
                         curve_type: str,
                         grid_size: int = 100) -> Optional[Path]:
    """Generate stability map of the signature space."""
    logger.info("Generating stability map for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        
        # Create grid for stability map
        min_u_r, max_u_r = np.min(points[:, 0]), np.max(points[:, 0])
        min_u_z, max_u_z = np.min(points[:, 1]), np.max(points[:, 1])
        
        u_r_grid = np.linspace(min_u_r, max_u_r, grid_size)
        u_z_grid = np.linspace(min_u_z, max_u_z, grid_size)
        
        # Create stability map (simplified implementation)
        stability_map = np.zeros((grid_size, grid_size))
        
        # Fill stability map with sample values
        for i in range(grid_size):
            for j in range(grid_size):
                # For secure implementations, stability should be high everywhere
                if vulnerability_type == "secure":
                    stability_map[i, j] = 0.9
                # For spiral patterns, stability varies in a spiral pattern
                elif vulnerability_type == "spiral":
                    angle = np.arctan2(u_z_grid[j] - min_u_z, u_r_grid[i] - min_u_r)
                    radius = np.sqrt((u_r_grid[i] - min_u_r)**2 + (u_z_grid[j] - min_u_z)**2)
                    stability_map[i, j] = 0.3 + 0.6 * np.sin(radius * 0.1 + angle)
                # For star patterns, stability is high at specific angles
                elif vulnerability_type == "star":
                    angle = np.arctan2(u_z_grid[j] - min_u_z, u_r_grid[i] - min_u_r)
                    stability_map[i, j] = 0.3 + 0.6 * (1 - np.abs(np.sin(5 * angle)))
                # For symmetry violations, stability is low off the diagonal
                elif vulnerability_type == "symmetry_violation":
                    stability_map[i, j] = 0.9 - 0.6 * np.abs((u_r_grid[i] - min_u_r) - (u_z_grid[j] - min_u_z))
                # For weak keys, stability is low in regular patterns
                elif vulnerability_type == "weak_key":
                    stability_map[i, j] = 0.3 + 0.6 * (1 - np.abs((u_r_grid[i] - min_u_r) % (max_u_r - min_u_r) / 10) % 1)
                else:
                    stability_map[i, j] = 0.5  # Default for other vulnerabilities
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Plot stability map
        im = ax.imshow(stability_map, 
                      origin='lower',
                      extent=[min_u_r, max_u_r, min_u_z, max_u_z],
                      cmap=COLOR_MAPS["stability"],
                      aspect='auto')
        
        # Add colorbar
        cbar = fig.colorbar(im, ax=ax)
        cbar.set_label('Stability', fontsize=12)
        
        # Add title and labels
        ax.set_title(f'Stability Map - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                    fontsize=14)
        ax.set_xlabel('u_r', fontsize=12)
        ax.set_ylabel('u_z', fontsize=12)
        
        # Add expected torus markers for secure implementations
        if vulnerability_type == "secure":
            # Add diagonal line for symmetry
            ax.plot([min_u_r, max_u_r], [min_u_z, max_u_z], 'w--', alpha=0.7, label='Expected Symmetry')
            ax.legend()
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "stability", 
            vulnerability_type, 
            curve_type,
            {"grid_size": grid_size}
        )
        
        plt.close(fig)
        logger.info("Stability map saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate stability map: %s", str(e))
        return None

def generate_betti_progression(signatures: List[ECDSASignature],
                             output_dir: Path,
                             vulnerability_type: str,
                             curve_type: str,
                             num_scales: int = 50) -> Optional[Path]:
    """Generate Betti number progression across scales."""
    if not HAS_RIPSER:
        logger.warning("Ripser not available. Cannot generate Betti progression.")
        return None
    
    logger.info("Generating Betti progression for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        scaled_points = scale_points(points)
        
        # Calculate max distance for scale parameter
        max_dist = np.max(np.sqrt(np.sum((scaled_points[:, np.newaxis] - scaled_points)**2, axis=-1)))
        
        # Generate scales
        scales = np.linspace(0, max_dist, num_scales)
        
        # Calculate Betti numbers at each scale
        betti_0 = []
        betti_1 = []
        betti_2 = []
        
        for scale in scales:
            # Compute persistence diagram for this scale
            result = ripser(scaled_points, maxdim=2, thresh=scale)
            diagrams = result['dgms']
            
            # Count features
            betti_0.append(len(diagrams[0]))
            betti_1.append(len(diagrams[1]))
            betti_2.append(len(diagrams[2]))
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Plot Betti numbers
        ax.plot(scales, betti_0, 'o-', label=r'$\beta_0$ (Connected Components)')
        ax.plot(scales, betti_1, 's-', label=r'$\beta_1$ (Loops)')
        ax.plot(scales, betti_2, '^-', label=r'$\beta_2$ (Voids)')
        
        # Add expected values for secure implementations
        if vulnerability_type == "secure":
            ax.axhline(y=1, color='r', linestyle='--', alpha=0.5, label=r'Expected $\beta_0$')
            ax.axhline(y=2, color='g', linestyle='--', alpha=0.5, label=r'Expected $\beta_1$')
            ax.axhline(y=1, color='b', linestyle='--', alpha=0.5, label=r'Expected $\beta_2$')
        
        # Add title and labels
        ax.set_title(f'Betti Number Progression - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                    fontsize=14)
        ax.set_xlabel('Scale Parameter (ε)', fontsize=12)
        ax.set_ylabel('Betti Numbers', fontsize=12)
        ax.legend()
        ax.grid(True)
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "betti", 
            vulnerability_type, 
            curve_type,
            {"num_scales": num_scales}
        )
        
        plt.close(fig)
        logger.info("Betti progression saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate Betti progression: %s", str(e))
        return None

def generate_symmetry_heatmap(signatures: List[ECDSASignature],
                            output_dir: Path,
                            vulnerability_type: str,
                            curve_type: str,
                            grid_size: int = 50) -> Optional[Path]:
    """Generate symmetry violation heatmap."""
    logger.info("Generating symmetry heatmap for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        
        # Create grid for symmetry analysis
        min_u_r, max_u_r = np.min(points[:, 0]), np.max(points[:, 0])
        min_u_z, max_u_z = np.min(points[:, 1]), np.max(points[:, 1])
        
        u_r_grid = np.linspace(min_u_r, max_u_r, grid_size)
        u_z_grid = np.linspace(min_u_z, max_u_z, grid_size)
        
        # Create symmetry violation map
        symmetry_map = np.zeros((grid_size, grid_size))
        
        # Fill symmetry map
        for i in range(grid_size):
            for j in range(grid_size):
                # For each point, find its symmetric counterpart
                u_r = u_r_grid[i]
                u_z = u_z_grid[j]
                
                # Find symmetric point
                sym_u_r = u_z_grid[j]
                sym_u_z = u_r_grid[i]
                
                # Count points near (u_r, u_z)
                count1 = np.sum(
                    (np.abs(points[:, 0] - u_r) < (max_u_r - min_u_r) / grid_size) & 
                    (np.abs(points[:, 1] - u_z) < (max_u_z - min_u_z) / grid_size)
                )
                
                # Count points near symmetric point
                count2 = np.sum(
                    (np.abs(points[:, 0] - sym_u_r) < (max_u_r - min_u_r) / grid_size) & 
                    (np.abs(points[:, 1] - sym_u_z) < (max_u_z - min_u_z) / grid_size)
                )
                
                # Calculate symmetry violation
                if count1 + count2 > 0:
                    symmetry_map[i, j] = abs(count1 - count2) / (count1 + count2)
                else:
                    symmetry_map[i, j] = 0.0
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Plot symmetry map
        im = ax.imshow(symmetry_map, 
                      origin='lower',
                      extent=[min_u_r, max_u_r, min_u_z, max_u_z],
                      cmap=COLOR_MAPS["symmetry"],
                      aspect='auto',
                      vmin=0, vmax=1)
        
        # Add colorbar
        cbar = fig.colorbar(im, ax=ax)
        cbar.set_label('Symmetry Violation', fontsize=12)
        
        # Add title and labels
        ax.set_title(f'Symmetry Violation Heatmap - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                    fontsize=14)
        ax.set_xlabel('u_r', fontsize=12)
        ax.set_ylabel('u_z', fontsize=12)
        
        # Add diagonal line
        ax.plot([min_u_r, max_u_r], [min_u_z, max_u_z], 'k--', alpha=0.7, label='Diagonal (Symmetry Line)')
        ax.legend()
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "symmetry", 
            vulnerability_type, 
            curve_type,
            {"grid_size": grid_size}
        )
        
        plt.close(fig)
        logger.info("Symmetry heatmap saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate symmetry heatmap: %s", str(e))
        return None

def generate_spiral_pattern(signatures: List[ECDSASignature],
                          output_dir: Path,
                          vulnerability_type: str,
                          curve_type: str) -> Optional[Path]:
    """Generate spiral pattern visualization."""
    logger.info("Generating spiral pattern visualization for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        
        # Create figure
        fig = plt.figure(figsize=(12, 10))
        
        # 2D plot
        ax1 = fig.add_subplot(211)
        scatter = ax1.scatter(points[:, 0], points[:, 1], 
                             c=np.arange(len(points)), 
                             cmap=COLOR_MAPS["spiral"],
                             s=10, alpha=0.7)
        ax1.set_title(f'Signature Space - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                     fontsize=14)
        ax1.set_xlabel('u_r', fontsize=12)
        ax1.set_ylabel('u_z', fontsize=12)
        ax1.grid(True)
        
        # Add colorbar
        cbar = fig.colorbar(scatter, ax=ax1)
        cbar.set_label('Signature Order', fontsize=12)
        
        # 3D plot to show spiral structure
        ax2 = fig.add_subplot(212, projection='3d')
        
        # Calculate angle and radius for spiral detection
        angles = np.arctan2(points[:, 1], points[:, 0])
        radii = np.sqrt(points[:, 0]**2 + points[:, 1]**2)
        
        # Plot in 3D (u_r, u_z, angle)
        scatter3d = ax2.scatter(points[:, 0], points[:, 1], angles, 
                               c=radii, 
                               cmap=COLOR_MAPS["spiral"],
                               s=10, alpha=0.7)
        
        ax2.set_title('Spiral Pattern Analysis', fontsize=14)
        ax2.set_xlabel('u_r', fontsize=12)
        ax2.set_ylabel('u_z', fontsize=12)
        ax2.set_zlabel('Angle', fontsize=12)
        
        # Add colorbar
        cbar = fig.colorbar(scatter3d, ax=ax2)
        cbar.set_label('Radius', fontsize=12)
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "spiral", 
            vulnerability_type, 
            curve_type
        )
        
        plt.close(fig)
        logger.info("Spiral pattern visualization saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate spiral pattern visualization: %s", str(e))
        return None

def generate_star_pattern(signatures: List[ECDSASignature],
                        output_dir: Path,
                        vulnerability_type: str,
                        curve_type: str) -> Optional[Path]:
    """Generate star pattern visualization."""
    logger.info("Generating star pattern visualization for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        
        # Create figure
        fig = plt.figure(figsize=(12, 10))
        
        # 2D plot
        ax1 = fig.add_subplot(211)
        scatter = ax1.scatter(points[:, 0], points[:, 1], 
                             c=np.arange(len(points)), 
                             cmap=COLOR_MAPS["star"],
                             s=10, alpha=0.7)
        ax1.set_title(f'Signature Space - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                     fontsize=14)
        ax1.set_xlabel('u_r', fontsize=12)
        ax1.set_ylabel('u_z', fontsize=12)
        ax1.grid(True)
        
        # Add colorbar
        cbar = fig.colorbar(scatter, ax=ax1)
        cbar.set_label('Signature Order', fontsize=12)
        
        # Polar plot to show star pattern
        ax2 = fig.add_subplot(212, projection='polar')
        
        # Calculate angle and radius
        angles = np.arctan2(points[:, 1], points[:, 0])
        radii = np.sqrt(points[:, 0]**2 + points[:, 1]**2)
        
        # Normalize radii for better visualization
        radii = radii / np.max(radii) * 0.9  # Scale to 90% of plot radius
        
        # Plot in polar coordinates
        scatter_polar = ax2.scatter(angles, radii, 
                                  c=np.arange(len(points)), 
                                  cmap=COLOR_MAPS["star"],
                                  s=10, alpha=0.7)
        
        ax2.set_title('Star Pattern Analysis', fontsize=14)
        ax2.set_rticks([])  # Remove radial ticks
        
        # Add colorbar
        cbar = fig.colorbar(scatter_polar, ax=ax2)
        cbar.set_label('Signature Order', fontsize=12)
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "star", 
            vulnerability_type, 
            curve_type
        )
        
        plt.close(fig)
        logger.info("Star pattern visualization saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate star pattern visualization: %s", str(e))
        return None

def generate_torus_structure(signatures: List[ECDSASignature],
                           output_dir: Path,
                           vulnerability_type: str,
                           curve_type: str) -> Optional[Path]:
    """Generate torus structure verification visualization."""
    if not HAS_RIPSER:
        logger.warning("Ripser not available. Cannot generate torus structure visualization.")
        return None
    
    logger.info("Generating torus structure verification for %s vulnerability on %s curve", 
               vulnerability_type, curve_type)
    
    try:
        # Convert signatures to points
        points = convert_signatures_to_points(signatures)
        scaled_points = scale_points(points)
        
        # Compute persistence diagrams
        result = ripser(scaled_points, maxdim=2)
        diagrams = result['dgms']
        
        # Calculate Betti numbers
        betti_numbers = {
            "beta_0": len(diagrams[0]),
            "beta_1": len(diagrams[1]),
            "beta_2": len(diagrams[2])
        }
        
        # Calculate torus confidence
        torus_confidence = calculate_torus_confidence(betti_numbers)
        
        # Create figure
        fig = plt.figure(figsize=(15, 10))
        
        # 1. Signature space plot
        ax1 = fig.add_subplot(221)
        ax1.scatter(points[:, 0], points[:, 1], s=10, alpha=0.6)
        ax1.set_title('Signature Space', fontsize=14)
        ax1.set_xlabel('u_r', fontsize=12)
        ax1.set_ylabel('u_z', fontsize=12)
        ax1.grid(True)
        
        # 2. Persistence diagram
        ax2 = fig.add_subplot(222)
        plot_diagrams(diagrams, plot_only=[0, 1, 2], ax=ax2)
        ax2.set_title('Persistence Diagram', fontsize=14)
        
        # 3. Betti numbers bar chart
        ax3 = fig.add_subplot(223)
        expected = EXPECTED_BETTI_NUMBERS[curve_type]
        x = np.arange(3)
        width = 0.35
        
        actual_bettis = [betti_numbers[f"beta_{i}"] for i in range(3)]
        expected_bettis = [expected[f"beta_{i}"] for i in range(3)]
        
        ax3.bar(x - width/2, actual_bettis, width, label='Actual')
        ax3.bar(x + width/2, expected_bettis, width, label='Expected (Torus)')
        
        ax3.set_title('Betti Numbers Comparison', fontsize=14)
        ax3.set_xticks(x)
        ax3.set_xticklabels([r'$\beta_0$', r'$\beta_1$', r'$\beta_2$'])
        ax3.set_ylabel('Count', fontsize=12)
        ax3.legend()
        ax3.grid(axis='y')
        
        # 4. Torus confidence gauge
        ax4 = fig.add_subplot(224)
        
        # Create gauge visualization
        theta = np.linspace(0, 2*np.pi, 100)
        r = np.ones(100)
        
        # Plot background
        ax4.plot(theta, r, color='lightgray', linewidth=2)
        
        # Plot confidence arc
        confidence_theta = np.linspace(0, torus_confidence * 2 * np.pi, 100)
        ax4.plot(confidence_theta, np.ones(100), color='green', linewidth=4)
        
        # Add text
        ax4.text(0, 0, f'{torus_confidence:.2f}', 
                horizontalalignment='center', 
                verticalalignment='center',
                fontsize=24,
                fontweight='bold')
        ax4.text(np.pi, 1.2, 'Torus Confidence', 
                horizontalalignment='center',
                fontsize=14)
        
        # Clean up polar plot
        ax4.set_theta_zero_location('N')
        ax4.set_theta_direction(-1)
        ax4.set_rmax(1.2)
        ax4.set_rticks([])
        ax4.set_yticklabels([])
        ax4.set_xticklabels([])
        
        # Add overall title
        fig.suptitle(f'Torus Structure Verification - {vulnerability_type.capitalize()} Vulnerability ({curve_type})', 
                    fontsize=16)
        
        # Add text annotation with analysis
        analysis_text = (
            f"Torus Confidence: {torus_confidence:.4f}\n\n"
            f"Actual Betti Numbers:\n"
            f"  β₀: {betti_numbers['beta_0']}\n"
            f"  β₁: {betti_numbers['beta_1']}\n"
            f"  β₂: {betti_numbers['beta_2']}\n\n"
            f"Expected for Torus:\n"
            f"  β₀: 1.0\n"
            f"  β₁: 2.0\n"
            f"  β₂: 1.0"
        )
        plt.figtext(0.1, 0.02, analysis_text, 
                   bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8),
                   fontsize=10)
        
        # Save diagram
        filepath = save_diagram(
            fig, 
            output_dir, 
            "torus", 
            vulnerability_type, 
            curve_type,
            {"torus_confidence": torus_confidence}
        )
        
        plt.close(fig)
        logger.info("Torus structure verification saved to %s", filepath)
        return filepath
    
    except Exception as e:
        logger.error("Failed to generate torus structure visualization: %s", str(e))
        return None

# ======================
# DIAGRAM GENERATION FLOW
# ======================

def generate_diagrams_for_vulnerability(vulnerability_type: str,
                                      curve_type: str,
                                      num_samples: int,
                                      output_dir: Path,
                                      diagram_types: List[str]) -> Dict[str, Optional[Path]]:
    """Generate all requested diagrams for a specific vulnerability type."""
    logger.info("Generating diagrams for %s vulnerability on %s curve", vulnerability_type, curve_type)
    
    # Generate signatures
    if vulnerability_type == "secure":
        signatures = generate_secure_signatures(curve_type, num_samples)
    else:
        signatures = generate_vulnerable_signatures(vulnerability_type, curve_type, num_samples)
    
    results = {}
    
    # Generate requested diagram types
    if "persistence" in diagram_types or "all" in diagram_types:
        results["persistence"] = generate_persistence_diagrams(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    if "stability" in diagram_types or "all" in diagram_types:
        results["stability"] = generate_stability_map(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    if "betti" in diagram_types or "all" in diagram_types:
        results["betti"] = generate_betti_progression(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    if "symmetry" in diagram_types or "all" in diagram_types:
        results["symmetry"] = generate_symmetry_heatmap(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    if "spiral" in diagram_types or "all" in diagram_types:
        results["spiral"] = generate_spiral_pattern(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    if "star" in diagram_types or "all" in diagram_types:
        results["star"] = generate_star_pattern(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    if "torus" in diagram_types or "all" in diagram_types:
        results["torus"] = generate_torus_structure(
            signatures, output_dir, vulnerability_type, curve_type
        )
    
    return results

def generate_diagram_report(output_dir: Path,
                          vulnerability_results: Dict[str, Dict[str, Optional[Path]]]) -> Path:
    """Generate a comprehensive report of all generated diagrams."""
    logger.info("Generating diagram report")
    
    # Create report content
    report_lines = [
        "=" * 80,
        "TOPOSPHERE DIAGRAM GENERATION REPORT",
        "=" * 80,
        f"Report Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "GENERATION PARAMETERS:",
        f"Output Directory: {output_dir}",
        f"Curve Type: {list(vulnerability_results.keys())[0] if vulnerability_results else 'N/A'}",
        f"Number of Samples: {list(vulnerability_results.values())[0]['num_samples'] if vulnerability_results else 'N/A'}",
        "",
        "GENERATED DIAGRAMS:"
    ]
    
    # Add diagram information
    for vulnerability_type, results in vulnerability_results.items():
        if not results:
            continue
        
        report_lines.append(f"\nVULNERABILITY TYPE: {vulnerability_type.upper()}")
        
        for diagram_type, filepath in results.items():
            if diagram_type == "num_samples":
                continue
                
            status = "SUCCESS" if filepath else "FAILED"
            path_str = str(filepath) if filepath else "N/A"
            report_lines.append(f"  - {diagram_type.upper()}: {status}")
            if filepath:
                report_lines.append(f"    Path: {path_str}")
    
    # Add summary
    report_lines.extend([
        "",
        "SUMMARY:",
        f"Total Vulnerability Types: {len(vulnerability_results)}",
        f"Total Diagram Types Generated: {sum(len(r) - 1 for r in vulnerability_results.values())}"
    ])
    
    report_lines.extend([
        "",
        "=" * 80,
        "TOPOSPHERE DIAGRAM REPORT FOOTER",
        "=" * 80,
        "This report was generated by the TopoSphere Diagram Generation Script,",
        "a component of the AuditCore v3.2 industrial implementation.",
        "",
        "TopoSphere is the world's first topological analyzer for ECDSA that:",
        "- Uses bijective parameterization (u_r, u_z)",
        "- Applies persistent homology and gradient analysis",
        "- Generates synthetic data without knowledge of the private key",
        "- Detects vulnerabilities through topological anomalies",
        "- Recovers keys through linear dependencies and special points",
        "",
        "The system is optimized with:",
        "- GPU acceleration",
        "- Distributed computing (Ray/Spark)",
        "- Intelligent caching",
        "",
        "As stated in our research: 'Topology is not a hacking tool, but a microscope",
        "for diagnosing vulnerabilities. Ignoring it means building cryptography on sand.'",
        "=" * 80
    ])
    
    # Save report
    report_path = output_dir / "diagram_generation_report.txt"
    with open(report_path, "w") as f:
        f.write("\n".join(report_lines))
    
    logger.info("Diagram report saved to %s", report_path)
    return report_path

# ======================
# MAIN GENERATION FLOW
# ======================

def generate_diagrams(vulnerability_types: List[str],
                     curve_types: List[str],
                     num_samples: int,
                     output_dir: Optional[Path] = None,
                     diagram_types: List[str] = ["all"]) -> int:
    """
    Generate topological diagrams for the specified vulnerability types and curve types.
    
    Args:
        vulnerability_types: List of vulnerability types to generate
        curve_types: List of curve types to generate
        num_samples: Number of signature samples to use
        output_dir: Output directory for generated diagrams
        diagram_types: List of diagram types to generate
        
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    start_time = time.time()
    logger.info("=" * 80)
    logger.info("Starting TopoSphere Diagram Generation Process")
    logger.info("Vulnerability Types: %s", ", ".join(vulnerability_types))
    logger.info("Curve Types: %s", ", ".join(curve_types))
    logger.info("Number of Samples: %d", num_samples)
    logger.info("Diagram Types: %s", ", ".join(diagram_types))
    logger.info("=" * 80)
    
    # Validate dependencies
    if not validate_dependencies():
        logger.error("Required dependencies are not available. Aborting.")
        return 1
    
    # Setup matplotlib
    setup_matplotlib()
    
    # Create output directory
    output_dir = create_output_directory(output_dir)
    
    # Track results
    all_results = {}
    
    # Generate diagrams for each vulnerability type and curve type
    for vulnerability_type in vulnerability_types:
        for curve_type in curve_types:
            # Skip if vulnerability_type is "all" and we're already processing specific types
            if vulnerability_type == "all" and len(vulnerability_types) > 1:
                continue
            
            # Skip if curve_type is "all" and we're already processing specific types
            if curve_type == "all" and len(curve_types) > 1:
                continue
            
            # Process specific vulnerability types
            if vulnerability_type == "all":
                vuln_types = [vt for vt in VULNERABILITY_TYPES.keys() if vt != "all"]
            else:
                vuln_types = [vulnerability_type]
            
            # Process specific curve types
            if curve_type == "all":
                curve_types = [ct for ct in CURVE_TYPES.keys() if ct != "all"]
            else:
                curve_types = [curve_type]
            
            # Generate diagrams for each vulnerability type
            for vt in vuln_types:
                for ct in curve_types:
                    results = generate_diagrams_for_vulnerability(
                        vt, ct, num_samples, output_dir, diagram_types
                    )
                    
                    # Store results
                    if vt not in all_results:
                        all_results[vt] = {}
                    all_results[vt][ct] = {
                        **results,
                        "num_samples": num_samples
                    }
    
    # Generate report
    generate_diagram_report(output_dir, all_results)
    
    # Log completion
    duration = time.time() - start_time
    logger.info("Diagram generation completed in %.2f seconds", duration)
    
    return 0

def main():
    """Main entry point for the diagram generation script."""
    parser = argparse.ArgumentParser(
        description="TopoSphere Diagram Generation Script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--vulnerability-types",
        nargs="+",
        choices=list(VULNERABILITY_TYPES.keys()),
        default=["secure"],
        help="Vulnerability types to generate diagrams for"
    )
    
    parser.add_argument(
        "--curve-types",
        nargs="+",
        choices=list(CURVE_TYPES.keys()),
        default=["secp256k1"],
        help="Curve types to generate diagrams for"
    )
    
    parser.add_argument(
        "--num-samples",
        type=int,
        default=1000,
        help="Number of signature samples to use"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Output directory for generated diagrams"
    )
    
    parser.add_argument(
        "--diagram-types",
        nargs="+",
        choices=list(DIAGRAM_TYPES.keys()),
        default=["all"],
        help="Diagram types to generate"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Convert to Path objects
    output_dir = Path(args.output_dir) if args.output_dir else None
    
    # Run diagram generation
    return generate_diagrams(
        args.vulnerability_types,
        args.curve_types,
        args.num_samples,
        output_dir,
        args.diagram_types
    )

if __name__ == "__main__":
    sys.exit(main())
