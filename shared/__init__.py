"""
TopoSphere Shared Module

This module contains common components used across both client and server components
of the TopoSphere system. It provides a unified interface for shared functionality,
ensuring consistency and reducing code duplication.

The shared module includes:
- Mathematical and cryptographic models
- Protocol definitions and message formats
- Utility functions for elliptic curve operations and topological calculations
- Security parameters and noise configurations

All components are designed with security and performance in mind, implementing
rigorous mathematical foundations while protecting intellectual property.

Version: 1.0.0
"""

__version__ = "1.0.0"
__all__ = [
    # Models
    "TopologicalModel",
    "SecurityModel",
    "CryptographicModel",
    "BettiNumbers",
    "SignatureSpace",
    "TorusStructure",
    
    # Protocol components
    "SecureProtocol",
    "MessageFormat",
    "NoiseParameters",
    "ProtocolVersion",
    "SessionState",
    
    # Utility functions
    "compute_betti_numbers",
    "estimate_private_key",
    "generate_synthetic_signatures",
    "check_diagonal_symmetry",
    "calculate_topological_entropy",
    "is_secure_topology",
    "validate_public_key",
    "compute_spiral_pattern",
    "analyze_symmetry_violations",
    
    # Constants
    "SECP256K1_ORDER",
    "MAX_SIGNATURES_PER_ANALYSIS",
    "DEFAULT_SAMPLING_RATE",
    "BETTI_SECURE_VALUES",
    "ENTROPY_THRESHOLD",
    "SYMMETRY_VIOLATION_THRESHOLD",
    "VULNERABILITY_SCORE_THRESHOLD"
]

# Import models
from .models.topological_models import (
    TopologicalModel,
    BettiNumbers,
    SignatureSpace,
    TorusStructure
)
from .models.security_models import (
    SecurityModel,
    TCONCompliance
)
from .models.cryptographic_models import (
    CryptographicModel,
    ECDSASignature
)

# Import protocols
from .protocols.secure_protocol import (
    SecureProtocol,
    ProtocolVersion,
    SessionState
)
from .protocols.message_formats import (
    MessageFormat,
    AnalysisRequest,
    AnalysisResponse,
    ErrorResponse
)
from .protocols.noise_parameters import (
    NoiseParameters,
    DifferentialPrivacyConfig
)

# Import utilities
from .utils.math_utils import (
    compute_betti_numbers,
    calculate_topological_entropy,
    is_secure_topology
)
from .utils.elliptic_curve import (
    validate_public_key,
    estimate_private_key,
    generate_synthetic_signatures,
    compute_spiral_pattern
)
from .utils.topology_calculations import (
    check_diagonal_symmetry,
    analyze_symmetry_violations
)

# Constants
SECP256K1_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337
MAX_SIGNATURES_PER_ANALYSIS = 10000
DEFAULT_SAMPLING_RATE = 0.01
BETTI_SECURE_VALUES = {"beta_0": 1, "beta_1": 2, "beta_2": 1}
ENTROPY_THRESHOLD = 0.5
SYMMETRY_VIOLATION_THRESHOLD = 0.01
VULNERABILITY_SCORE_THRESHOLD = 0.2

def get_shared_version() -> str:
    """
    Returns the version of the shared module.
    
    Returns:
        str: Version string in semantic versioning format
    """
    return __version__

def get_security_parameters() -> dict:
    """
    Returns the core security parameters used throughout TopoSphere.
    
    Returns:
        dict: Dictionary containing security thresholds and parameters
    """
    return {
        "betti_secure_values": BETTI_SECURE_VALUES,
        "entropy_threshold": ENTROPY_THRESHOLD,
        "symmetry_violation_threshold": SYMMETRY_VIOLATION_THRESHOLD,
        "vulnerability_score_threshold": VULNERABILITY_SCORE_THRESHOLD,
        "max_signatures_per_analysis": MAX_SIGNATURES_PER_ANALYSIS,
        "default_sampling_rate": DEFAULT_SAMPLING_RATE
    }

# Initialize any necessary components
def initialize_shared_module():
    """
    Initializes the shared module, setting up any necessary configurations
    or precomputations.
    """
    # Placeholder for any initialization logic
    pass

# Call initialization on import
initialize_shared_module()

__doc__ += f"\nVersion: {__version__}"
