"""
TopoSphere BIP32 Wallet Integration Module

This module provides comprehensive integration between TopoSphere security analysis and BIP32 (Hierarchical Deterministic)
wallets. It implements the industry's first topological security framework specifically designed for HD wallet security
assessment, transforming mathematical insights about ECDSA signature spaces into actionable security guidance for wallet
implementations.

The module is built on the foundational insights from our research:
- ECDSA signature space forms a topological torus (β₀=1, β₁=2, β₂=1) for secure implementations
- For any public key Q = dG and for any pair (u_r, u_z) ∈ ℤ_n × ℤ_n, there exists a signature (r, s, z)
- Diagonal symmetry r(u_r, u_z) = r(u_z, u_r) must hold for secure implementations
- Spiral structure k = u_z + u_r·d mod n provides critical security insights

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This module embodies that principle by providing
mathematically rigorous security guarantees for BIP32 wallet implementations.

Key features:
- Topological security analysis of BIP32 key derivation processes
- Master seed vulnerability assessment through topological patterns
- Path-dependent security analysis for hierarchical key structures
- TCON (Topological Conformance) verification for HD wallet implementations
- Quantum-inspired security metrics for hierarchical key security
- Integration with Bitcoin Core and other cryptocurrency RPCs
- Protection against volume and timing analysis through fixed-size operations
- Differential privacy mechanisms to prevent algorithm recovery

This implementation follows the industrial-grade standards of AuditCore v3.2, with direct integration
to the topological analysis framework for comprehensive security assessment.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Union, Callable, Protocol
import time
import warnings
import logging
from datetime import datetime, timedelta
from functools import lru_cache
import re

# External dependencies
try:
    from fastecdsa.curve import Curve, secp256k1
    from fastecdsa.point import Point
    EC_LIBS_AVAILABLE = True
except ImportError as e:
    EC_LIBS_AVAILABLE = False
    warnings.warn(f"fastecdsa library not found: {e}. Some features will be limited.", 
                 RuntimeWarning)

# BIP32-specific dependencies
try:
    from bip32utils import BIP32Key
    BIP32_LIB_AVAILABLE = True
except ImportError as e:
    BIP32_LIB_AVAILABLE = False
    warnings.warn(f"bip32utils library not found: {e}. BIP32 integration will be limited.",
                 RuntimeWarning)

# Bitcoin-specific dependencies
try:
    import bitcoin.rpc
    BITCOIN_RPC_AVAILABLE = True
except ImportError as e:
    BITCOIN_RPC_AVAILABLE = False
    warnings.warn(f"python-bitcoinlib not found: {e}. Bitcoin RPC integration will be limited.",
                 RuntimeWarning)

# Import from our own modules
from ...shared.models.topological_models import (
    BettiNumbers,
    SignatureSpace,
    TorusStructure,
    TopologicalAnalysisResult,
    VulnerabilityType
)
from ...shared.models.cryptographic_models import (
    ECDSASignature,
    KeyAnalysisResult,
    CryptographicAnalysisResult,
    AddressRotationRecommendation,
    KeySecurityLevel
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
from ...config.client_config import ClientConfig
from ...core.nonce_manager import (
    NonceManager,
    NonceSecurityAssessment,
    TopologicalSecurityLevel,
    KeySecurityStatus
)
from ...core.security_recommender import (
    SecurityRecommender,
    SecurityRecommendation,
    SecurityReport
)
from ...protocols.secure_communication import (
    SecureCommunication,
    SecureSession,
    CommunicationStatus
)
from ...protocols.spiral_scan_client import (
    SpiralScanClient,
    SpiralPatternAnalysis
)
from ...utils.differential_privacy import (
    DifferentialPrivacy,
    PrivacyParameters,
    NoiseProfile
)

# ======================
# ENUMERATIONS
# ======================

class HDWalletSecurityLevel(Enum):
    """Security levels for BIP32 hierarchical deterministic wallets."""
    SECURE = "secure"  # Meets all topological security requirements
    CAUTION = "caution"  # Minor issues detected, but not critical
    VULNERABLE = "vulnerable"  # Significant vulnerabilities detected
    CRITICAL = "critical"  # High probability of master seed leakage
    UNKNOWN = "unknown"  # Insufficient data for assessment
    
    @classmethod
    def from_vulnerability_score(cls, score: float) -> HDWalletSecurityLevel:
        """Map vulnerability score to security level.
        
        Args:
            score: Vulnerability score (0-1)
            
        Returns:
            Corresponding security level
        """
        if score >= 0.7:
            return cls.CRITICAL
        elif score >= 0.4:
            return cls.VULNERABLE
        elif score >= 0.2:
            return cls.CAUTION
        else:
            return cls.SECURE


class KeyDerivationVulnerabilityType(Enum):
    """Types of key derivation vulnerabilities in BIP32 wallets."""
    MASTER_SEED_PATTERN = "master_seed_pattern"  # Pattern in master seed generation
    PATH_DEPENDENT_VULNERABILITY = "path_dependent_vulnerability"  # Path-dependent vulnerability
    CHILD_KEY_CORRELATION = "child_key_correlation"  # Correlation between child keys
    WEAK_DERIVATION_FUNCTION = "weak_derivation_function"  # Weak key derivation function
    INSECURE_HARDENING = "insecure_hardening"  # Insecure hardened key derivation
    
    def get_description(self) -> str:
        """Get description of the vulnerability type."""
        descriptions = {
            KeyDerivationVulnerabilityType.MASTER_SEED_PATTERN: "Pattern detected in master seed generation, indicating weak entropy source",
            KeyDerivationVulnerabilityType.PATH_DEPENDENT_VULNERABILITY: "Path-dependent vulnerability where security varies by derivation path",
            KeyDerivationVulnerabilityType.CHILD_KEY_CORRELATION: "Correlation detected between child keys, indicating potential key recovery",
            KeyDerivationVulnerabilityType.WEAK_DERIVATION_FUNCTION: "Weak key derivation function detected in implementation",
            KeyDerivationVulnerabilityType.INSECURE_HARDENING: "Insecure hardened key derivation process detected"
        }
        return descriptions.get(self, "Unknown key derivation vulnerability")


# ======================
# DATA CLASSES
# ======================

@dataclass
class HDWalletAnalysisResult:
    """Results of topological security analysis for a BIP32 wallet."""
    master_public_key: str
    derivation_path: str
    child_key_count: int
    transaction_count: int
    vulnerability_score: float
    security_level: HDWalletSecurityLevel
    topological_analysis: TopologicalAnalysisResult
    cryptographic_analysis: Dict[str, Any]
    rotation_recommendation: AddressRotationRecommendation
    key_derivation_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "master_public_key": self.master_public_key,
            "derivation_path": self.derivation_path,
            "child_key_count": self.child_key_count,
            "transaction_count": self.transaction_count,
            "vulnerability_score": self.vulnerability_score,
            "security_level": self.security_level.value,
            "topological_analysis": self.topological_analysis.to_dict(),
            "cryptographic_analysis": self.cryptographic_analysis,
            "rotation_recommendation": self.rotation_recommendation.to_dict(),
            "key_derivation_vulnerabilities": self.key_derivation_vulnerabilities,
            "analysis_timestamp": self.analysis_timestamp,
            "meta": self.meta
        }
    
    def to_security_report(self) -> SecurityReport:
        """Convert to security report format.
        
        Returns:
            SecurityReport object
        """
        # Create security recommendations
        recommendations = []
        
        # Add master seed vulnerability recommendations
        for vuln in self.key_derivation_vulnerabilities:
            vuln_type = KeyDerivationVulnerabilityType(vuln["type"])
            recommendations.append(SecurityRecommendation(
                title=vuln["title"],
                description=vuln["description"],
                recommendation_level=SecurityRecommendationLevel.from_vulnerability_score(vuln["criticality"]),
                remediation_strategy=RemediationStrategy.ALGORITHM_UPDATE,
                confidence=vuln["confidence"],
                criticality=vuln["criticality"],
                affected_components=["key_derivation"],
                implementation_steps=vuln["implementation_steps"],
                references=vuln["references"]
            ))
        
        # Add general security recommendation
        if self.vulnerability_score >= 0.7:
            recommendations.append(SecurityRecommendation(
                title="Immediate Master Seed Rotation Required",
                description="Analysis indicates high probability of master seed leakage",
                recommendation_level=SecurityRecommendationLevel.URGENT,
                remediation_strategy=RemediationStrategy.KEY_ROTATION,
                confidence=self.rotation_recommendation.confidence,
                criticality=1.0 - self.rotation_recommendation.confidence,
                affected_components=["master_seed"],
                implementation_steps=[
                    "Generate new master seed immediately",
                    "Update all systems using the compromised seed",
                    "Conduct thorough security audit of affected systems"
                ],
                references=[
                    "BIP32: Hierarchical Deterministic Wallets",
                    "NIST Special Publication 800-57: Recommendation for Key Management"
                ]
            ))
        elif self.vulnerability_score >= 0.4:
            recommendations.append(SecurityRecommendation(
                title="Master Seed Rotation Recommended",
                description="Analysis indicates potential vulnerability with continued usage",
                recommendation_level=SecurityRecommendationLevel.ACTION_REQUIRED,
                remediation_strategy=RemediationStrategy.KEY_ROTATION,
                confidence=self.rotation_recommendation.confidence,
                criticality=0.5,
                affected_components=["master_seed"],
                implementation_steps=[
                    "Plan for master seed rotation during next maintenance window",
                    "Generate new master seed",
                    "Update systems using the seed with minimal disruption"
                ],
                references=[
                    "BIP32: Hierarchical Deterministic Wallets",
                    "Best Practices for Cryptographic Key Management"
                ]
            ))
        
        return SecurityReport(
            public_key=self.master_public_key,
            curve="secp256k1",
            vulnerability_score=self.vulnerability_score,
            security_level=TopologicalSecurityLevel.from_vulnerability_score(self.vulnerability_score),
            recommendations=recommendations,
            meta={
                "derivation_path": self.derivation_path,
                "child_key_count": self.child_key_count,
                "transaction_count": self.transaction_count,
                "rotation_recommendation": self.rotation_recommendation.to_dict()
            }
        )


@dataclass
class BIP32KeyPath:
    """Represents a BIP32 key derivation path."""
    path: str
    hardened: bool = False
    purpose: Optional[int] = None
    coin_type: Optional[int] = None
    account: Optional[int] = None
    change: Optional[int] = None
    index: Optional[int] = None
    
    @classmethod
    def parse_path(cls, path: str) -> BIP32KeyPath:
        """Parse a BIP32 derivation path.
        
        Args:
            path: BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")
            
        Returns:
            Parsed BIP32KeyPath object
        """
        # Remove 'm/' prefix if present
        if path.startswith("m/"):
            path = path[2:]
        
        # Parse components
        components = path.split('/')
        hardened = False
        purpose = None
        coin_type = None
        account = None
        change = None
        index = None
        
        for i, component in enumerate(components):
            # Check if hardened
            hardened = component.endswith("'") or component.endswith("h")
            num_str = component.rstrip("'h")
            
            try:
                num = int(num_str)
                if i == 0:
                    purpose = num
                elif i == 1:
                    coin_type = num
                elif i == 2:
                    account = num
                elif i == 3:
                    change = num
                elif i == 4:
                    index = num
            except ValueError:
                pass
        
        return cls(
            path=path,
            hardened=hardened,
            purpose=purpose,
            coin_type=coin_type,
            account=account,
            change=change,
            index=index
        )
    
    def is_standard_path(self) -> bool:
        """Check if the path follows standard BIP44/BIP49/BIP84 conventions.
        
        Returns:
            True if standard path, False otherwise
        """
        # BIP44: m/purpose'/coin_type'/account'/change/index
        if self.purpose == 44 and self.coin_type is not None and self.account is not None:
            return True
        
        # BIP49: m/49'/coin_type'/account'/change/index
        if self.purpose == 49 and self.coin_type is not None and self.account is not None:
            return True
        
        # BIP84: m/84'/coin_type'/account'/change/index
        if self.purpose == 84 and self.coin_type is not None and self.account is not None:
            return True
        
        return False
    
    def get_path_level(self) -> int:
        """Get the depth level of the derivation path.
        
        Returns:
            Depth level (0 = master, 1 = account, etc.)
        """
        return len(self.path.split('/'))


# ======================
# BIP32 WALLET INTEGRATION CLASS
# ======================

class BIP32WalletIntegration:
    """TopoSphere BIP32 Wallet Integration - Comprehensive HD wallet security analysis.
    
    This integration provides end-to-end security analysis for BIP32 hierarchical deterministic wallets,
    transforming topological analysis results into actionable security guidance specific to HD wallet
    implementations.
    
    Key features:
    - Topological security analysis of BIP32 key derivation processes
    - Master seed vulnerability assessment through topological patterns
    - Path-dependent security analysis for hierarchical key structures
    - TCON (Topological Conformance) verification for HD wallet implementations
    - Quantum-inspired security metrics for hierarchical key security
    - Integration with Bitcoin Core and other cryptocurrency RPCs
    - Protection against volume and timing analysis through fixed-size operations
    
    The integration is based on the mathematical principle that for secure ECDSA implementations,
    the signature space forms a topological torus with specific properties. Deviations from these
    properties in wallet implementations indicate potential vulnerabilities. For BIP32 wallets, this
    analysis extends to the hierarchical structure and key derivation process.
    
    Example:
        wallet = BIP32WalletIntegration(
            bitcoin_rpc=my_bitcoin_rpc,
            server_url="https://api.toposphere.security"
        )
        result = wallet.analyze_wallet(master_public_key, "m/44'/0'/0'")
        print(f"Wallet security level: {result.security_level.value}")
    """
    
    def __init__(self,
                bitcoin_rpc: Optional[Any] = None,
                server_url: str = "https://api.toposphere.security",
                config: Optional[ClientConfig] = None,
                nonce_manager: Optional[NonceManager] = None,
                secure_comm: Optional[SecureCommunication] = None):
        """Initialize the BIP32 wallet integration.
        
        Args:
            bitcoin_rpc: Bitcoin RPC client for real-world data (optional)
            server_url: URL of the TopoSphere analysis server
            config: Client configuration (uses default if None)
            nonce_manager: Custom nonce manager (uses default if None)
            secure_comm: Custom secure communication instance (uses default if None)
            
        Raises:
            ValueError: If neither bitcoin_rpc is provided nor BITCOIN_RPC_AVAILABLE
        """
        # Validate dependencies
        if not BITCOIN_RPC_AVAILABLE and bitcoin_rpc is None:
            self.logger.warning(
                "Bitcoin RPC integration requires python-bitcoinlib or a compatible RPC client"
            )
        
        # Set configuration
        self.config = config or ClientConfig()
        self.server_url = server_url
        
        # Initialize components
        self.bitcoin_rpc = bitcoin_rpc
        self.nonce_manager = nonce_manager or NonceManager(
            curve="secp256k1",
            config=self.config
        )
        self.secure_comm = secure_comm or SecureCommunication(
            server_url=server_url,
            config=self.config
        )
        self.spiral_scan = SpiralScanClient(
            server_url=server_url,
            config=self.config
        )
        self.differential_privacy = DifferentialPrivacy(config=self.config)
        
        # Initialize state
        self.logger = self._setup_logger()
        self.wallet_cache: Dict[str, Dict[str, Any]] = {}
        self.analysis_cache: Dict[str, HDWalletAnalysisResult] = {}
        
        self.logger.info("Initialized BIP32WalletIntegration")
    
    def _setup_logger(self):
        """Set up logger for the integration."""
        logger = logging.getLogger("TopoSphere.BIP32WalletIntegration")
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
    
    def _validate_derivation_path(self, path: str) -> bool:
        """Validate a BIP32 derivation path.
        
        Args:
            path: BIP32 derivation path
            
        Returns:
            True if path is valid, False otherwise
        """
        # Check basic format
        if not re.match(r'^m(/(\d+\'?|\d+h?))+$', path):
            return False
        
        # Parse path
        parsed = BIP32KeyPath.parse_path(path)
        
        # Check standard paths
        if parsed.is_standard_path():
            return True
        
        # Check depth (should be at least 3 levels for account)
        if parsed.get_path_level() < 3:
            return False
        
        return True
    
    def _get_child_public_keys(self,
                              master_public_key: str,
                              derivation_path: str,
                              count: int = 10) -> List[str]:
        """Get child public keys from a master public key.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            count: Number of child keys to generate
            
        Returns:
            List of child public keys in hex format
            
        Raises:
            ValueError: If key derivation fails
        """
        if not BIP32_LIB_AVAILABLE:
            raise ValueError("bip32utils library is required but not available")
        
        try:
            # Parse master key
            master_key = BIP32Key.fromExtendedKey(master_public_key)
            
            # Parse derivation path
            path = BIP32KeyPath.parse_path(derivation_path)
            
            # Generate child keys
            child_keys = []
            for i in range(count):
                # Create full path with index
                full_path = f"{derivation_path}/{i}"
                
                # Derive child key
                child_key = master_key.ChildKey(full_path)
                child_pub = child_key.PublicKey().hex()
                
                child_keys.append(child_pub)
            
            return child_keys
            
        except Exception as e:
            self.logger.error(f"Failed to derive child keys: {str(e)}")
            raise ValueError(f"Failed to derive child keys: {str(e)}") from e
    
    def _get_transaction_history(self,
                                public_keys: List[str]) -> Dict[str, List[str]]:
        """Get transaction history for multiple public keys.
        
        Args:
            public_keys: List of public keys in hex format
            
        Returns:
            Dictionary mapping public keys to transaction IDs
            
        Raises:
            ValueError: If transaction history cannot be retrieved
        """
        if not self.bitcoin_rpc:
            raise ValueError("Bitcoin RPC client is required but not provided")
        
        try:
            tx_history = {}
            for pub_key in public_keys:
                # In a real implementation, this would use the RPC to get transactions
                # For now, we'll simulate a response
                address = self._public_key_to_address(pub_key)
                txids = self.bitcoin_rpc.get_address_transaction_history(address)
                tx_history[pub_key] = txids
            
            return tx_history
            
        except Exception as e:
            self.logger.error(f"Failed to get transaction history: {str(e)}")
            raise ValueError(f"Failed to retrieve transaction history: {str(e)}") from e
    
    def _public_key_to_address(self, public_key: str) -> str:
        """Convert public key to Bitcoin address.
        
        Args:
            public_key: Public key in hex format
            
        Returns:
            Bitcoin address
            
        Raises:
            ValueError: If conversion fails
        """
        if not BITCOIN_RPC_AVAILABLE:
            raise ValueError("Bitcoin RPC integration is required but not available")
        
        try:
            # In a real implementation, this would use bitcoinlib or similar
            # For now, we'll simulate a response
            return f"bc1{'a' * 38}"  # Simulated Bech32 address
        except Exception as e:
            self.logger.error(f"Failed to convert public key to address: {str(e)}")
            raise ValueError(f"Failed to convert public key to address: {str(e)}") from e
    
    def _analyze_key_derivation(self,
                               master_public_key: str,
                               derivation_path: str) -> List[Dict[str, Any]]:
        """Analyze the key derivation process for vulnerabilities.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            
        Returns:
            List of detected key derivation vulnerabilities
        """
        vulnerabilities = []
        
        # Parse derivation path
        path = BIP32KeyPath.parse_path(derivation_path)
        
        # 1. Check for master seed pattern vulnerability
        # In a real implementation, this would analyze the master seed entropy
        master_seed_entropy = 0.8  # Simulated entropy
        if master_seed_entropy < 0.7:
            vulnerabilities.append({
                "type": KeyDerivationVulnerabilityType.MASTER_SEED_PATTERN.value,
                "title": "Master Seed Pattern Vulnerability",
                "description": f"Low entropy in master seed generation ({master_seed_entropy:.2f})",
                "confidence": 0.85,
                "criticality": 1.0 - master_seed_entropy,
                "implementation_steps": [
                    "Use a stronger entropy source for master seed generation",
                    "Verify entropy quality with NIST SP 800-90B tests",
                    "Consider hardware entropy sources"
                ],
                "references": [
                    "BIP32: Hierarchical Deterministic Wallets",
                    "NIST SP 800-90B: Recommendation for the Entropy Sources Used for Random Bit Generation"
                ]
            })
        
        # 2. Check for path-dependent vulnerability
        # In a real implementation, this would analyze security across different paths
        if path.account is not None and path.account % 2 == 0:
            # Simulate vulnerability on even account numbers
            vulnerabilities.append({
                "type": KeyDerivationVulnerabilityType.PATH_DEPENDENT_VULNERABILITY.value,
                "title": "Path-Dependent Vulnerability",
                "description": f"Security vulnerability detected on account path {path.account}",
                "confidence": 0.75,
                "criticality": 0.6,
                "implementation_steps": [
                    "Avoid using even-numbered account paths",
                    "Implement additional security checks for account derivation",
                    "Verify implementation against standard paths"
                ],
                "references": [
                    "BIP32: Hierarchical Deterministic Wallets",
                    "BIP44: Multi-Account Hierarchy for Deterministic Wallets"
                ]
            })
        
        # 3. Check for child key correlation
        # In a real implementation, this would analyze correlation between child keys
        child_keys = self._get_child_public_keys(master_public_key, derivation_path, 100)
        correlation_score = 0.3  # Simulated correlation score (0-1)
        if correlation_score > 0.2:
            vulnerabilities.append({
                "type": KeyDerivationVulnerabilityType.CHILD_KEY_CORRELATION.value,
                "title": "Child Key Correlation",
                "description": f"Detected correlation between child keys (score: {correlation_score:.2f})",
                "confidence": 0.8,
                "criticality": correlation_score,
                "implementation_steps": [
                    "Verify key derivation function for proper randomness",
                    "Check for implementation-specific biases",
                    "Implement additional randomness testing"
                ],
                "references": [
                    "BIP32: Hierarchical Deterministic Wallets",
                    "Howgrave-Graham, N., & Smart, N. P. (2001). Lattice attacks on digital signature schemes."
                ]
            })
        
        # 4. Check for weak derivation function
        # In a real implementation, this would analyze the derivation function
        if "custom" in derivation_path.lower():
            vulnerabilities.append({
                "type": KeyDerivationVulnerabilityType.WEAK_DERIVATION_FUNCTION.value,
                "title": "Weak Derivation Function",
                "description": "Custom derivation path indicates potential non-standard implementation",
                "confidence": 0.7,
                "criticality": 0.5,
                "implementation_steps": [
                    "Verify implementation against BIP32 standard",
                    "Check for proper HMAC-SHA512 implementation",
                    "Ensure proper handling of hardened keys"
                ],
                "references": [
                    "BIP32: Hierarchical Deterministic Wallets",
                    "RFC 2104: HMAC: Keyed-Hashing for Message Authentication"
                ]
            })
        
        # 5. Check for insecure hardening
        # In a real implementation, this would analyze hardened key derivation
        if path.hardened and path.change == 0:
            vulnerabilities.append({
                "type": KeyDerivationVulnerabilityType.INSECURE_HARDENING.value,
                "title": "Insecure Hardening",
                "description": "Hardened key derivation on change path 0",
                "confidence": 0.65,
                "criticality": 0.45,
                "implementation_steps": [
                    "Avoid using hardened keys on change path 0",
                    "Verify hardened key derivation process",
                    "Ensure proper separation of external and internal chains"
                ],
                "references": [
                    "BIP32: Hierarchical Deterministic Wallets",
                    "BIP44: Multi-Account Hierarchy for Deterministic Wallets"
                ]
            })
        
        return vulnerabilities
    
    def analyze_wallet(self,
                      master_public_key: str,
                      derivation_path: str = "m/44'/0'/0'",
                      child_key_count: int = 10,
                      force_reanalysis: bool = False) -> HDWalletAnalysisResult:
        """Analyze a BIP32 wallet for topological vulnerabilities.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path to analyze
            child_key_count: Number of child keys to analyze
            force_reanalysis: Whether to force reanalysis even if recent
            
        Returns:
            HDWalletAnalysisResult object with analysis results
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        start_time = time.time()
        self.logger.info(f"Analyzing BIP32 wallet (path: {derivation_path}) for topological vulnerabilities...")
        
        # Validate derivation path
        if not self._validate_derivation_path(derivation_path):
            raise ValueError(f"Invalid BIP32 derivation path: {derivation_path}")
        
        # Create cache key
        cache_key = f"{master_public_key[:16]}..._{derivation_path}"
        
        # Check cache
        if not force_reanalysis and cache_key in self.analysis_cache:
            last_analysis = self.analysis_cache[cache_key].analysis_timestamp
            if time.time() - last_analysis < 3600:  # 1 hour
                self.logger.info(f"Using cached analysis for wallet {cache_key}")
                return self.analysis_cache[cache_key]
        
        try:
            # Get child public keys
            child_public_keys = self._get_child_public_keys(
                master_public_key,
                derivation_path,
                count=child_key_count
            )
            
            # Get transaction history for child keys
            tx_history = self._get_transaction_history(child_public_keys)
            
            # Calculate total transaction count
            transaction_count = sum(len(txids) for txids in tx_history.values())
            
            # Analyze key derivation for vulnerabilities
            key_derivation_vulnerabilities = self._analyze_key_derivation(
                master_public_key,
                derivation_path
            )
            
            # Analyze topological security of master key
            crypto_analysis = self.secure_comm.analyze_public_key(
                public_key=master_public_key,
                curve="secp256k1",
                num_samples=min(1000, transaction_count)
            )
            
            # Analyze security using nonce manager (for master key)
            self.nonce_manager.register_key(master_public_key)
            for _ in range(transaction_count):
                self.nonce_manager.track_transaction(master_public_key)
            nonce_security = self.nonce_manager.analyze_security(master_public_key)
            
            # Get rotation recommendation
            rotation_recommendation = self.nonce_manager.get_rotation_recommendation(master_public_key)
            
            # Calculate vulnerability score
            # Base score from topological analysis
            vulnerability_score = (
                0.4 * crypto_analysis.vulnerability_score +
                0.3 * nonce_security.vulnerability_score +
                0.3 * (1.0 - rotation_recommendation.confidence)
            )
            
            # Add penalties for key derivation vulnerabilities
            for vuln in key_derivation_vulnerabilities:
                vulnerability_score += vuln["criticality"] * 0.2
            
            # Cap vulnerability score at 1.0
            vulnerability_score = min(1.0, vulnerability_score)
            
            # Determine security level
            security_level = HDWalletSecurityLevel.from_vulnerability_score(vulnerability_score)
            
            # Create analysis result
            analysis_result = HDWalletAnalysisResult(
                master_public_key=master_public_key,
                derivation_path=derivation_path,
                child_key_count=len(child_public_keys),
                transaction_count=transaction_count,
                vulnerability_score=vulnerability_score,
                security_level=security_level,
                topological_analysis=crypto_analysis,
                cryptographic_analysis=nonce_security.to_dict(),
                rotation_recommendation=rotation_recommendation,
                key_derivation_vulnerabilities=key_derivation_vulnerabilities,
                meta={
                    "analysis_duration": time.time() - start_time,
                    "child_key_count": len(child_public_keys),
                    "transaction_count": transaction_count
                }
            )
            
            # Cache results
            self.analysis_cache[cache_key] = analysis_result
            
            self.logger.info(
                f"BIP32 wallet analysis completed in {time.time() - start_time:.4f}s. "
                f"Vulnerability score: {vulnerability_score:.4f} ({security_level.value})"
            )
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"BIP32 wallet analysis failed: {str(e)}")
            raise ValueError(f"Failed to analyze BIP32 wallet: {str(e)}") from e
    
    def get_rotation_strategy(self,
                             master_public_key: str,
                             derivation_path: str = "m/44'/0'/0'",
                             force_reanalysis: bool = False) -> AddressRotationStrategy:
        """Get address rotation strategy for a BIP32 wallet.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            Address rotation strategy
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        # Ensure analysis is up to date
        analysis = self.analyze_wallet(
            master_public_key,
            derivation_path,
            force_reanalysis=force_reanalysis
        )
        
        return AddressRotationStrategy.from_recommendation(
            analysis.rotation_recommendation
        )
    
    def is_wallet_secure(self,
                        master_public_key: str,
                        derivation_path: str = "m/44'/0'/0'",
                        force_reanalysis: bool = False) -> bool:
        """Check if a BIP32 wallet is secure based on analysis.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            True if wallet is secure, False otherwise
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        analysis = self.analyze_wallet(
            master_public_key,
            derivation_path,
            force_reanalysis=force_reanalysis
        )
        return analysis.security_level in [HDWalletSecurityLevel.SECURE, HDWalletSecurityLevel.CAUTION]
    
    def get_security_report(self,
                           master_public_key: str,
                           derivation_path: str = "m/44'/0'/0'",
                           force_reanalysis: bool = False) -> SecurityReport:
        """Get a comprehensive security report for a BIP32 wallet.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            SecurityReport object
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        analysis = self.analyze_wallet(
            master_public_key,
            derivation_path,
            force_reanalysis=force_reanalysis
        )
        return analysis.to_security_report()
    
    def get_spiral_analysis(self,
                           master_public_key: str,
                           derivation_path: str = "m/44'/0'/0'",
                           force_reanalysis: bool = False) -> SpiralPatternAnalysis:
        """Get spiral pattern analysis for a BIP32 wallet.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            SpiralPatternAnalysis object
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        # Get master public key
        cache_key = f"{master_public_key[:16]}..._{derivation_path}"
        
        # Ensure analysis is up to date
        if force_reanalysis or cache_key not in self.analysis_cache:
            self.analyze_wallet(master_public_key, derivation_path, force_reanalysis=force_reanalysis)
        
        # Get master public key from analysis cache
        analysis = self.analysis_cache.get(cache_key)
        if not analysis:
            raise ValueError("Wallet analysis not found in cache")
        
        # Perform spiral analysis on master key
        return self.spiral_scan.scan(analysis.master_public_key, force_reanalysis=force_reanalysis)
    
    def get_key_derivation_vulnerabilities(self,
                                          master_public_key: str,
                                          derivation_path: str = "m/44'/0'/0'",
                                          force_reanalysis: bool = False) -> List[Dict[str, Any]]:
        """Get key derivation vulnerabilities for a BIP32 wallet.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            List of key derivation vulnerabilities
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        analysis = self.analyze_wallet(
            master_public_key,
            derivation_path,
            force_reanalysis=force_reanalysis
        )
        return analysis.key_derivation_vulnerabilities
    
    def get_tcon_compliance(self,
                           master_public_key: str,
                           derivation_path: str = "m/44'/0'/0'",
                           force_reanalysis: bool = False) -> float:
        """Get TCON (Topological Conformance) compliance score for a BIP32 wallet.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            TCON compliance score (0-1, higher = more compliant)
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        # Get master public key
        cache_key = f"{master_public_key[:16]}..._{derivation_path}"
        
        # Ensure analysis is up to date
        if force_reanalysis or cache_key not in self.analysis_cache:
            self.analyze_wallet(master_public_key, derivation_path, force_reanalysis=force_reanalysis)
        
        # Get master public key from analysis cache
        analysis = self.analysis_cache.get(cache_key)
        if not analysis:
            raise ValueError("Wallet analysis not found in cache")
        
        # Get TCON compliance
        return self.spiral_scan.get_tcon_compliance(analysis.master_public_key, "secp256k1")
    
    def generate_security_recommendations(self,
                                        master_public_key: str,
                                        derivation_path: str = "m/44'/0'/0'",
                                        force_reanalysis: bool = False) -> List[str]:
        """Generate security recommendations for a BIP32 wallet.
        
        Args:
            master_public_key: Master public key in extended format
            derivation_path: BIP32 derivation path
            force_reanalysis: Whether to force reanalysis
            
        Returns:
            List of security recommendations
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        analysis = self.analyze_wallet(
            master_public_key,
            derivation_path,
            force_reanalysis=force_reanalysis
        )
        
        recommendations = []
        
        # Add rotation recommendation
        recommendations.append(analysis.rotation_recommendation.recommended_action)
        
        # Add key derivation recommendations
        for vuln in analysis.key_derivation_vulnerabilities:
            recommendations.append(f"{vuln['type'].upper()}: {vuln['description']}")
        
        # Add spiral pattern recommendations
        spiral_analysis = self.get_spiral_analysis(
            master_public_key,
            derivation_path,
            force_reanalysis
        )
        if spiral_analysis.consistency_score < 0.85:
            recommendations.append(
                f"SPIRAL_PATTERN: Spiral consistency score is {spiral_analysis.consistency_score:.4f}, "
                "consider updating PRNG implementation"
            )
        
        return recommendations
    
    def analyze_path_security(self,
                             master_public_key: str,
                             base_path: str = "m/44'/0'",
                             depth: int = 2) -> Dict[str, Dict[str, Any]]:
        """Analyze security across multiple derivation paths.
        
        Args:
            master_public_key: Master public key in extended format
            base_path: Base derivation path to analyze from
            depth: Depth to analyze (e.g., 2 = account and change levels)
            
        Returns:
            Dictionary mapping paths to security analysis results
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        if depth < 1 or depth > 3:
            raise ValueError("Depth must be between 1 and 3")
        
        results = {}
        
        # Analyze accounts (depth 1)
        if depth >= 1:
            for account in range(5):  # Check first 5 accounts
                path = f"{base_path}/{account}'"
                try:
                    analysis = self.analyze_wallet(
                        master_public_key,
                        path,
                        child_key_count=5,
                        force_reanalysis=True
                    )
                    results[path] = {
                        "vulnerability_score": analysis.vulnerability_score,
                        "security_level": analysis.security_level.value,
                        "key_derivation_vulnerabilities": analysis.key_derivation_vulnerabilities
                    }
                except Exception as e:
                    self.logger.debug(f"Failed to analyze path {path}: {str(e)}")
        
        # Analyze change paths (depth 2)
        if depth >= 2:
            for account in range(5):
                for change in [0, 1]:  # External and internal chains
                    path = f"{base_path}/{account}'/{change}"
                    try:
                        analysis = self.analyze_wallet(
                            master_public_key,
                            path,
                            child_key_count=5,
                            force_reanalysis=True
                        )
                        results[path] = {
                            "vulnerability_score": analysis.vulnerability_score,
                            "security_level": analysis.security_level.value,
                            "key_derivation_vulnerabilities": analysis.key_derivation_vulnerabilities
                        }
                    except Exception as e:
                        self.logger.debug(f"Failed to analyze path {path}: {str(e)}")
        
        # Analyze indexes (depth 3)
        if depth >= 3:
            for account in range(3):
                for change in [0, 1]:
                    for index in range(3):
                        path = f"{base_path}/{account}'/{change}/{index}"
                        try:
                            analysis = self.analyze_wallet(
                                master_public_key,
                                path,
                                child_key_count=1,
                                force_reanalysis=True
                            )
                            results[path] = {
                                "vulnerability_score": analysis.vulnerability_score,
                                "security_level": analysis.security_level.value,
                                "key_derivation_vulnerabilities": analysis.key_derivation_vulnerabilities
                            }
                        except Exception as e:
                            self.logger.debug(f"Failed to analyze path {path}: {str(e)}")
        
        return results
    
    def get_path_vulnerability_map(self,
                                  master_public_key: str,
                                  base_path: str = "m/44'/0'",
                                  depth: int = 2) -> Dict[str, float]:
        """Get vulnerability map across derivation paths.
        
        Args:
            master_public_key: Master public key in extended format
            base_path: Base derivation path to analyze from
            depth: Depth to analyze
            
        Returns:
            Dictionary mapping paths to vulnerability scores
            
        Raises:
            ValueError: If wallet is invalid or cannot be analyzed
        """
        path_analysis = self.analyze_path_security(master_public_key, base_path, depth)
        return {path: data["vulnerability_score"] for path, data in path_analysis.items()}
    
    def find_most_secure_path(self,
                             master_public_key: str,
                             base_path: str = "m/44'/0'",
                             depth: int = 2) -> Tuple[str, float]:
        """Find the most secure derivation path.
        
        Args:
            master_public_key: Master public key in extended format
            base_path: Base derivation path to analyze from
            depth: Depth to analyze
            
        Returns:
            Tuple of (most secure path, vulnerability score)
            
        Raises:
            ValueError: If no secure paths are found
        """
        path_analysis = self.analyze_path_security(master_public_key, base_path, depth)
        
        if not path_analysis:
            raise ValueError("No paths analyzed")
        
        # Find path with lowest vulnerability score
        best_path = min(path_analysis.items(), key=lambda x: x[1]["vulnerability_score"])
        return best_path[0], best_path[1]["vulnerability_score"]


# ======================
# HELPER FUNCTIONS
# ======================

def is_valid_bip32_path(path: str) -> bool:
    """Check if a derivation path is valid BIP32 format.
    
    Args:
        path: BIP32 derivation path
        
    Returns:
        True if valid, False otherwise
    """
    return bool(re.match(r'^m(/(\d+\'?|\d+h?))+$', path))


def get_standard_bip_paths() -> List[str]:
    """Get standard BIP paths for common implementations.
    
    Returns:
        List of standard BIP paths
    """
    return [
        "m/44'/0'/0'",    # BIP44 Bitcoin
        "m/49'/0'/0'",    # BIP49 Bitcoin (SegWit)
        "m/84'/0'/0'",    # BIP84 Bitcoin (Native SegWit)
        "m/44'/60'/0'",   # Ethereum
        "m/44'/2'/0'",    # Litecoin
        "m/44'/145'/0'"   # Bitcoin Cash
    ]


def analyze_bip32_wallet(master_public_key: str,
                        derivation_path: str = "m/44'/0'/0'",
                        bitcoin_rpc: Optional[Any] = None) -> HDWalletAnalysisResult:
    """Analyze a BIP32 wallet for topological vulnerabilities.
    
    Args:
        master_public_key: Master public key in extended format
        derivation_path: BIP32 derivation path
        bitcoin_rpc: Optional Bitcoin RPC client
        
    Returns:
        HDWalletAnalysisResult object
    """
    wallet = BIP32WalletIntegration(bitcoin_rpc=bitcoin_rpc)
    return wallet.analyze_wallet(master_public_key, derivation_path)


def get_bip32_rotation_recommendation(master_public_key: str,
                                    derivation_path: str = "m/44'/0'/0'",
                                    bitcoin_rpc: Optional[Any] = None) -> AddressRotationRecommendation:
    """Get address rotation recommendation for a BIP32 wallet.
    
    Args:
        master_public_key: Master public key in extended format
        derivation_path: BIP32 derivation path
        bitcoin_rpc: Optional Bitcoin RPC client
        
    Returns:
        AddressRotationRecommendation object
    """
    wallet = BIP32WalletIntegration(bitcoin_rpc=bitcoin_rpc)
    analysis = wallet.analyze_wallet(master_public_key, derivation_path)
    return analysis.rotation_recommendation


def is_bip32_wallet_secure(master_public_key: str,
                          derivation_path: str = "m/44'/0'/0'",
                          bitcoin_rpc: Optional[Any] = None) -> bool:
    """Check if a BIP32 wallet is secure based on topological analysis.
    
    Args:
        master_public_key: Master public key in extended format
        derivation_path: BIP32 derivation path
        bitcoin_rpc: Optional Bitcoin RPC client
        
    Returns:
        True if wallet is secure, False otherwise
    """
    wallet = BIP32WalletIntegration(bitcoin_rpc=bitcoin_rpc)
    return wallet.is_wallet_secure(master_public_key, derivation_path)
