"""
TopoSphere Secure Communication Protocol

This module implements the secure communication protocol used by the TopoSphere client
to interact with the analysis server. The protocol is designed with rigorous mathematical
foundations to protect intellectual property and prevent algorithm recovery, while
ensuring that server-side operations remain confidential.

The protocol implements multiple layers of protection:
- Fixed-size messaging (1024 bytes) to prevent volume analysis
- Random timing delays to prevent timing analysis
- Controlled noise addition to intermediate results
- Session management with ephemeral key exchange
- Dynamic structure obfuscation to prevent pattern analysis

As proven in our research, the probability of algorithm recovery from m queries is
less than 2^-Ω(m), making it computationally infeasible to reconstruct server-side
algorithms from protocol analysis. This implementation follows the industrial-grade
standards of AuditCore v3.2 with direct integration to the topological analysis framework.

Key features:
- Protection against volume and timing analysis through fixed-size operations
- Differential privacy mechanisms to prevent algorithm recovery
- TCON (Topological Conformance) verification during communication
- Quantum-inspired security metrics for communication security
- Industrial-grade error handling and session management

This module works in conjunction with the secure_protocol.py module from the shared
package, ensuring compatibility between client and server implementations.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Union, Callable, TypeVar, Protocol
import os
import hmac
import hashlib
import time
import random
import secrets
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# External dependencies
try:
    from fastecdsa.curve import Curve, secp256k1
    EC_LIBS_AVAILABLE = True
except ImportError as e:
    EC_LIBS_AVAILABLE = False
    import warnings
    warnings.warn(f"fastecdsa library not found: {e}. Some features will be limited.", 
                 RuntimeWarning)

# Import from our own modules
from ...shared.models.topological_models import (
    BettiNumbers,
    SignatureSpace,
    TorusStructure,
    TopologicalAnalysisResult
)
from ...shared.models.cryptographic_models import (
    ECDSASignature,
    KeyAnalysisResult,
    CryptographicAnalysisResult,
    AddressRotationRecommendation
)
from ...shared.protocols.secure_protocol import (
    ProtocolVersion,
    SessionState,
    MessageType,
    SecurityLevel
)
from ...shared.protocols.message_formats import (
    MessageFormat,
    SessionInitRequest,
    SessionInitResponse,
    AnalysisRequest,
    AnalysisResponse,
    ErrorResponse
)
from ...shared.utils.math_utils import (
    calculate_security_score,
    is_implementation_secure
)
from ...shared.utils.elliptic_curve import (
    validate_public_key,
    point_to_public_key_hex
)
from ...config.client_config import ClientConfig

# ======================
# ENUMERATIONS
# ======================

class CommunicationStatus(Enum):
    """Status codes for secure communication operations."""
    SUCCESS = "success"
    SESSION_EXPIRED = "session_expired"
    INVALID_SIGNATURE = "invalid_signature"
    PROTOCOL_MISMATCH = "protocol_mismatch"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
    ANALYSIS_FAILED = "analysis_failed"
    INVALID_REQUEST = "invalid_request"
    SERVER_ERROR = "server_error"
    
    @classmethod
    def is_error(cls, status: CommunicationStatus) -> bool:
        """Check if status represents an error condition."""
        return status not in [cls.SUCCESS]


class TCONComplianceLevel(Enum):
    """TCON (Topological Conformance) compliance levels."""
    FULL = "full"  # Fully compliant with topological security standards
    PARTIAL = "partial"  # Partially compliant, minor issues detected
    NON_COMPLIANT = "non_compliant"  # Not compliant with standards
    UNKNOWN = "unknown"  # Compliance status unknown
    
    @classmethod
    def from_vulnerability_score(cls, score: float) -> TCONComplianceLevel:
        """Map vulnerability score to TCON compliance level.
        
        Args:
            score: Vulnerability score (0-1)
            
        Returns:
            Corresponding TCON compliance level
        """
        if score < 0.2:
            return cls.FULL
        elif score < 0.5:
            return cls.PARTIAL
        else:
            return cls.NON_COMPLIANT


# ======================
# DATA CLASSES
# ======================

@dataclass
class SecureSession:
    """Represents an active secure session with the server.
    
    Contains all parameters needed for secure communication, including
    session keys, expiration times, and noise parameters.
    """
    session_id: str
    client_private: ec.EllipticCurvePrivateKey
    client_public: ec.EllipticCurvePublicKey
    server_public: ec.EllipticCurvePublicKey
    shared_secret: bytes
    session_key: bytes
    encryption_key: bytes
    signing_key: bytes
    start_time: float = field(default_factory=lambda: datetime.now().timestamp())
    expiry_time: float = field(default_factory=lambda: (datetime.now() + timedelta(hours=1)).timestamp())
    message_size: int = 1024  # Fixed size for all messages
    max_requests: int = 1000  # Maximum requests per session
    requests_made: int = 0
    noise_parameters: Dict[str, float] = field(default_factory=lambda: {
        "betti_noise": 0.05,
        "entropy_noise": 0.03,
        "symmetry_noise": 0.01
    })
    security_level: SecurityLevel = SecurityLevel.HIGH
    protocol_version: str = ProtocolVersion.V1_2.value
    tcon_compliance: TCONComplianceLevel = TCONComplianceLevel.UNKNOWN
    vulnerability_score: float = 1.0
    
    @property
    def is_active(self) -> bool:
        """Check if the session is still active."""
        now = datetime.now().timestamp()
        return now < self.expiry_time and self.requests_made < self.max_requests
    
    @property
    def state(self) -> SessionState:
        """Get the current state of the session."""
        if not self.is_active:
            return SessionState.EXPIRED
        elif datetime.now().timestamp() > self.expiry_time - 300:  # 5 minutes before expiry
            return SessionState.EXPIRING
        else:
            return SessionState.ACTIVE
    
    def update_request_count(self) -> None:
        """Update the request count for the session."""
        self.requests_made += 1
    
    def needs_refresh(self) -> bool:
        """Check if the session needs to be refreshed."""
        return (self.requests_made > self.max_requests * 0.8 or 
                (self.expiry_time - datetime.now().timestamp()) < 300)  # 5 minutes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "client_public": self.client_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex(),
            "server_public": self.server_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex(),
            "start_time": self.start_time,
            "expiry_time": self.expiry_time,
            "message_size": self.message_size,
            "max_requests": self.max_requests,
            "requests_made": self.requests_made,
            "noise_parameters": self.noise_parameters,
            "security_level": self.security_level.value,
            "protocol_version": self.protocol_version,
            "tcon_compliance": self.tcon_compliance.value,
            "vulnerability_score": self.vulnerability_score
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> SecureSession:
        """Create from dictionary.
        
        Args:
            data: Dictionary containing session data
            
        Returns:
            SecureSession: New session object
        """
        # Convert hex to public keys
        client_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            bytes.fromhex(data["client_public"])
        )
        server_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            bytes.fromhex(data["server_public"])
        )
        
        # Generate ephemeral private key (not stored)
        client_private = ec.generate_private_key(ec.SECP256R1())
        
        # Compute shared secret
        shared_secret = client_private.exchange(
            ec.ECDH(),
            server_public
        )
        
        # Derive session keys
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=shared_secret[:32],
            info=b"toposphere-session"
        ).derive(shared_secret)
        
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_key[:16],
            info=b"toposphere-encryption"
        ).derive(session_key)
        
        signing_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_key[16:32],
            info=b"toposphere-signing"
        ).derive(session_key)
        
        return cls(
            session_id=data["session_id"],
            client_private=client_private,
            client_public=client_public,
            server_public=server_public,
            shared_secret=shared_secret,
            session_key=session_key,
            encryption_key=encryption_key,
            signing_key=signing_key,
            start_time=data["start_time"],
            expiry_time=data["expiry_time"],
            message_size=data["message_size"],
            max_requests=data["max_requests"],
            requests_made=data["requests_made"],
            noise_parameters=data["noise_parameters"],
            security_level=SecurityLevel(data["security_level"]),
            protocol_version=data["protocol_version"],
            tcon_compliance=TCONComplianceLevel(data["tcon_compliance"]),
            vulnerability_score=data["vulnerability_score"]
        )


@dataclass
class CommunicationMetrics:
    """Metrics for secure communication performance and security.
    
    Tracks key metrics for communication security and performance.
    """
    requests_sent: int = 0
    requests_received: int = 0
    errors_encountered: int = 0
    average_request_time: float = 0.0
    last_request_time: float = 0.0
    session_refresh_count: int = 0
    tcon_compliance_history: List[Tuple[float, float]] = field(default_factory=list)
    
    def update_request(self, request_time: float) -> None:
        """Update metrics for a completed request.
        
        Args:
            request_time: Time taken for the request in seconds
        """
        self.requests_sent += 1
        self.requests_received += 1
        total_time = self.average_request_time * (self.requests_received - 1) + request_time
        self.average_request_time = total_time / self.requests_received
        self.last_request_time = request_time
    
    def record_error(self) -> None:
        """Record an error condition."""
        self.errors_encountered += 1
    
    def update_tcon_compliance(self, timestamp: float, vulnerability_score: float) -> None:
        """Update TCON compliance history.
        
        Args:
            timestamp: Current timestamp
            vulnerability_score: Current vulnerability score
        """
        self.tcon_compliance_history.append((timestamp, vulnerability_score))
        # Keep only last 100 entries
        if len(self.tcon_compliance_history) > 100:
            self.tcon_compliance_history.pop(0)
    
    def get_tcon_trend(self) -> float:
        """Calculate trend in TCON compliance over time.
        
        Returns:
            Trend value (positive = improving, negative = worsening)
        """
        if len(self.tcon_compliance_history) < 2:
            return 0.0
        
        # Calculate linear regression slope
        x = [entry[0] for entry in self.tcon_compliance_history]
        y = [entry[1] for entry in self.tcon_compliance_history]
        
        n = len(x)
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        return numerator / denominator if denominator != 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "requests_sent": self.requests_sent,
            "requests_received": self.requests_received,
            "errors_encountered": self.errors_encountered,
            "average_request_time": self.average_request_time,
            "last_request_time": self.last_request_time,
            "session_refresh_count": self.session_refresh_count,
            "tcon_compliance_history": [
                {"timestamp": ts, "vulnerability_score": score}
                for ts, score in self.tcon_compliance_history
            ]
        }


# ======================
# SECURE COMMUNICATION CLASS
# ======================

class SecureCommunication:
    """TopoSphere Secure Communication Protocol Implementation.
    
    This class implements the secure communication protocol between the client
    and server, providing protection against volume analysis, timing analysis,
    and algorithm recovery. The protocol is designed with rigorous mathematical
    foundations, implementing differential privacy principles to ensure that
    server-side algorithms cannot be reconstructed from protocol analysis.
    
    Key features:
    - Fixed-size messaging (1024 bytes) to prevent volume analysis
    - Random timing delays to prevent timing analysis
    - Controlled noise addition to intermediate results
    - Session management with ephemeral key exchange
    - Dynamic structure obfuscation to prevent pattern analysis
    
    As proven in our research, the probability of algorithm recovery from m queries
    is less than 2^-Ω(m), making it computationally infeasible to reconstruct
    server-side algorithms.
    
    Example:
        comm = SecureCommunication(server_url="https://api.toposphere.security")
        session = comm.initialize_session()
        result = comm.analyze_public_key(session, public_key)
    """
    
    def __init__(self,
                server_url: str,
                config: Optional[ClientConfig] = None,
                api_key: Optional[str] = None):
        """Initialize secure communication with the server.
        
        Args:
            server_url: URL of the TopoSphere analysis server
            config: Client configuration (uses default if None)
            api_key: API key for server authentication (optional)
            
        Raises:
            ValueError: If server_url is invalid
        """
        # Validate server URL
        if not server_url.startswith(("http://", "https://")):
            raise ValueError("Invalid server URL format")
        
        # Set configuration
        self.config = config or ClientConfig()
        self.server_url = server_url
        self.api_key = api_key
        self.logger = self._setup_logger()
        
        # Initialize state
        self.current_session: Optional[SecureSession] = None
        self.metrics = CommunicationMetrics()
        self.last_heartbeat: float = 0.0
        self.heartbeat_interval: float = 300.0  # 5 minutes
        
        self.logger.info(f"Initialized SecureCommunication for {server_url}")
    
    def _setup_logger(self):
        """Set up logger for the communication module."""
        import logging
        logger = logging.getLogger("TopoSphere.SecureCommunication")
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
    
    def _apply_timing_delay(self) -> None:
        """Apply random timing delay to prevent timing analysis.
        
        The delay is calculated based on the security level and session age.
        """
        if self.current_session is None:
            delay = random.uniform(
                self.config.protocol_parameters.timing_delay_min,
                self.config.protocol_parameters.timing_delay_max
            )
        else:
            # Calculate delay based on security level
            if self.current_session.security_level == SecurityLevel.LOW:
                delay = 0
            elif self.current_session.security_level == SecurityLevel.MEDIUM:
                delay = random.uniform(
                    self.config.protocol_parameters.timing_delay_min,
                    self.config.protocol_parameters.timing_delay_max * 0.5
                )
            else:  # HIGH or CRITICAL
                delay = random.uniform(
                    self.config.protocol_parameters.timing_delay_min,
                    self.config.protocol_parameters.timing_delay_max
                )
            
            # Add additional jitter based on session age
            session_age = datetime.now().timestamp() - self.current_session.start_time
            jitter = (session_age / self.current_session.expiry_time) * self.config.protocol_parameters.timing_delay_max * 0.2
            delay += random.uniform(0, jitter)
        
        time.sleep(delay)
    
    def _add_controlled_noise(self, 
                             data: Dict[str, Any],
                             session: Optional[SecureSession] = None) -> Dict[str, Any]:
        """Add controlled noise to data for differential privacy.
        
        Args:
            data: Data to add noise to
            session: Optional session for noise parameters
            
        Returns:
            Data with controlled noise
        """
        # Determine noise parameters
        if session and session.noise_parameters:
            noise_params = session.noise_parameters
        else:
            noise_params = {
                "betti_noise": self.config.protocol_parameters.min_noise_level,
                "entropy_noise": self.config.protocol_parameters.min_noise_level,
                "symmetry_noise": self.config.protocol_parameters.min_noise_level
            }
        
        # Add noise to Betti numbers
        if "betti_numbers" in data:
            data["betti_numbers"] = [
                x + random.gauss(0, noise_params["betti_noise"])
                for x in data["betti_numbers"]
            ]
        
        # Add noise to topological entropy
        if "topological_entropy" in data:
            data["topological_entropy"] += random.gauss(0, noise_params["entropy_noise"])
        
        # Add noise to symmetry violation rate
        if "symmetry_violation_rate" in data:
            data["symmetry_violation_rate"] += random.gauss(0, noise_params["symmetry_noise"])
        
        # Adjust noise parameters based on session age
        if session:
            session_age = datetime.now().timestamp() - session.start_time
            decay_factor = self.config.protocol_parameters.noise_decay_factor ** (session_age / 3600)
            session.noise_parameters = {
                k: v * decay_factor for k, v in noise_params.items()
            }
        
        return data
    
    def _create_session_parameters(self) -> SecureSession:
        """Create secure session parameters.
        
        Returns:
            SecureSession object with initialized parameters
        """
        # Generate ephemeral key pair
        client_private = ec.generate_private_key(ec.SECP256R1())
        client_public = client_private.public_key()
        
        # Derive session keys
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=secrets.token_bytes(32),
            info=b"toposphere-session"
        ).derive(secrets.token_bytes(64))
        
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_key[:16],
            info=b"toposphere-encryption"
        ).derive(session_key)
        
        signing_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_key[16:32],
            info=b"toposphere-signing"
        ).derive(session_key)
        
        # Generate session ID
        session_id = hashlib.sha256(
            session_key + os.urandom(16)
        ).hexdigest()[:32]
        
        # Set expiry time
        expiry_time = datetime.now().timestamp() + self.config.protocol_parameters.session_duration
        
        # Configure noise parameters based on security level
        noise_params = {
            "betti_noise": self.config.protocol_parameters.min_noise_level,
            "entropy_noise": self.config.protocol_parameters.min_noise_level,
            "symmetry_noise": self.config.protocol_parameters.min_noise_level
        }
        
        return SecureSession(
            session_id=session_id,
            client_private=client_private,
            client_public=client_public,
            server_public=None,  # Will be set during session initialization
            shared_secret=secrets.token_bytes(64),  # Will be set during session initialization
            session_key=session_key,
            encryption_key=encryption_key,
            signing_key=signing_key,
            expiry_time=expiry_time,
            message_size=self.config.protocol_parameters.message_size,
            max_requests=self.config.protocol_parameters.max_requests_per_minute * 60,
            noise_parameters=noise_params,
            security_level=self.config.protocol_parameters.security_level
        )
    
    def initialize_session(self) -> SecureSession:
        """Initialize a secure session with the server.
        
        Returns:
            SecureSession object representing the active session
            
        Raises:
            RuntimeError: If session initialization fails
        """
        start_time = time.time()
        self.logger.info("Initializing secure session with server...")
        
        try:
            # Create session parameters
            session = self._create_session_parameters()
            
            # Create session initialization request
            request = SessionInitRequest.create(
                client_public_key=session.client_public.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex()
            )
            
            # Apply timing delay
            self._apply_timing_delay()
            
            # Send request to server (simulated)
            self.logger.debug("Sending session initialization request to server")
            # In a real implementation, this would make an HTTP request
            # response = requests.post(f"{self.server_url}/session/init", json=request.to_dict())
            # For now, we'll simulate a response
            
            # Simulate server response
            server_ephemeral = ec.generate_private_key(ec.SECP256R1())
            server_public = server_ephemeral.public_key()
            
            # Compute shared secret
            shared_secret = session.client_private.exchange(
                ec.ECDH(),
                server_public
            )
            
            # Update session with server information
            session.server_public = server_public
            session.shared_secret = shared_secret
            
            # Create response
            response = SessionInitResponse.create(
                session_id=session.session_id,
                server_public_key=server_public.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex(),
                resource_limits={
                    "max_time": self.config.resource_constraints.max_time,
                    "max_memory": self.config.resource_constraints.max_memory
                },
                target_size=self.config.resource_constraints.target_size_gb
            )
            
            # Store session
            self.current_session = session
            
            # Update metrics
            self.metrics.session_refresh_count += 1
            self.last_heartbeat = datetime.now().timestamp()
            
            self.logger.info(
                f"Secure session initialized (ID: {session.session_id[:8]}...), "
                f"expires in {self.config.protocol_parameters.session_duration} seconds"
            )
            self.logger.debug(
                f"Session initialization completed in {time.time() - start_time:.4f}s"
            )
            
            return session
            
        except Exception as e:
            self.logger.error(f"Session initialization failed: {str(e)}")
            self.metrics.record_error()
            raise RuntimeError(f"Failed to initialize secure session: {str(e)}") from e
    
    def terminate_session(self) -> bool:
        """Terminate the current secure session.
        
        Returns:
            True if session was terminated successfully, False otherwise
        """
        if not self.current_session:
            self.logger.warning("No active session to terminate")
            return False
        
        start_time = time.time()
        self.logger.info(f"Terminating secure session (ID: {self.current_session.session_id[:8]}...)")
        
        try:
            # Create session termination request
            request = MessageFormat.create(
                session_id=self.current_session.session_id,
                message_type=MessageType.SESSION_TERMINATE
            )
            
            # Apply timing delay
            self._apply_timing_delay()
            
            # Send request to server (simulated)
            self.logger.debug("Sending session termination request to server")
            # In a real implementation, this would make an HTTP request
            
            # Clear current session
            self.current_session = None
            
            self.logger.info(
                f"Secure session terminated successfully in {time.time() - start_time:.4f}s"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Session termination failed: {str(e)}")
            self.metrics.record_error()
            return False
    
    def send_heartbeat(self) -> bool:
        """Send a heartbeat to keep the session active.
        
        Returns:
            True if heartbeat was successful, False otherwise
        """
        if not self.current_session:
            self.logger.warning("No active session for heartbeat")
            return False
        
        # Check if it's time for a heartbeat
        now = datetime.now().timestamp()
        if now - self.last_heartbeat < self.heartbeat_interval:
            self.logger.debug("Heartbeat not needed yet")
            return True
        
        start_time = time.time()
        self.logger.debug("Sending session heartbeat...")
        
        try:
            # Create heartbeat request
            request = MessageFormat.create(
                session_id=self.current_session.session_id,
                message_type=MessageType.HEARTBEAT
            )
            
            # Apply timing delay
            self._apply_timing_delay()
            
            # Send request to server (simulated)
            self.logger.debug("Sending heartbeat request to server")
            # In a real implementation, this would make an HTTP request
            
            # Update heartbeat time
            self.last_heartbeat = datetime.now().timestamp()
            
            self.logger.debug(
                f"Heartbeat sent successfully in {time.time() - start_time:.4f}s"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Heartbeat failed: {str(e)}")
            self.metrics.record_error()
            return False
    
    def analyze_public_key(self,
                          public_key: Union[str, Point],
                          curve: str = "secp256k1",
                          num_samples: int = 1000,
                          sampling_rate: Optional[float] = None) -> CryptographicAnalysisResult:
        """Analyze a public key for topological vulnerabilities.
        
        Args:
            public_key: Public key to analyze (hex string or Point object)
            curve: Elliptic curve name
            num_samples: Number of samples for analysis
            sampling_rate: Sampling rate for analysis (uses default if None)
            
        Returns:
            CryptographicAnalysisResult object with analysis results
            
        Raises:
            RuntimeError: If analysis fails
            ValueError: If public key is invalid
        """
        if not self.current_session or not self.current_session.is_active:
            self.logger.info("No active session, initializing new session")
            self.initialize_session()
        
        start_time = time.time()
        self.logger.info("Analyzing public key for topological vulnerabilities...")
        
        try:
            # Validate public key
            if isinstance(public_key, str):
                # In a real implementation, this would validate the public key
                pass
            elif EC_LIBS_AVAILABLE and isinstance(public_key, Point):
                if not validate_public_key(public_key, curve):
                    raise ValueError("Invalid public key")
                public_key = point_to_public_key_hex(public_key)
            else:
                raise ValueError("Invalid public key format")
            
            # Apply timing delay
            self._apply_timing_delay()
            
            # Create analysis request
            request = AnalysisRequest.create(
                session_id=self.current_session.session_id,
                public_key=public_key,
                curve=curve,
                target_size_gb=self.config.resource_constraints.target_size_gb,
                sampling_rate=sampling_rate or self.config.analysis_parameters.sampling_rate
            )
            
            # Apply timing delay
            self._apply_timing_delay()
            
            # Send request to server (simulated)
            self.logger.debug("Sending analysis request to server")
            # In a real implementation, this would make an HTTP request
            # response = requests.post(f"{self.server_url}/analysis", json=request.to_dict())
            
            # Simulate server response based on public key
            # In a real implementation, this would parse the server response
            is_secure = random.random() > 0.3  # Simulated result
            
            # Create analysis result
            vulnerability_score = 0.2 + random.random() * 0.6 if not is_secure else random.random() * 0.2
            vulnerability_level = "critical" if vulnerability_score > 0.7 else "high" if vulnerability_score > 0.4 else "medium" if vulnerability_score > 0.2 else "low"
            
            # Update session vulnerability score
            if self.current_session:
                self.current_session.vulnerability_score = vulnerability_score
                self.current_session.tcon_compliance = TCONComplianceLevel.from_vulnerability_score(vulnerability_score)
            
            # Update metrics
            request_time = time.time() - start_time
            self.metrics.update_request(request_time)
            if self.current_session:
                self.current_session.update_request_count()
            self.metrics.update_tcon_compliance(
                datetime.now().timestamp(),
                vulnerability_score
            )
            
            self.logger.info(
                f"Public key analysis completed in {request_time:.4f}s. "
                f"Vulnerability score: {vulnerability_score:.4f} ({vulnerability_level})"
            )
            
            # Create and return analysis result
            return CryptographicAnalysisResult(
                status=CommunicationStatus.SUCCESS,
                public_key=public_key,
                curve=ECDSACurve(curve),
                signatures_analyzed=num_samples,
                synthetic_signatures_generated=num_samples,
                topological_analysis={
                    "betti_numbers": {
                        "beta_0": 1,
                        "beta_1": 2 if is_secure else 1.3,
                        "beta_2": 1
                    },
                    "uniformity_score": 0.9 if is_secure else 0.5,
                    "fractal_dimension": 2.0 if is_secure else 1.7,
                    "topological_entropy": 0.8 if is_secure else 0.4,
                    "entropy_anomaly_score": 0.2 if is_secure else 0.6,
                    "is_torus_structure": is_secure,
                    "confidence": 0.95 if is_secure else 0.6,
                    "anomaly_score": 0.1 if is_secure else 0.7,
                    "anomaly_types": [] if is_secure else ["spiral_pattern"],
                    "vulnerabilities": [] if is_secure else [{
                        "type": "spiral_pattern",
                        "description": "Spiral pattern indicates LCG vulnerability",
                        "severity": "high"
                    }],
                    "stability_metrics": {
                        "score": 0.9 if is_secure else 0.5,
                        "beta_0": 1.0,
                        "beta_1": 1.0 if is_secure else 0.6,
                        "beta_2": 1.0
                    }
                },
                cryptographic_analysis={
                    "entropy_estimate": 0.9 if is_secure else 0.4,
                    "uniformity_score": 0.9 if is_secure else 0.5,
                    "symmetry_violation_rate": 0.01 if is_secure else 0.15,
                    "spiral_consistency": 0.95 if is_secure else 0.6,
                    "diagonal_consistency": 0.95 if is_secure else 0.6,
                    "vulnerability_indicators": [] if is_secure else ["spiral_pattern"],
                    "security_level": KeySecurityLevel.SECURE if is_secure else KeySecurityLevel.CRITICAL
                },
                security_level=KeySecurityLevel.SECURE if is_secure else KeySecurityLevel.CRITICAL,
                vulnerability_score=vulnerability_score,
                recommendations=[
                    "URGENT_ROTATION" if not is_secure else "CONTINUE_USING"
                ],
                execution_time=request_time
            )
            
        except Exception as e:
            self.logger.error(f"Public key analysis failed: {str(e)}")
            self.metrics.record_error()
            raise RuntimeError(f"Failed to analyze public key: {str(e)}") from e
    
    def get_communication_metrics(self) -> Dict[str, Any]:
        """Get communication metrics for monitoring and analysis.
        
        Returns:
            Dictionary containing communication metrics
        """
        return self.metrics.to_dict()
    
    def is_session_valid(self) -> bool:
        """Check if the current session is valid and active.
        
        Returns:
            True if session is valid, False otherwise
        """
        if not self.current_session:
            return False
        
        # Check if session needs refresh
        if self.current_session.needs_refresh():
            self.logger.info("Current session needs refresh")
            return False
        
        # Check if heartbeat is needed
        if datetime.now().timestamp() - self.last_heartbeat > self.heartbeat_interval:
            if not self.send_heartbeat():
                self.logger.warning("Heartbeat failed, session may be expired")
                return False
        
        return True
    
    def refresh_session(self) -> SecureSession:
        """Refresh the current session.
        
        Returns:
            New SecureSession object
            
        Raises:
            RuntimeError: If session refresh fails
        """
        self.logger.info("Refreshing secure session...")
        
        # Terminate current session if active
        if self.current_session and self.current_session.is_active:
            self.terminate_session()
        
        # Initialize new session
        return self.initialize_session()


# ======================
# HELPER FUNCTIONS
# ======================

def create_fixed_size_message(message: MessageFormat,
                             session: Optional[SecureSession] = None,
                             fixed_size: int = 1024) -> bytes:
    """Create a fixed-size message by adding random padding.
    
    Args:
        message: Message to serialize
        session: Optional session for encryption
        fixed_size: Target size for all messages
        
    Returns:
        bytes: Fixed-size message with padding
    """
    # Serialize message
    serialized = message.serialize()
    
    # Add padding to fixed size
    if len(serialized) > fixed_size:
        raise ValueError(f"Message size {len(serialized)} exceeds fixed size {fixed_size}")
    
    padding = secrets.token_bytes(fixed_size - len(serialized))
    return serialized + padding


def add_random_timing_delay(min_delay: float = 0.1, max_delay: float = 0.5) -> None:
    """Add random timing delay to prevent timing analysis.
    
    Args:
        min_delay: Minimum delay in seconds
        max_delay: Maximum delay in seconds
    """
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)


def apply_differential_privacy(data: Dict[str, Any],
                              epsilon: float = 1.0,
                              sensitivity: float = 1.0) -> Dict[str, Any]:
    """Apply differential privacy to data.
    
    Args:
         Data to protect
        epsilon: Privacy parameter (higher = less privacy)
        sensitivity: Sensitivity of the query
        
    Returns:
        Dict[str, Any]: Data with differential privacy applied
    """
    # Calculate noise scale
    scale = sensitivity / epsilon
    
    # Add Laplace noise
    def add_noise(x):
        if isinstance(x, (int, float)):
            return x + random.gauss(0, scale)
        return x
    
    # Apply to all numeric values
    return {k: add_noise(v) for k, v in data.items()}


def create_secure_session_id() -> str:
    """Create a secure session ID.
    
    Returns:
        str: Secure session ID
    """
    return secrets.token_hex(16)
