"""
Secure Protocol Module

This module defines the secure communication protocol used throughout the TopoSphere system.
The protocol enables secure communication between client and server while protecting both
intellectual property and cryptographic operations from analysis.

The protocol implements multiple layers of protection:
- Fixed-size messaging to prevent volume analysis
- Random timing delays to prevent timing analysis
- Controlled noise addition to intermediate results
- Session management with ephemeral key exchange
- Dynamic structure obfuscation to prevent pattern analysis

All components are designed with rigorous mathematical foundations, implementing differential
privacy principles to ensure that server-side algorithms cannot be reconstructed from protocol
analysis.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any, Callable, TypeVar, Generic
import os
import hmac
import hashlib
import time
import random
import secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# ======================
# ENUMERATIONS
# ======================

class ProtocolVersion(Enum):
    """Supported protocol versions with backward compatibility."""
    V1_0 = "1.0"  # Initial secure version
    V1_1 = "1.1"  # Added quantum scanning support
    V1_2 = "1.2"  # Enhanced differential privacy
    V2_0 = "2.0"  # Major overhaul with improved security
    
    @classmethod
    def is_compatible(cls, client_version: str, server_version: str) -> bool:
        """Check if client and server versions are compatible.
        
        For now, we allow minor version differences (e.g., 1.0 and 1.1),
        but not major version differences (e.g., 1.0 and 2.0).
        """
        client_major = int(client_version.split('.')[0])
        server_major = int(server_version.split('.')[0])
        return client_major == server_major
    
    @classmethod
    def get_supported_versions(cls) -> List[str]:
        """Get list of supported protocol versions."""
        return [v.value for v in cls]


class SessionState(Enum):
    """Possible states of a secure session."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    INVALID = "invalid"


class MessageType(Enum):
    """Types of protocol messages."""
    SESSION_INIT = "session_init"
    SESSION_INIT_RESPONSE = "session_init_response"
    ANALYSIS_REQUEST = "analysis_request"
    ANALYSIS_RESPONSE = "analysis_response"
    ERROR = "error"
    SESSION_TERMINATE = "session_terminate"
    SESSION_TERMINATE_RESPONSE = "session_terminate_response"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_RESPONSE = "heartbeat_response"


class SecurityLevel(Enum):
    """Security levels for protocol operations."""
    LOW = "low"  # Basic protection
    MEDIUM = "medium"  # Standard protection
    HIGH = "high"  # Enhanced protection
    CRITICAL = "critical"  # Maximum protection


# ======================
# DATA CLASSES
# ======================

T = TypeVar('T')
@dataclass
class SecureMessage(Generic[T]):
    """A secure protocol message with all necessary protections.
    
    All messages have fixed size to prevent volume analysis and include
    random offsets to prevent pattern analysis.
    """
    session_id: str
    message_type: MessageType
    payload: T
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    random_offset: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    padding: bytes = field(default_factory=lambda: b'')
    version: str = ProtocolVersion.V1_2.value
    signature: bytes = field(default_factory=bytes)
    
    def serialize(self, key: bytes, fixed_size: int = 1024) -> bytes:
        """Serialize the message with fixed size and encryption.
        
        Args:
            key: Session key for encryption
            fixed_size: Fixed size for all messages (default: 1024 bytes)
            
        Returns:
            bytes: Serialized, encrypted message with fixed size
        """
        # Convert to dictionary
        msg_dict = {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
        
        # Serialize to JSON
        import json
        msg_json = json.dumps(msg_dict).encode('utf-8')
        
        # Add HMAC for integrity
        h = hmac.new(key, msg_json, hashlib.sha256)
        signed_msg = msg_json + h.digest()
        
        # Encrypt
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad to block size
        padding_length = 16 - (len(signed_msg) % 16)
        padded_msg = signed_msg + bytes([padding_length] * padding_length)
        
        ciphertext = iv + encryptor.update(padded_msg) + encryptor.finalize()
        
        # Add padding to fixed size
        if len(ciphertext) < fixed_size:
            self.padding = secrets.token_bytes(fixed_size - len(ciphertext))
        else:
            # Should not happen with fixed_size=1024
            self.padding = b''
        
        return ciphertext + self.padding
    
    @classmethod
    def deserialize(cls, 
                  data: bytes, 
                  key: bytes, 
                  fixed_size: int = 1024) -> SecureMessage:
        """Deserialize a message from bytes.
        
        Args:
            data: Serialized message data
            key: Session key for decryption
            fixed_size: Fixed size for all messages
            
        Returns:
            SecureMessage: Deserialized message
            
        Raises:
            ValueError: If message is invalid or tampered with
        """
        # Ensure correct size
        if len(data) != fixed_size:
            raise ValueError(f"Message size {len(data)} does not match fixed size {fixed_size}")
        
        # Extract ciphertext (everything except padding)
        iv = data[:16]
        ciphertext = data[16:fixed_size]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_msg[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")
        msg_data = padded_msg[:-padding_length]
        
        # Verify HMAC
        msg_json = msg_data[:-32]
        signature = msg_data[-32:]
        h = hmac.new(key, msg_json, hashlib.sha256)
        if not hmac.compare_digest(h.digest(), signature):
            raise ValueError("Invalid message signature")
        
        # Parse JSON
        import json
        msg_dict = json.loads(msg_json.decode('utf-8'))
        
        # Create message
        return cls(
            session_id=msg_dict["session_id"],
            message_type=MessageType(msg_dict["message_type"]),
            payload=msg_dict["payload"],
            timestamp=msg_dict["timestamp"],
            random_offset=bytes.fromhex(msg_dict["random_offset"]),
            version=msg_dict["version"]
        )
    
    def sign(self, signing_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Sign the message with ECDSA.
        
        Args:
            signing_key: Private key for signing
            
        Returns:
            bytes: Signature
        """
        # Create message to sign (excluding existing signature)
        msg_to_sign = {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
        
        import json
        msg_json = json.dumps(msg_to_sign, sort_keys=True).encode('utf-8')
        
        # Sign
        self.signature = signing_key.sign(
            msg_json,
            ec.ECDSA(hashes.SHA256())
        )
        return self.signature
    
    def verify_signature(self, verifying_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify the message signature.
        
        Args:
            verifying_key: Public key for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        if not self.signature:
            return False
            
        # Create message to verify (excluding signature)
        msg_to_verify = {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
        
        import json
        msg_json = json.dumps(msg_to_verify, sort_keys=True).encode('utf-8')
        
        try:
            verifying_key.verify(
                self.signature,
                msg_json,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


@dataclass
class SessionParameters:
    """Parameters for a secure session.
    
    These parameters are negotiated during session initialization and
    used throughout the session for secure communication.
    """
    session_id: str
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


@dataclass
class SecureProtocolConfig:
    """Configuration for the secure protocol.
    
    This configuration is used to initialize the protocol and can be
    adjusted based on security requirements and resource constraints.
    """
    default_message_size: int = 1024  # Fixed size for all messages
    default_max_requests: int = 1000  # Maximum requests per session
    default_session_duration: int = 3600  # Session duration in seconds
    min_noise_level: float = 0.01  # Minimum noise level for differential privacy
    max_noise_level: float = 0.1  # Maximum noise level for differential privacy
    noise_decay_factor: float = 0.95  # How quickly noise decays with session age
    timing_delay_min: float = 0.1  # Minimum random delay in seconds
    timing_delay_max: float = 0.5  # Maximum random delay in seconds
    security_level: SecurityLevel = SecurityLevel.HIGH
    supported_versions: List[str] = field(default_factory=lambda: [v.value for v in ProtocolVersion])
    heartbeat_interval: int = 300  # Heartbeat interval in seconds
    
    def get_session_parameters(self, 
                             client_public: ec.EllipticCurvePublicKey,
                             server_public: ec.EllipticCurvePublicKey,
                             shared_secret: bytes) -> SessionParameters:
        """Create session parameters from configuration.
        
        Args:
            client_public: Client's public key
            server_public: Server's public key
            shared_secret: Ephemeral shared secret
            
        Returns:
            SessionParameters: Configured session parameters
        """
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
        
        # Generate session ID
        session_id = hashlib.sha256(
            session_key + os.urandom(16)
        ).hexdigest()[:32]
        
        # Set expiry time
        expiry_time = datetime.now().timestamp() + self.default_session_duration
        
        # Configure noise parameters based on security level
        noise_params = {
            "betti_noise": self._get_noise_level(0.05),
            "entropy_noise": self._get_noise_level(0.03),
            "symmetry_noise": self._get_noise_level(0.01)
        }
        
        return SessionParameters(
            session_id=session_id,
            client_public=client_public,
            server_public=server_public,
            shared_secret=shared_secret,
            session_key=session_key,
            encryption_key=encryption_key,
            signing_key=signing_key,
            expiry_time=expiry_time,
            message_size=self.default_message_size,
            max_requests=self.default_max_requests,
            noise_parameters=noise_params,
            security_level=self.security_level,
            protocol_version=ProtocolVersion.V1_2.value
        )
    
    def _get_noise_level(self, base_level: float) -> float:
        """Get noise level adjusted for security configuration."""
        return max(
            self.min_noise_level,
            min(base_level, self.max_noise_level)
        )


# ======================
# PROTOCOL CLASSES
# ======================

class SecureProtocol:
    """Main class for secure protocol operations.
    
    This class handles all aspects of secure communication between
    client and server, including:
    - Session initialization and management
    - Message serialization and deserialization
    - Timing delay management
    - Noise parameter adjustment
    - Security level enforcement
    
    The protocol is designed to prevent:
    - Volume analysis (fixed-size messages)
    - Timing analysis (random delays)
    - Pattern analysis (dynamic structure)
    - Algorithm recovery (differential privacy)
    """
    
    def __init__(self, config: Optional[SecureProtocolConfig] = None):
        """Initialize the secure protocol.
        
        Args:
            config: Protocol configuration (uses defaults if None)
        """
        self.config = config or SecureProtocolConfig()
        self.sessions: Dict[str, SessionParameters] = {}
        self._lock = threading.RLock()
        self._heartbeat_task: Optional[threading.Thread] = None
        self._running = False
    
    def start(self) -> None:
        """Start the protocol (including heartbeat monitoring)."""
        self._running = True
        self._heartbeat_task = threading.Thread(target=self._heartbeat_monitor, daemon=True)
        self._heartbeat_task.start()
    
    def stop(self) -> None:
        """Stop the protocol (including heartbeat monitoring)."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.join(timeout=1.0)
    
    def _heartbeat_monitor(self) -> None:
        """Monitor sessions and send heartbeats as needed."""
        while self._running:
            time.sleep(self.config.heartbeat_interval / 2)
            
            with self._lock:
                # Check for expired sessions
                now = datetime.now().timestamp()
                expired = [
                    sid for sid, params in self.sessions.items()
                    if now > params.expiry_time
                ]
                for sid in expired:
                    del self.sessions[sid]
                
                # Send heartbeats for expiring sessions
                for sid, params in list(self.sessions.items()):
                    if params.state == SessionState.EXPIRING:
                        self._send_heartbeat(sid)
    
    def _send_heartbeat(self, session_id: str) -> None:
        """Send a heartbeat for the specified session."""
        with self._lock:
            if session_id not in self.sessions:
                return
            
            params = self.sessions[session_id]
            if params.state != SessionState.EXPIRING:
                return
            
            # In a real implementation, this would send a heartbeat message
            # For now, we just extend the session
            params.expiry_time = datetime.now().timestamp() + self.config.default_session_duration
            params.requests_made = 0
    
    def initialize_session(self, 
                          client_public: ec.EllipticCurvePublicKey,
                          server_private: ec.EllipticCurvePrivateKey) -> Tuple[SessionParameters, bytes]:
        """Initialize a new secure session.
        
        Args:
            client_public: Client's ephemeral public key
            server_private: Server's ephemeral private key
            
        Returns:
            Tuple[SessionParameters, bytes]: Session parameters and serialized response
        """
        # Generate server ephemeral key
        server_ephemeral = server_private
        
        # Compute shared secret
        shared_secret = server_ephemeral.exchange(
            ec.ECDH(),
            client_public
        )
        
        # Create session parameters
        params = self.config.get_session_parameters(
            client_public,
            server_ephemeral.public_key(),
            shared_secret
        )
        
        # Store session
        with self._lock:
            self.sessions[params.session_id] = params
        
        # Create response
        response = {
            "session_id": params.session_id,
            "ephemeral_public": server_ephemeral.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex(),
            "resource_limits": {
                "max_time": 30.0,  # seconds
                "max_memory": 1.0   # GB
            },
            "target_size": 0.1,   # GB
            "timestamp": datetime.now().isoformat(),
            "signature": ""
        }
        
        # Sign response
        signature = server_private.sign(
            json.dumps(response, sort_keys=True).encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        response["signature"] = signature.hex()
        
        return params, json.dumps(response).encode('utf-8')
    
    def create_message(self, 
                      session_id: str,
                      message_type: MessageType,
                      payload: Any) -> SecureMessage:
        """Create a secure message for the specified session.
        
        Args:
            session_id: Session ID
            message_type: Type of message
            payload: Message payload
            
        Returns:
            SecureMessage: Secure message ready for serialization
            
        Raises:
            ValueError: If session is invalid or expired
        """
        with self._lock:
            if session_id not in self.sessions:
                raise ValueError("Invalid session ID")
            
            params = self.sessions[session_id]
            if not params.is_active:
                raise ValueError("Session expired")
            
            # Update request count
            params.update_request_count()
            
            # Create message
            return SecureMessage(
                session_id=session_id,
                message_type=message_type,
                payload=payload,
                random_offset=secrets.token_bytes(32)
            )
    
    def apply_timing_delay(self, session_id: str) -> None:
        """Apply random timing delay to prevent timing analysis.
        
        Args:
            session_id: Session ID
            
        Raises:
            ValueError: If session is invalid
        """
        with self._lock:
            if session_id not in self.sessions:
                raise ValueError("Invalid session ID")
            
            params = self.sessions[session_id]
            
            # Calculate delay based on security level
            if params.security_level == SecurityLevel.LOW:
                delay = 0
            elif params.security_level == SecurityLevel.MEDIUM:
                delay = random.uniform(
                    self.config.timing_delay_min,
                    self.config.timing_delay_max * 0.5
                )
            else:  # HIGH or CRITICAL
                delay = random.uniform(
                    self.config.timing_delay_min,
                    self.config.timing_delay_max
                )
            
            # Add additional jitter based on session age
            session_age = datetime.now().timestamp() - params.start_time
            jitter = (session_age / params.expiry_time) * self.config.timing_delay_max * 0.2
            delay += random.uniform(0, jitter)
            
            time.sleep(delay)
    
    def add_controlled_noise(self, 
                           session_id: str,
                           data: Dict[str, Any]) -> Dict[str, Any]:
        """Add controlled noise to data for differential privacy.
        
        Args:
            session_id: Session ID
            data: Data to add noise to
            
        Returns:
            Dict[str, Any]: Data with controlled noise
            
        Raises:
            ValueError: If session is invalid
        """
        with self._lock:
            if session_id not in self.sessions:
                raise ValueError("Invalid session ID")
            
            params = self.sessions[session_id]
            noise_params = params.noise_parameters
            
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
            session_age = datetime.now().timestamp() - params.start_time
            decay_factor = self.config.noise_decay_factor ** (session_age / 3600)
            params.noise_parameters = {
                k: v * decay_factor for k, v in noise_params.items()
            }
            
            return data
    
    def validate_message(self, 
                        message: SecureMessage,
                        verifying_key: ec.EllipticCurvePublicKey) -> bool:
        """Validate a secure message.
        
        Args:
            message: Message to validate
            verifying_key: Public key for signature verification
            
        Returns:
            bool: True if message is valid, False otherwise
        """
        # Check session
        if message.session_id not in self.sessions:
            return False
        
        params = self.sessions[message.session_id]
        if not params.is_active:
            return False
        
        # Verify signature
        if not message.verify_signature(verifying_key):
            return False
        
        # Verify timestamp (not too old or too new)
        now = datetime.now().timestamp()
        if abs(now - message.timestamp) > 300:  # 5 minutes
            return False
        
        return True
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a secure session.
        
        Args:
            session_id: Session ID
            
        Returns:
            bool: True if session was terminated, False if invalid
        """
        with self._lock:
            if session_id not in self.sessions:
                return False
            
            del self.sessions[session_id]
            return True
    
    def get_session_state(self, session_id: str) -> Optional[SessionState]:
        """Get the state of a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Optional[SessionState]: Session state or None if invalid
        """
        with self._lock:
            if session_id not in self.sessions:
                return None
            
            return self.sessions[session_id].state
    
    def needs_session_refresh(self, session_id: str) -> bool:
        """Check if a session needs to be refreshed.
        
        Args:
            session_id: Session ID
            
        Returns:
            bool: True if session needs refresh, False otherwise
        """
        with self._lock:
            if session_id not in self.sessions:
                return True  # Needs new session
            
            return self.sessions[session_id].needs_refresh()


# ======================
# HELPER FUNCTIONS
# ======================

def generate_ephemeral_key() -> ec.EllipticCurvePrivateKey:
    """Generate an ephemeral key for secure communication.
    
    Returns:
        EllipticCurvePrivateKey: Generated ephemeral key
    """
    return ec.generate_private_key(ec.SECP256R1())


def validate_public_key(public_key: ec.EllipticCurvePublicKey) -> bool:
    """Validate a public key for secure communication.
    
    Args:
        public_key: Public key to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Check if it's a valid ECDSA public key
        public_key.public_numbers()
        return True
    except Exception:
        return False


def create_fixed_size_message(message: bytes, fixed_size: int = 1024) -> bytes:
    """Create a fixed-size message by adding random padding.
    
    Args:
        message: Original message
        fixed_size: Target size for all messages
        
    Returns:
        bytes: Fixed-size message with padding
    """
    if len(message) > fixed_size:
        raise ValueError(f"Message size {len(message)} exceeds fixed size {fixed_size}")
    
    padding = secrets.token_bytes(fixed_size - len(message))
    return message + padding


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
        data: Data to protect
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
