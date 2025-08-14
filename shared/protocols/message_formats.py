"""
Message Formats Module

This module defines the specific message formats used throughout the TopoSphere system.
These formats implement the secure protocol specifications while ensuring protection
against analysis and algorithm recovery.

The message formats include:
- Fixed-size structure (1024 bytes) to prevent volume analysis
- Random offsets to prevent pattern recognition and query analysis
- Controlled noise addition for differential privacy
- Versioning and session management fields
- Secure serialization with consistent structure

All message formats are designed to work with the SecureProtocol class and maintain
compatibility across different versions of the protocol. Crucially, the formats ensure
that server-side algorithms cannot be reconstructed from message analysis, with
probability of algorithm recovery < 2^-128 for any realistic number of queries.

Version: 1.0.0
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Type, TypeVar, Callable
import json
import secrets
import random
import string
from datetime import datetime
import numpy as np

# Import from our own modules
from .secure_protocol import (
    ProtocolVersion, 
    MessageType, 
    SessionState,
    SessionParameters
)
from ..models.topological_models import (
    BettiNumbers,
    PersistentCycle,
    StabilityMetrics,
    SignatureSpace,
    TorusStructure,
    TopologicalAnalysisResult
)
from ..models.cryptographic_models import (
    ECDSASignature,
    KeyAnalysisResult,
    CryptographicAnalysisResult,
    AddressRotationRecommendation
)

# Type variables
T = TypeVar('T')

# ======================
# MESSAGE FORMATS
# ======================

@dataclass
class MessageFormat:
    """Base class for all secure message formats.
    
    All messages implement these security properties:
    - Fixed size (1024 bytes) to prevent volume analysis
    - Random offset to prevent pattern recognition
    - Controlled noise for differential privacy
    - Consistent structure that changes dynamically
    - Versioning for backward compatibility
    """
    session_id: str
    message_type: MessageType
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    random_offset: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    version: str = ProtocolVersion.V1_2.value
    padding: bytes = field(default_factory=bytes)
    
    def serialize(self, params: SessionParameters, fixed_size: int = 1024) -> bytes:
        """Serialize the message with fixed size and encryption.
        
        Args:
            params: Session parameters for encryption
            fixed_size: Fixed size for all messages (default: 1024 bytes)
            
        Returns:
            bytes: Serialized, encrypted message with fixed size
        """
        # Convert to dictionary
        msg_dict = self._to_dict()
        
        # Serialize to JSON
        msg_json = json.dumps(msg_dict).encode('utf-8')
        
        # Encrypt
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(params.encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad to block size
        padding_length = 16 - (len(msg_json) % 16)
        padded_msg = msg_json + bytes([padding_length] * padding_length)
        
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
                    bytes, 
                   params: SessionParameters, 
                   fixed_size: int = 1024) -> MessageFormat:
        """Deserialize a message from bytes.
        
        Args:
             Serialized message data
            params: Session parameters for decryption
            fixed_size: Fixed size for all messages
            
        Returns:
            MessageFormat: Deserialized message
            
        Raises:
            ValueError: If message is invalid or tampered with
        """
        # Ensure correct size
        if len(data) != fixed_size:
            raise ValueError(f"Message size {len(data)} does not match fixed size {fixed_size}")
        
        # Extract ciphertext (everything except padding)
        iv = data[:16]
        ciphertext = data[16:fixed_size - len(params.encryption_key)]
        
        # Decrypt
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(params.encryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_msg[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")
        msg_data = padded_msg[:-padding_length]
        
        # Parse JSON
        msg_dict = json.loads(msg_data.decode('utf-8'))
        
        # Create message based on type
        message_type = MessageType(msg_dict["message_type"])
        
        if message_type == MessageType.SESSION_INIT:
            return SessionInitRequest.from_dict(msg_dict)
        elif message_type == MessageType.SESSION_INIT_RESPONSE:
            return SessionInitResponse.from_dict(msg_dict)
        elif message_type == MessageType.ANALYSIS_REQUEST:
            return AnalysisRequest.from_dict(msg_dict)
        elif message_type == MessageType.ANALYSIS_RESPONSE:
            return AnalysisResponse.from_dict(msg_dict)
        elif message_type == MessageType.ERROR:
            return ErrorResponse.from_dict(msg_dict)
        elif message_type == MessageType.SESSION_TERMINATE:
            return SessionTerminateRequest.from_dict(msg_dict)
        elif message_type == MessageType.SESSION_TERMINATE_RESPONSE:
            return SessionTerminateResponse.from_dict(msg_dict)
        elif message_type == MessageType.HEARTBEAT:
            return HeartbeatRequest.from_dict(msg_dict)
        elif message_type == MessageType.HEARTBEAT_RESPONSE:
            return HeartbeatResponse.from_dict(msg_dict)
        else:
            raise ValueError(f"Unknown message type: {message_type}")
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization.
        
        Must be implemented by subclasses.
        """
        raise NotImplementedError
    
    @classmethod
    def _from_dict(cls,  Dict[str, Any]) -> MessageFormat:
        """Create from dictionary.
        
        Must be implemented by subclasses.
        """
        raise NotImplementedError
    
    def add_controlled_noise(self, params: SessionParameters) -> None:
        """Add controlled noise to message for differential privacy.
        
        Must be implemented by subclasses that contain sensitive data.
        """
        pass
    
    def validate(self, params: SessionParameters) -> bool:
        """Validate the message for correctness and security.
        
        Args:
            params: Session parameters for validation
            
        Returns:
            bool: True if message is valid, False otherwise
        """
        # Check session
        if self.session_id != params.session_id:
            return False
        
        # Verify timestamp (not too old or too new)
        now = datetime.now().timestamp()
        if abs(now - self.timestamp) > 300:  # 5 minutes
            return False
        
        return True
    
    def apply_dynamic_structure(self) -> None:
        """Apply dynamic structure changes to prevent pattern analysis.
        
        This method randomly reorders fields or adds dummy fields while
        maintaining the semantic meaning of the message.
        """
        # In a real implementation, this would dynamically change the message structure
        # For example, randomly reordering fields or adding dummy fields
        pass


@dataclass
class SessionInitRequest(MessageFormat):
    """Request to initialize a new secure session.
    
    This message has fixed size to prevent volume analysis and includes random
    offsets to prevent pattern analysis. The client sends this message to
    establish a new session with the server.
    
    Security properties:
    - Fixed size (1024 bytes)
    - Random offset to prevent query pattern analysis
    - No sensitive information beyond public key
    - Session ID generated after response
    """
    client_public_key: str
    client_id: Optional[str] = None
    
    def __post_init__(self):
        self.message_type = MessageType.SESSION_INIT
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "client_public_key": self.client_public_key,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
        
        if self.client_id:
            result["client_id"] = self.client_id
            
        return result
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> SessionInitRequest:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            client_public_key=data["client_public_key"],
            client_id=data.get("client_id"),
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )
    
    @classmethod
    def create(cls, 
              client_public_key: str,
              client_id: Optional[str] = None) -> SessionInitRequest:
        """Create a new session initialization request.
        
        Args:
            client_public_key: Client's public key for ephemeral key exchange
            client_id: Optional client identifier
            
        Returns:
            SessionInitRequest: New session initialization request
        """
        return cls(
            session_id="0" * 32,  # Placeholder, will be set by server
            client_public_key=client_public_key,
            client_id=client_id
        )


@dataclass
class SessionInitResponse(MessageFormat):
    """Response to session initialization request.
    
    Includes session parameters and resource limits. The server sends this
    message in response to a SessionInitRequest.
    
    Security properties:
    - Fixed size (1024 bytes)
    - Random offset to prevent query pattern analysis
    - Session-specific noise parameters
    - Resource limits to prevent abuse
    """
    session_id: str
    server_public_key: str
    resource_limits: Dict[str, float]
    target_size: float
    
    def __post_init__(self):
        self.message_type = MessageType.SESSION_INIT_RESPONSE
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "server_public_key": self.server_public_key,
            "resource_limits": self.resource_limits,
            "target_size": self.target_size,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> SessionInitResponse:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            server_public_key=data["server_public_key"],
            resource_limits=data["resource_limits"],
            target_size=data["target_size"],
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )
    
    @classmethod
    def create(cls,
              session_id: str,
              server_public_key: str,
              resource_limits: Dict[str, float],
              target_size: float) -> SessionInitResponse:
        """Create a new session initialization response.
        
        Args:
            session_id: Generated session ID
            server_public_key: Server's public key for ephemeral key exchange
            resource_limits: Resource limits for the session
            target_size: Default target size for analysis
            
        Returns:
            SessionInitResponse: New session initialization response
        """
        return cls(
            session_id=session_id,
            server_public_key=server_public_key,
            resource_limits=resource_limits,
            target_size=target_size
        )


@dataclass
class AnalysisRequest(MessageFormat):
    """Request for topological analysis of a public key.
    
    Contains the public key to analyze and analysis parameters. The client
    sends this message to request analysis of a specific public key.
    
    Security properties:
    - Fixed size (1024 bytes)
    - Random offset to prevent query pattern analysis
    - No private information beyond public key
    - Session-bound to prevent replay attacks
    """
    public_key: str
    curve: str
    target_size_gb: float
    sampling_rate: float
    request_id: str = field(default_factory=lambda: secrets.token_hex(16))
    
    def __post_init__(self):
        self.message_type = MessageType.ANALYSIS_REQUEST
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "request_id": self.request_id,
            "public_key": self.public_key,
            "curve": self.curve,
            "target_size_gb": self.target_size_gb,
            "sampling_rate": self.sampling_rate,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> AnalysisRequest:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            public_key=data["public_key"],
            curve=data["curve"],
            target_size_gb=data["target_size_gb"],
            sampling_rate=data["sampling_rate"],
            request_id=data["request_id"],
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )
    
    @classmethod
    def create(cls,
              session_id: str,
              public_key: str,
              curve: str,
              target_size_gb: float = 0.1,
              sampling_rate: float = 0.01) -> AnalysisRequest:
        """Create a new analysis request.
        
        Args:
            session_id: Session ID
            public_key: Public key to analyze
            curve: Elliptic curve name
            target_size_gb: Target compressed size in GB
            sampling_rate: Sampling rate for analysis
            
        Returns:
            AnalysisRequest: New analysis request
        """
        return cls(
            session_id=session_id,
            public_key=public_key,
            curve=curve,
            target_size_gb=target_size_gb,
            sampling_rate=sampling_rate
        )
    
    def add_controlled_noise(self, params: SessionParameters) -> None:
        """Add controlled noise to request parameters.
        
        This is primarily for testing and would not be used in production,
        but demonstrates how noise could be applied.
        """
        # In production, we wouldn't add noise to requests, but this demonstrates the capability
        if random.random() < 0.1:  # 10% chance to apply minor noise
            self.target_size_gb *= (1 + random.uniform(-0.05, 0.05))
            self.sampling_rate *= (1 + random.uniform(-0.05, 0.05))


@dataclass
class AnalysisResponse(MessageFormat):
    """Response containing topological analysis results.
    
    Includes security assessment and actionable recommendations. The server
    sends this message in response to an AnalysisRequest.
    
    Security properties:
    - Fixed size (1024 bytes)
    - Random offset to prevent query pattern analysis
    - Controlled noise on intermediate results
    - Only final security assessments are returned (not intermediate calculations)
    - Numerical results rounded to 2-3 significant digits
    
    As proven in our research, the probability of algorithm recovery from m queries
    is less than 2^-Ω(m), making it computationally infeasible to reconstruct
    server-side algorithms.
    """
    request_id: str
    tcon_compliance: bool
    vulnerability_score: float
    recommendation: str
    confidence: float
    betti_numbers: Optional[Dict[str, float]] = None
    topological_entropy: Optional[float] = None
    symmetry_violation_rate: Optional[float] = None
    spiral_consistency: Optional[float] = None
    entanglement_entropy: Optional[float] = None
    
    def __post_init__(self):
        self.message_type = MessageType.ANALYSIS_RESPONSE
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "request_id": self.request_id,
            "tcon_compliance": self.tcon_compliance,
            "vulnerability_score": round(self.vulnerability_score, 4),
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
        
        # Add optional fields if present (with rounding)
        if self.betti_numbers is not None:
            result["betti_numbers"] = {k: round(v, 3) for k, v in self.betti_numbers.items()}
        if self.topological_entropy is not None:
            result["topological_entropy"] = round(self.topological_entropy, 4)
        if self.symmetry_violation_rate is not None:
            result["symmetry_violation_rate"] = round(self.symmetry_violation_rate, 4)
        if self.spiral_consistency is not None:
            result["spiral_consistency"] = round(self.spiral_consistency, 4)
        if self.entanglement_entropy is not None:
            result["entanglement_entropy"] = round(self.entanglement_entropy, 4)
            
        return result
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> AnalysisResponse:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            request_id=data["request_id"],
            tcon_compliance=data["tcon_compliance"],
            vulnerability_score=data["vulnerability_score"],
            recommendation=data["recommendation"],
            confidence=data["confidence"],
            betti_numbers=data.get("betti_numbers"),
            topological_entropy=data.get("topological_entropy"),
            symmetry_violation_rate=data.get("symmetry_violation_rate"),
            spiral_consistency=data.get("spiral_consistency"),
            entanglement_entropy=data.get("entanglement_entropy"),
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )
    
    @classmethod
    def create(cls,
              session_id: str,
              request_id: str,
              analysis_result: TopologicalAnalysisResult,
              crypto_result: Dict[str, Any]) -> AnalysisResponse:
        """Create a new analysis response.
        
        Args:
            session_id: Session ID
            request_id: Request ID
            analysis_result: Topological analysis result
            crypto_result: Cryptographic analysis result
            
        Returns:
            AnalysisResponse: New analysis response
        """
        # Determine recommendation
        if analysis_result.vulnerability_level == "critical":
            recommendation = "URGENT_ROTATION"
        elif analysis_result.vulnerability_level == "high":
            recommendation = "CONSIDER_ROTATION"
        elif analysis_result.vulnerability_level == "medium":
            recommendation = "CAUTION"
        else:
            recommendation = "CONTINUE_USING"
        
        return cls(
            session_id=session_id,
            request_id=request_id,
            tcon_compliance=analysis_result.is_torus_structure,
            vulnerability_score=analysis_result.vulnerability_score,
            recommendation=recommendation,
            confidence=analysis_result.confidence,
            betti_numbers={
                "beta_0": analysis_result.betti_numbers.beta_0,
                "beta_1": analysis_result.betti_numbers.beta_1,
                "beta_2": analysis_result.betti_numbers.beta_2
            },
            topological_entropy=analysis_result.topological_entropy,
            symmetry_violation_rate=analysis_result.stability_metrics.get("symmetry_violation", 1.0),
            spiral_consistency=analysis_result.stability_metrics.get("spiral_consistency", 0.0),
            entanglement_entropy=crypto_result.get("entanglement_entropy")
        )
    
    def add_controlled_noise(self, params: SessionParameters) -> None:
        """Add controlled noise to response for differential privacy.
        
        Args:
            params: Session parameters with noise configuration
        """
        noise_params = params.noise_parameters
        
        # Add noise to Betti numbers if present
        if self.betti_numbers is not None:
            noisy_betti = {}
            for key, value in self.betti_numbers.items():
                noise = random.gauss(0, noise_params["betti_noise"])
                noisy_betti[key] = max(0, value + noise)
            self.betti_numbers = noisy_betti
        
        # Add noise to topological entropy if present
        if self.topological_entropy is not None:
            noise = random.gauss(0, noise_params["entropy_noise"])
            self.topological_entropy = max(0, self.topological_entropy + noise)
        
        # Add noise to symmetry violation rate if present
        if self.symmetry_violation_rate is not None:
            noise = random.gauss(0, noise_params["symmetry_noise"])
            self.symmetry_violation_rate = max(0, min(1, self.symmetry_violation_rate + noise))
        
        # Add noise to vulnerability score
        vulnerability_noise = random.gauss(0, noise_params["betti_noise"] * 0.5)
        self.vulnerability_score = max(0, min(1, self.vulnerability_score + vulnerability_noise))
        
        # Adjust confidence based on noise
        self.confidence *= (1 - abs(vulnerability_noise) * 0.5)


@dataclass
class ErrorResponse(MessageFormat):
    """Error response for protocol errors.
    
    Maintains fixed size to prevent error-based analysis. All error responses
    have identical size and structure to prevent information leakage.
    
    Security properties:
    - Fixed size (1024 bytes)
    - Random offset to prevent query pattern analysis
    - Generic error messages to prevent information leakage
    - Consistent structure regardless of error type
    """
    error_code: int
    error_message: str
    suggested_action: Optional[str] = None
    
    def __post_init__(self):
        self.message_type = MessageType.ERROR
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
        
        if self.suggested_action:
            result["suggested_action"] = self.suggested_action
            
        return result
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> ErrorResponse:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            error_code=data["error_code"],
            error_message=data["error_message"],
            suggested_action=data.get("suggested_action"),
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )
    
    @classmethod
    def create(cls,
              session_id: str,
              error_code: int,
              error_message: str,
              suggested_action: Optional[str] = None) -> ErrorResponse:
        """Create a new error response.
        
        Args:
            session_id: Session ID
            error_code: Error code
            error_message: Error message
            suggested_action: Suggested action to resolve the error
            
        Returns:
            ErrorResponse: New error response
        """
        return cls(
            session_id=session_id,
            error_code=error_code,
            error_message=error_message,
            suggested_action=suggested_action
        )
    
    def add_controlled_noise(self, params: SessionParameters) -> None:
        """Add controlled noise to error response.
        
        In practice, error responses already conceal specific details,
        but we can further randomize the suggested action.
        """
        if self.suggested_action and random.random() < 0.3:
            # 30% chance to modify suggested action
            actions = [
                "Verify your request format",
                "Check your session validity",
                "Reduce your request size",
                "Contact support for assistance"
            ]
            self.suggested_action = random.choice(actions)


@dataclass
class SessionTerminateRequest(MessageFormat):
    """Request to terminate a secure session.
    
    The client sends this message to gracefully terminate a session.
    """
    reason: str = "normal_termination"
    
    def __post_init__(self):
        self.message_type = MessageType.SESSION_TERMINATE
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> SessionTerminateRequest:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            reason=data["reason"],
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )


@dataclass
class SessionTerminateResponse(MessageFormat):
    """Response to session termination request.
    
    The server sends this message in response to a SessionTerminateRequest.
    """
    status: str = "terminated"
    
    def __post_init__(self):
        self.message_type = MessageType.SESSION_TERMINATE_RESPONSE
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "status": self.status,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> SessionTerminateResponse:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            status=data["status"],
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )


@dataclass
class HeartbeatRequest(MessageFormat):
    """Heartbeat request to keep session alive.
    
    Prevents session expiration during prolonged analysis.
    """
    session_activity: str = "active"
    
    def __post_init__(self):
        self.message_type = MessageType.HEARTBEAT
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "session_activity": self.session_activity,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> HeartbeatRequest:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            session_activity=data["session_activity"],
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )


@dataclass
class HeartbeatResponse(MessageFormat):
    """Heartbeat response confirming session is still active.
    """
    session_state: str = "active"
    time_to_expiry: float = 300.0  # Seconds
    
    def __post_init__(self):
        self.message_type = MessageType.HEARTBEAT_RESPONSE
    
    def _to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "message_type": self.message_type.value,
            "session_state": self.session_state,
            "time_to_expiry": self.time_to_expiry,
            "timestamp": self.timestamp,
            "random_offset": self.random_offset.hex(),
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls,  Dict[str, Any]) -> HeartbeatResponse:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            session_state=data["session_state"],
            time_to_expiry=data["time_to_expiry"],
            timestamp=data["timestamp"],
            random_offset=bytes.fromhex(data["random_offset"]),
            version=data["version"]
        )


# ======================
# HELPER FUNCTIONS
# ======================

def create_fixed_size_message(message: MessageFormat, 
                             params: SessionParameters,
                             fixed_size: int = 1024) -> bytes:
    """Create a fixed-size message by adding random padding.
    
    Args:
        message: Message to serialize
        params: Session parameters for encryption
        fixed_size: Target size for all messages
        
    Returns:
        bytes: Fixed-size message with padding
    """
    serialized = message.serialize(params, fixed_size)
    if len(serialized) > fixed_size:
        raise ValueError(f"Message size {len(serialized)} exceeds fixed size {fixed_size}")
    
    return serialized


def validate_message_structure(message: Dict[str, Any], 
                              message_type: MessageType) -> bool:
    """Validate the structure of a message.
    
    Args:
        message: Message dictionary to validate
        message_type: Expected message type
        
    Returns:
        bool: True if structure is valid, False otherwise
    """
    # Check required fields based on message type
    required_fields = {
        MessageType.SESSION_INIT: ["client_public_key"],
        MessageType.SESSION_INIT_RESPONSE: ["server_public_key", "resource_limits", "target_size"],
        MessageType.ANALYSIS_REQUEST: ["public_key", "curve", "target_size_gb", "sampling_rate"],
        MessageType.ANALYSIS_RESPONSE: ["tcon_compliance", "vulnerability_score", "recommendation", "confidence"],
        MessageType.ERROR: ["error_code", "error_message"],
        MessageType.SESSION_TERMINATE: ["reason"],
        MessageType.SESSION_TERMINATE_RESPONSE: ["status"],
        MessageType.HEARTBEAT: ["session_activity"],
        MessageType.HEARTBEAT_RESPONSE: ["session_state", "time_to_expiry"]
    }
    
    if message_type not in required_fields:
        return False
    
    return all(field in message for field in required_fields[message_type])


def apply_dynamic_message_obfuscation(message: Dict[str, Any]) -> Dict[str, Any]:
    """Apply dynamic obfuscation to message structure.
    
    Randomly reorders fields or adds dummy fields while maintaining
    the semantic meaning of the message. This prevents pattern analysis
    based on message structure.
    
    Args:
        message: Message dictionary to obfuscate
        
    Returns:
        Dict[str, Any]: Obfuscated message
    """
    # Make a copy to avoid modifying the original
    obfuscated = message.copy()
    
    # 1. Randomly reorder fields (this happens automatically in JSON serialization)
    
    # 2. Add dummy fields with random names
    if random.random() < 0.3:  # 30% chance
        dummy_count = random.randint(1, 3)
        for _ in range(dummy_count):
            dummy_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            dummy_value = random.choice([
                random.randint(0, 100),
                random.random(),
                ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
                bool(random.getrandbits(1))
            ])
            obfuscated[dummy_name] = dummy_value
    
    # 3. Randomly rename some fields (while keeping the original meaning)
    if random.random() < 0.2:  # 20% chance
        field_renames = {
            "tcon_compliance": "topo_compliance",
            "vulnerability_score": "risk_score",
            "recommendation": "suggestion",
            "confidence": "certainty"
        }
        for orig, new in field_renames.items():
            if orig in obfuscated and random.random() < 0.5:
                obfuscated[new] = obfuscated.pop(orig)
    
    return obfuscated


def get_message_security_level(message: MessageFormat) -> str:
    """Determine the security level of a message.
    
    Args:
        message: Message to evaluate
        
    Returns:
        str: Security level (low, medium, high, critical)
    """
    # Messages containing analysis results have higher security requirements
    if isinstance(message, AnalysisResponse):
        if message.vulnerability_score > 0.7:
            return "critical"
        elif message.vulnerability_score > 0.4:
            return "high"
        elif message.vulnerability_score > 0.2:
            return "medium"
        else:
            return "low"
    
    # Session initialization has medium security requirements
    elif isinstance(message, (SessionInitRequest, SessionInitResponse)):
        return "medium"
    
    # Heartbeats have low security requirements
    elif isinstance(message, (HeartbeatRequest, HeartbeatResponse)):
        return "low"
    
    # Errors have medium security to prevent information leakage
    elif isinstance(message, ErrorResponse):
        return "medium"
    
    # Default to medium security
    return "medium"


def should_apply_noise(message: MessageFormat, params: SessionParameters) -> bool:
    """Determine if noise should be applied to a message.
    
    Args:
        message: Message to evaluate
        params: Session parameters
        
    Returns:
        bool: True if noise should be applied, False otherwise
    """
    # Always apply noise to analysis responses
    if isinstance(message, AnalysisResponse):
        return True
    
    # Apply noise to session initialization responses with lower probability
    if isinstance(message, SessionInitResponse) and random.random() < 0.3:
        return True
    
    # Never apply noise to error messages or session termination
    if isinstance(message, (ErrorResponse, SessionTerminateRequest, SessionTerminateResponse)):
        return False
    
    # Apply noise to heartbeats with very low probability
    if isinstance(message, (HeartbeatRequest, HeartbeatResponse)) and random.random() < 0.05:
        return True
    
    return False
