# Getting Started with TopoSphere

## Introduction

Welcome to TopoSphere, a revolutionary framework for topological analysis of ECDSA implementations. Unlike traditional auditing tools, TopoSphere treats the ECDSA signature space as a topological torus, enabling unprecedented vulnerability detection while protecting intellectual property through a client-server architecture.

> "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities. Ignoring it means building cryptography on sand." - TopoSphere Research Team

This guide will help you quickly set up and start using TopoSphere for analyzing ECDSA implementations. By the end of this guide, you'll be able to:
- Install and configure TopoSphere
- Perform basic security analysis on ECDSA implementations
- Interpret the results of topological analysis
- Integrate TopoSphere with your existing cryptographic systems

## Prerequisites

Before installing TopoSphere, ensure you have:

- Python 3.8 or newer
- pip package manager
- Basic understanding of ECDSA and elliptic curve cryptography
- A system with at least 4GB of RAM (for full analysis capabilities)
- Optional: Docker (for containerized server deployment)

## Installation

### Client Installation

TopoSphere client can be installed via pip:

```bash
# Create a virtual environment (recommended)
python -m venv topsphere-env
source topsphere-env/bin/activate  # Linux/MacOS
topsphere-env\Scripts\activate    # Windows

# Install TopoSphere client
pip install topsphere-client
```

### Server Installation (Optional)

For full functionality, you may want to set up your own TopoSphere server:

```bash
# Clone the repository
git clone https://github.com/toposphere/server.git
cd server

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Start the server
python main.py
```

Alternatively, you can use the Docker setup:

```bash
docker-compose up -d
```

## Basic Configuration

### Client Configuration

After installation, configure your client:

```python
from topsphere.client import ClientConfig

# Create a configuration file
config = ClientConfig(
    server_url="https://api.toposphere.security",  # or your self-hosted server
    api_key="your_api_key_here",
    default_curve="secp256k1",
    resource_limits={
        "max_time": 30.0,  # seconds
        "max_memory": 1.0   # GB
    }
)

# Save configuration
config.save("~/.toposphere/config.json")
```

### Server Configuration (if self-hosting)

Edit the `.env` file to set your preferences:

```ini
# Server configuration
HOST=0.0.0.0
PORT=8000
DEBUG=False

# Resource limits
MAX_TIME=30.0
MAX_MEMORY=1.0
MAX_REQUESTS_PER_MINUTE=60

# Security settings
JWT_SECRET=your_strong_secret_here
ALLOWED_ORIGINS=https://your-client-app.com
```

## Quick Start Guide

### Analyzing a Public Key

Let's analyze a Bitcoin public key to check its security:

```python
from topsphere.client import TopologicalOracle, SecurityRecommender

# Initialize the oracle
oracle = TopologicalOracle(
    server_url="https://api.toposphere.security",
    api_key="your_api_key"
)

# Your Bitcoin public key (hex format)
public_key_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Analyze the public key
analysis = oracle.analyze(
    public_key=public_key_hex,
    curve="secp256k1",
    target_size_gb=0.1  # Target compressed size in GB
)

# Print security assessment
print(f"Topological conformance: {analysis['tcon_compliance']}")
print(f"Vulnerability score: {analysis['vulnerability_score']:.4f}")
print(f"Recommendation: {analysis['recommendation']}")
print(f"Confidence: {analysis['confidence']:.2f}")

# Get security recommendations
recommender = SecurityRecommender()
recommendation = recommender.get_recommendation(
    public_key_hex,
    analysis=analysis
)
print(f"\nSecurity recommendation: {recommendation['action']}")
print(f"Reason: {recommendation['reason']}")
```

### Generating Synthetic Signatures for Testing

You can generate synthetic signatures without knowing the private key:

```python
from topsphere.client import SyntheticSignatureGenerator

# Initialize the generator
generator = SyntheticSignatureGenerator(curve="secp256k1")

# Generate 1000 synthetic signatures
signatures = generator.generate(
    public_key=public_key_hex,
    num_samples=1000
)

# Use these signatures for testing your implementation
print(f"Generated {len(signatures)} synthetic signatures")
print(f"Example signature: r={signatures[0]['r']}, s={signatures[0]['s']}, z={signatures[0]['z']}")
```

### Dynamic Vulnerability Analysis

Track security over time to determine optimal address rotation:

```python
from topsphere.client import DynamicVulnerabilityAnalyzer

# Initialize the analyzer
analyzer = DynamicVulnerabilityAnalyzer()

# Add historical analysis results
for i in range(1, 101):
    # In a real scenario, you'd get this from previous analyses
    analysis = {
        "vulnerability_score": 0.01 * i,  # Simulated increasing vulnerability
        "timestamp": f"2023-01-{i:02d}T12:00:00Z"
    }
    analyzer.update(analysis)

# Predict future vulnerability
prediction = analyzer.predict_vulnerability_risk(future_steps=10)
print(f"\nPredicted vulnerability in 10 transactions: {prediction['vulnerability_probability']:.4f}")
print(f"Optimal address change point: {prediction['optimal_change_point']} transactions")
```

## Understanding the Output

### Topological Analysis Results

When you run an analysis, TopoSphere returns a comprehensive report with these key metrics:

| Metric | Description | Secure Value |
|--------|-------------|--------------|
| `tcon_compliance` | Whether the implementation conforms to topological standards | True |
| `vulnerability_score` | Quantitative measure of vulnerability (0-1) | < 0.2 |
| `betti_numbers` | Topological invariants (β₀, β₁, β₂) | [1.0, 2.0, 1.0] |
| `symmetry_violation_rate` | Rate of diagonal symmetry violations | < 0.01 |
| `entanglement_entropy` | Quantum-inspired security metric | > 0.5 |
| `spiral_consistency` | Consistency with expected spiral structure | > 0.7 |

**Example Interpretation**:
- If `betti_numbers[1] < 1.5`, this indicates a critical vulnerability
- If `entanglement_entropy < 0.5`, the implementation is highly vulnerable
- If `symmetry_violation_rate > 0.05`, there are systematic issues in nonce generation

### Security Recommendations

TopoSphere provides actionable security recommendations:

| Recommendation | When to Use | Action |
|----------------|-------------|--------|
| `continue_using` | When `vulnerability_score < 0.1` | Continue using the current address |
| `consider_rotation` | When `0.1 ≤ vulnerability_score < 0.3` | Consider rotating to a new address soon |
| `urgent_rotation` | When `vulnerability_score ≥ 0.3` | Immediately rotate to a new address |

## Troubleshooting Common Issues

### Issue: "Analysis takes too long"

**Solution**: Adjust the target size parameter to reduce resource requirements:

```python
analysis = oracle.analyze(
    public_key=public_key_hex,
    curve="secp256k1",
    target_size_gb=0.01  # Reduced from 0.1 to 0.01
)
```

### Issue: "Public key format error"

**Solution**: Ensure your public key is in the correct format:

```python
# For compressed public keys (starting with 02 or 03)
compressed_key = "02" + public_key_x_hex

# For uncompressed public keys (starting with 04)
uncompressed_key = "04" + public_key_x_hex + public_key_y_hex
```

### Issue: "High vulnerability score despite RFC 6979"

**Solution**: Even RFC 6979 implementations can have vulnerabilities. Check:
- Whether the same address is being reused
- Potential implementation errors in the HMAC-DRBG
- Systematic deviations in the random number generator

TopoSphere can detect these issues through topological analysis even when standard tests pass.

## Next Steps

### Advanced Analysis Techniques

Once you're comfortable with the basics, explore these advanced features:

#### Quantum Scanning
```python
from topsphere.client import QuantumScanner

scanner = QuantumScanner()
entropy = scanner.scan(public_key_hex, curve="secp256k1")
print(f"Entanglement entropy: {entropy:.4f}")
```

#### Differential Topological Analysis
```python
from topsphere.client import DifferentialTopologicalAnalyzer

analyzer = DifferentialTopologicalAnalyzer()
comparison = analyzer.compare(
    target_public_key=target_key,
    reference_public_keys=[ref_key1, ref_key2, ref_key3]
)
print(f"Topological distance: {comparison['topological_distance']:.4f}")
```

#### TCON Verification
```python
from topsphere.client import TCONVerifier

verifier = TCONVerifier()
result = verifier.verify(public_key_hex, curve="secp256k1")
print(f"TCON compliance: {result['compliance']}")
print(f"Confidence: {result['confidence']:.2f}")
```

### Integration with Existing Systems

TopoSphere provides integrations with common cryptographic systems:

#### Bitcoin Wallet Integration
```python
from topsphere.integrations import BitcoinWalletIntegration

integration = BitcoinWalletIntegration()
wallet_analysis = integration.analyze_wallet("path/to/wallet.dat")
print(f"Wallet security status: {wallet_analysis['security_status']}")
```

#### OpenSSL Integration
```python
from topsphere.integrations import OpenSSLIntegration

integration = OpenSSLIntegration()
openssl_analysis = integration.analyze_implementation()
print(f"OpenSSL ECDSA implementation secure: {openssl_analysis['secure']}")
```

## Support and Community

- **Documentation**: [https://docs.toposphere.security](https://docs.toposphere.security)
- **GitHub Issues**: [https://github.com/toposphere/ecdsa-analysis/issues](https://github.com/toposphere/ecdsa-analysis/issues)
- **Security Vulnerabilities**: Please report via SECURITY.md
- **Research Papers**: [https://research.toposphere.security](https://research.toposphere.security)

## Conclusion

You've now learned how to set up and use TopoSphere for topological analysis of ECDSA implementations. By leveraging the mathematical properties of the ECDSA signature space as a torus, TopoSphere provides unique insights into cryptographic security that traditional methods miss.

Remember the fundamental security principle: "The main protection is not to reveal the public key and to use a new address after each transaction." TopoSphere helps you verify and enforce this principle through rigorous mathematical analysis.

As you continue exploring TopoSphere, you'll discover how topological methods can transform your approach to cryptographic security - not as a reactive process, but as a proactive assurance based on solid mathematical foundations.

#ecdsa #cryptography #topology #security #blockchain #bitcoin #postquantum #cryptanalysis #math #sheaftheory #torus #hypercube #digitalsecurity #privacy #quantumcomputing
