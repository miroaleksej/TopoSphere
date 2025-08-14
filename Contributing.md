# Contributing to TopoSphere

Thank you for your interest in contributing to TopoSphere! We welcome contributions that enhance the topological analysis capabilities, improve security guarantees, and expand the framework's applicability to cryptographic systems.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Improving Documentation](#improving-documentation)
- [Pull Request Process](#pull-request-process)
- [Development Guidelines](#development-guidelines)
  - [Coding Standards](#coding-standards)
  - [Testing Requirements](#testing-requirements)
  - [Documentation Standards](#documentation-standards)
- [Scientific Contribution Guidelines](#scientific-contribution-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Additional Resources](#additional-resources)

## Code of Conduct
This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs
When reporting bugs, please follow these guidelines:

1. **Check if the bug has already been reported** by searching the [Issues](https://github.com/toposphere/ecdsa-analysis/issues) section.

2. **Create a new issue** with the "Bug Report" template if it hasn't been reported.

3. **Provide detailed information**:
   - TopoSphere version
   - Python version
   - Operating system
   - Steps to reproduce the issue
   - Expected behavior vs. actual behavior
   - Error logs or screenshots if applicable
   - Mathematical context if relevant (e.g., curve parameters, Betti numbers)

4. **Include a minimal working example** that demonstrates the bug.

### Suggesting Enhancements
We welcome suggestions for new features or improvements:

1. **Check if the enhancement has already been suggested** by searching the [Issues](https://github.com/toposphere/ecdsa-analysis/issues) section.

2. **Create a new issue** with the "Feature Request" template.

3. **Provide a clear rationale** for the enhancement:
   - Explain the problem it solves
   - Describe the proposed solution
   - Include mathematical justification if applicable (e.g., how it relates to topological properties, Betti numbers, torus structure)
   - Explain how it fits with TopoSphere's core philosophy: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities"

4. **Consider potential security implications** of the proposed enhancement.

### Your First Code Contribution
Looking to contribute code? Here's how to get started:

1. **Fork the repository** and create a new branch for your feature/fix.

2. **Set up your development environment**:
   ```bash
   git clone https://github.com/your-username/toposphere.git
   cd topsphere
   python -m venv venv
   source venv/bin/activate  # Linux/MacOS
   venv\Scripts\activate    # Windows
   pip install -r requirements-dev.txt
   ```

3. **Run the test suite** to ensure everything works:
   ```bash
   pytest
   ```

4. **Make your changes** following our [Development Guidelines](#development-guidelines).

5. **Add tests** for your changes.

6. **Update documentation** as needed.

7. **Submit a pull request** following the [Pull Request Process](#pull-request-process).

### Improving Documentation
Documentation improvements are always welcome:

1. **Check our [Documentation Structure](docs/)** to understand where your contribution fits.

2. **Follow the documentation standards** outlined in [Documentation Standards](#documentation-standards).

3. **Focus on clarity and scientific rigor** - TopoSphere documentation should maintain mathematical precision while being accessible.

4. **Include examples** for complex concepts, especially those related to topological analysis, Betti numbers, and torus structures.

## Pull Request Process
1. **Ensure your branch is up-to-date** with the main branch:
   ```bash
   git fetch origin
   git rebase origin/main
   ```

2. **Reference the related issue** in your pull request description (e.g., "Fixes #123").

3. **Provide a detailed description** of your changes, including:
   - The problem being solved
   - Mathematical justification (if applicable)
   - How your changes align with TopoSphere's security model
   - Performance implications

4. **Ensure all tests pass** and you've added appropriate tests for new functionality.

5. **Wait for review** from maintainers. We aim to review pull requests within 7 business days.

6. **Address review comments** promptly and thoroughly.

7. **Squash commits** before final merge to maintain a clean history.

## Development Guidelines

### Coding Standards
- **Follow PEP 8** for Python code style.
- **Use type hints** for all function signatures.
- **Write docstrings** in Google format for all public functions and classes.
- **Maintain mathematical precision** in comments and documentation.
- **Avoid global variables** - use dependency injection where appropriate.
- **Keep functions focused** on a single responsibility.
- **Use meaningful variable names** that reflect mathematical concepts (e.g., `u_r`, `u_z` for topological parameters).

Example:
```python
def compute_betti_numbers(sparse_matrix: np.ndarray, 
                          curve: EllipticCurve) -> Tuple[int, int, int]:
    """Compute Betti numbers for the topological structure of ECDSA signatures.
    
    The Betti numbers β₀=1, β₁=2, β₂=1 confirm the topological equivalence 
    to a torus, which is critical for security analysis.
    
    Args:
        sparse_matrix: Sparse representation of the signature space
        curve: Elliptic curve parameters
        
    Returns:
        Tuple of Betti numbers (β₀, β₁, β₂)
        
    Raises:
        TopologyError: If the structure doesn't conform to expected topology
    """
    # Implementation here
```

### Testing Requirements
- **All code must be tested** with a minimum 85% test coverage.
- **Tests must verify mathematical correctness** for topological components.
- **Include tests for edge cases** in topological analysis (e.g., special values of d).
- **Test security properties** where applicable (e.g., differential privacy guarantees).
- **Use pytest** for test organization and execution.
- **Tests should run quickly** - optimize test data for performance.

### Documentation Standards
- **Maintain scientific rigor** in all documentation.
- **Explain topological concepts** clearly for cryptographic practitioners.
- **Include mathematical proofs or references** for key algorithms.
- **Document limitations** of analysis methods.
- **Use consistent terminology** (e.g., "torus", "Betti numbers", "topological conformance").
- **Provide concrete examples** for complex concepts.

## Scientific Contribution Guidelines

TopoSphere is built on rigorous mathematical foundations. When contributing scientific components:

1. **Verify mathematical correctness** of any topological claims:
   - Confirm that Betti numbers β₀=1, β₁=2, β₂=1 are preserved where expected
   - Validate topological entropy calculations (h_top = log|d|)
   - Ensure torus structure is properly maintained

2. **Provide theoretical justification** for new analysis methods:
   - How does it relate to the topological model of ECDSA?
   - What vulnerabilities does it detect?
   - How does it compare to existing methods?

3. **Include experimental validation**:
   - Test with known vulnerable and secure implementations
   - Measure detection rates and false positive rates
   - Compare performance metrics

4. **Consider security implications**:
   - How does this affect the security guarantees?
   - Does it introduce new attack vectors?
   - How does it interact with differential privacy protections?

5. **Maintain the core principle**: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities."

## Commit Message Guidelines

Please format commit messages as follows:

```
[component] Brief summary (max 50 characters)

More detailed explanation of the changes. This should include:
- What was changed and why
- Mathematical justification if applicable
- Reference to related issues

Include a section for reviewers if needed:
- [ ] Added tests
- [ ] Updated documentation
- [ ] Verified mathematical correctness
```

Examples:
```
[torus_scan] Implement spiral analysis for vulnerability detection

Added spiral ("snail") pattern analysis to detect vulnerabilities through 
topological anomalies on the torus structure. The implementation follows 
the theoretical framework where the mapping T: (u_r, u_z) ↦ (u_r + 1, u_z + d mod n) 
creates a spiral on the torus.

- Verified with d=27, n=79 that the spiral covers the torus after 79 steps
- Added tests for both secure and vulnerable implementations
- Included documentation on the mathematical foundation
```

```
[security] Enhance differential privacy guarantees

Increased noise parameters to ensure ε-differential privacy with ε=0.1 
for all topological queries. This prevents algorithm reconstruction 
from m queries with probability < 2^(-Ω(m)).

- Updated noise generation across all analysis modules
- Verified privacy guarantees through statistical testing
- Added documentation on privacy parameters
```

## Additional Resources

- [TopoSphere Architecture Documentation](docs/architecture/system_architecture.md)
- [Topological Analysis Research Papers](docs/research/)
- [API Reference](docs/api/)
- [Development Setup Guide](scripts/development/README.md)
- [Security Model Explanation](docs/architecture/security_guarantees.md)

Thank you for contributing to TopoSphere! Your efforts help advance the field of topological cryptographic analysis and improve security for ECDSA implementations worldwide.
