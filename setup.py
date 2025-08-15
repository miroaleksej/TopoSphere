#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TopoSphere - Topological Analysis Framework for ECDSA Security

This package implements the TopoSphere system, an industrial-grade framework for
topological analysis of ECDSA implementations. The system is built on the fundamental
insight from our research: "For secure ECDSA implementations, the signature space
forms a topological torus (β₀=1, β₁=2, β₂=1)" and "Direct analysis without building
the full hypercube enables efficient monitoring of large spaces."

TopoSphere provides:
- Advanced topological analysis of ECDSA signature spaces
- Vulnerability detection through pattern recognition
- TCON (Topological Conformance) verification
- Quantum-inspired security metrics
- Differential privacy mechanisms for secure analysis
- Industrial-grade implementation following AuditCore v3.2 standards

As stated in our research: "Topology is not a hacking tool, but a microscope for
diagnosing vulnerabilities. Ignoring it means building cryptography on sand."

For more information, see the documentation at:
https://toposphere.auditcore.io
"""

import os
import re
import sys
import platform
import subprocess
from pathlib import Path
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext
from setuptools.command.test import test as TestCommand

# Check Python version
if sys.version_info < (3, 8):
    raise RuntimeError("TopoSphere requires Python 3.8 or higher")

# Get version from source file
def get_version():
    """Extract version from __init__.py"""
    init_py = (Path("toposphere") / "__init__.py").read_text()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", init_py, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

# Get long description from README
def get_long_description():
    """Get long description from README.md"""
    readme_path = Path("README.md")
    if readme_path.exists():
        return readme_path.read_text(encoding="utf-8")
    return __doc__

# Get requirements from requirements.txt
def get_requirements():
    """Get requirements from requirements.txt"""
    requirements_path = Path("requirements.txt")
    if requirements_path.exists():
        with open(requirements_path, "r") as f:
            return [
                line.strip() for line in f 
                if line.strip() and not line.startswith("#")
            ]
    return []

# Custom build_ext command for optional C extensions
class BuildExt(build_ext):
    """Custom build_ext command with optional C extensions"""
    def run(self):
        try:
            build_ext.run(self)
        except Exception as e:
            print(f"Warning: Failed to build optional C extensions: {e}")
            print("Proceeding with pure Python implementation.")

# Custom test command with pytest
class PyTest(TestCommand):
    """Custom test command using pytest"""
    user_options = [("pytest-args=", "a", "Arguments to pass to pytest")]
    
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = ""
    
    def run_tests(self):
        import shlex
        import pytest
        errno = pytest.main(shlex.split(self.pytest_args))
        sys.exit(errno)

# Check if we're building documentation
is_building_docs = any(arg.startswith(("build_sphinx", "apidoc")) for arg in sys.argv)

# Platform-specific dependencies
platform_deps = []
if platform.system() == "Linux":
    platform_deps.append("python-prctl>=1.0")
elif platform.system() == "Darwin":
    platform_deps.append("macfsevents>=0.7")

# TopoSphere-specific dependencies
toposphere_deps = [
    "auditcore>=3.2.0,<3.3.0",
    "topological-analyzer>=1.0.0,<1.1.0",
    "torusscan>=1.0.0,<1.1.0",
    "tcon-validator>=1.0.0,<1.1.0",
    "hypercore-transformer>=1.0.0,<1.1.0",
    "betti-analyzer>=1.0.0,<1.1.0",
    "gradient-analysis>=1.0.0,<1.1.0",
    "collision-engine>=1.0.0,<1.1.0",
    "dynamic-compute-router>=1.0.0,<1.1.0",
    "quantum-scanning>=1.0.0,<1.1.0"
]

# Development dependencies (for pip install -e .[dev])
dev_deps = [
    "pytest>=8.1.1,<8.2.0",
    "pytest-cov>=5.0.0,<5.1.0",
    "pytest-mock>=3.14.0,<3.15.0",
    "black>=24.3.0,<24.4.0",
    "isort>=5.13.2,<5.14.0",
    "pre-commit>=3.7.0,<3.8.0",
    "sphinx>=7.2.6,<7.3.0",
    "sphinx-rtd-theme>=2.0.0,<2.1.0",
    "myst-parser>=2.0.0,<2.1.0"
]

# Optional dependencies for specific features
optional_deps = {
    "gpu": ["torch>=2.2.2,<2.3.0", "tensorflow>=2.16.1,<2.17.0"],
    "compression": ["lz4>=4.3.3,<4.4.0", "blosc2>=2.11.0,<2.12.0", "zstandard>=0.22.0,<0.23.0"],
    "distributed": ["ray>=2.10.0,<2.11.0", "dask>=2024.3.2,<2024.4.0"],
    "docs": [
        "sphinx>=7.2.6,<7.3.0",
        "sphinx-rtd-theme>=2.0.0,<2.1.0",
        "myst-parser>=2.0.0,<2.1.0",
        "sphinx-copybutton>=0.5.2,<0.6.0",
        "sphinx-autobuild>=2021.3.14,<2021.4.0"
    ],
    "dev": dev_deps,
    "all": dev_deps + platform_deps + [
        "torch>=2.2.2,<2.3.0",
        "tensorflow>=2.16.1,<2.17.0",
        "ray>=2.10.0,<2.11.0",
        "dask>=2024.3.2,<2024.4.0",
        "lz4>=4.3.3,<4.4.0",
        "blosc2>=2.11.0,<2.12.0",
        "zstandard>=0.22.0,<0.23.0"
    ]
}

# Package data
package_data = {
    "toposphere": [
        "config/*.yaml",
        "config/*.json",
        "config/*.conf",
        "resources/*.dat",
        "resources/*.bin",
        "resources/*.txt",
        "resources/*.md",
        "resources/*.json",
        "resources/schemas/*.json",
        "resources/templates/*.j2",
        "resources/templates/*.html"
    ]
}

# Data files
data_files = [
    ("etc/toposphere", ["config/toposphere.conf.example"]),
    ("share/doc/toposphere", ["README.md", "LICENSE", "CHANGELOG.md"])
]

# Entry points for command-line tools
entry_points = {
    "console_scripts": [
        "toposphere = toposphere.cli.main:main",
        "toposphere-server = toposphere.server.main:main",
        "toposphere-client = toposphere.client.main:main",
        "toposphere-analyze = toposphere.cli.analyze:main",
        "toposphere-scan = toposphere.cli.scan:main",
        "toposphere-tcon = toposphere.cli.tcon:main",
        "toposphere-quantum = toposphere.cli.quantum:main"
    ]
}

# Classifiers for PyPI
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: Apache Software License",
    "Natural Language :: English",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security :: Cryptography",
    "Topic :: Scientific/Engineering :: Mathematics",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: System :: Monitoring",
    "Typing :: Typed"
]

# Setup configuration
setup(
    name="toposphere",
    version=get_version(),
    description="Topological Analysis Framework for ECDSA Security",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="TopoSphere Development Team",
    author_email="contact@toposphere.auditcore.io",
    url="https://toposphere.auditcore.io",
    project_urls={
        "Documentation": "https://toposphere.auditcore.io/docs",
        "Source Code": "https://github.com/auditcore/toposphere",
        "Bug Tracker": "https://github.com/auditcore/toposphere/issues",
        "Research Paper": "https://toposphere.auditcore.io/paper"
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data=package_data,
    data_files=data_files,
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.8, <3.13",
    install_requires=get_requirements() + platform_deps + toposphere_deps,
    extras_require=optional_deps,
    tests_require=dev_deps,
    setup_requires=["setuptools>=61.0", "wheel>=0.37.0"],
    cmdclass={
        "build_ext": BuildExt,
        "test": PyTest
    },
    entry_points=entry_points,
    classifiers=classifiers,
    license="Apache-2.0",
    keywords=(
        "cryptography security ec cryptography topological analysis "
        "ecdsa vulnerability detection torus topological conformance "
        "quantum-inspired security auditcore"
    ),
    platforms=["any"],
    test_suite="tests"
)
