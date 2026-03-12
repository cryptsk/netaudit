#!/usr/bin/env python3
"""
CRYPTSK NetAudit - Setup Script
Linux Network Infrastructure Audit Tool

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cryptsk-netaudit",
    version="1.0.0",
    author="CRYPTSK Pvt Ltd",
    author_email="info@cryptsk.com",
    description="Linux Network Infrastructure Audit Tool - Professional Security Auditing by CRYPTSK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://cryptsk.com",
    project_urls={
        "Homepage": "https://cryptsk.com",
        "Documentation": "https://cryptsk.com/netaudit/docs",
        "Support": "mailto:info@cryptsk.com",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Security Professionals",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.109.0",
        "uvicorn>=0.27.0",
        "typer>=0.9.0",
        "rich>=13.7.0",
        "pydantic>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "netaudit=cli.main:app",
            "cryptsk-netaudit=cli.main:app",
        ],
    },
    keywords="security audit linux network infrastructure firewall sysctl hardening",
    license="MIT",
    include_package_data=True,
)
