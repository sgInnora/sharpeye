#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="sharpeye",
    version="0.1.0",
    description="Advanced Linux Intrusion Detection and Threat Hunting System",
    author="innora.ai",
    author_email="security@innora.ai",
    url="https://github.com/sgInnora/sharpeye",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        'console_scripts': [
            'sharpeye=main:main',
        ],
    },
    install_requires=[
        "pyyaml>=5.1",
        "jinja2>=2.11.0",
        "psutil>=5.7.0",
        "requests>=2.23.0",
        "cryptography>=3.0",
        "python-dateutil>=2.8.1",
        "colorama>=0.4.3",
        "numpy>=1.19.0",
        "scipy>=1.5.0"
    ],
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)