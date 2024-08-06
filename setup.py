from setuptools import setup, find_packages

setup(
    name="cve_2023_38831_scanner",
    version="0.2",
    packages=find_packages(),
    install_requires=[
        "pytest==8.3.2",
        "argparse==1.4.0",
    ],
    entry_points={
        "console_scripts": [
            "cve_2023_38831_scan=src.cli:main",
        ],
    },
)
