from setuptools import setup, find_packages

setup(
    name="cve_2023_38831_scanner",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "pytest==7.3.1",
    ],
    entry_points={
        "console_scripts": [
            "cve_2023_38831_scan=src.scanner:main",
        ],
    },
)
