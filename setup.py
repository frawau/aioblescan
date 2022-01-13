#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import setuptools

version = "0.2.11"

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aioblescan",
    packages=["aioblescan", "aioblescan.plugins"],
    # packages=setuptools.find_packages(),
    version=version,
    author="François Wautier",
    author_email="francois@wautier.eu",
    description="Scanning Bluetooth for advertised info with asyncio.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="http://github.com/frawau/aioblescan",
    keywords=["bluetooth", "advertising", "hci", "ble"],
    license="MIT",
    install_requires=[],
    extras_require={"dev": ["pytest"]},
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # Pick your license as you wish (should match "license" above)
        "License :: OSI Approved :: MIT License",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    entry_points={"console_scripts": ["aioblescan=aioblescan.__main__:main"]},
    zip_safe=False,
)
