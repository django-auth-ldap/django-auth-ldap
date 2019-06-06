#!/usr/bin/env python

from setuptools import setup

import django_auth_ldap

with open("README.rst") as fp:
    readme = fp.read()

setup(
    name="django-auth-ldap",
    version=django_auth_ldap.version_string,
    description="Django LDAP authentication backend",
    long_description=readme,
    url="https://github.com/django-auth-ldap/django-auth-ldap",
    author="Peter Sagerson",
    author_email="psagers@ignorare.net",
    maintainer="Jon Dufresne",
    maintainer_email="jon.dufresne@gmail.com",
    license="BSD",
    packages=["django_auth_ldap"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.11",
        "Framework :: Django :: 2.1",
        "Framework :: Django :: 2.2",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
    ],
    keywords=["django", "ldap", "authentication", "auth"],
    project_urls={
        "Documentation": "https://django-auth-ldap.readthedocs.io/",
        "Source": "https://github.com/django-auth-ldap/django-auth-ldap",
        "Tracker": "https://github.com/django-auth-ldap/django-auth-ldap/issues",
    },
    python_requires=">=3.5",
    install_requires=["Django >= 1.11", "python-ldap >= 3.1"],
    tests_require=["mock >= 2.0.0"],
)
