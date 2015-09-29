#!/usr/bin/env python

import sys

from setuptools import setup


PY3 = (sys.version_info[0] == 3)


setup(
    name="django-auth-ldap",
    version="1.2.7",
    description="Django LDAP authentication backend",
    long_description=open('README').read(),
    url="http://bitbucket.org/psagers/django-auth-ldap/",
    author="Peter Sagerson",
    author_email="psagers.pypi@ignorare.net",
    license="BSD",
    packages=["django_auth_ldap"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords=["django", "ldap", "authentication", "auth"],
    install_requires=[
        "django",
        "pyldap" if PY3 else "python-ldap >= 2.0",
    ],
    setup_requires=[
        "setuptools >= 0.6c11",
    ],
    tests_require=[
        "mockldap >= 0.2.6",
    ]
)
