#!/usr/bin/env python

from distutils.core import setup

setup(
    name="django-auth-ldap",
    version="1.1",
    description="Django LDAP authentication backend",
    long_description=open('README.rst').read(),
    url="http://bitbucket.org/psagers/django-auth-ldap/",
    author="Peter Sagerson",
    author_email="psagers.pypi@ignorare.net",
    license="BSD",
    packages=["django_auth_ldap"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Programming Language :: Python",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords=["django", "ldap", "authentication", "auth"],
)
