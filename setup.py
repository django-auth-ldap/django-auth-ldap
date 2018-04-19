#!/usr/bin/env python

from __future__ import unicode_literals

from setuptools import setup

import django_auth_ldap


long_description = """\
This is a Django authentication backend that authenticates against an LDAP
service. Configuration can be as simple as a single distinguished name template,
but there are many rich configuration options for working with users, groups,
and permissions.

This version is supported on Python 2.7 and 3.4+; and Django 1.11+. It requires
`python-ldap <https://pypi.org/project/python-ldap/>`_ >= 3.0.

* Repository: https://github.com/django-auth-ldap/django-auth-ldap
* Documentation: https://django-auth-ldap.readthedocs.io/

Following is an example configuration, just to whet your appetite::

    import ldap
    from django_auth_ldap.config import LDAPSearch, GroupOfNamesType


    # Baseline configuration.
    AUTH_LDAP_SERVER_URI = "ldap://ldap.example.com"

    AUTH_LDAP_BIND_DN = "cn=django-agent,dc=example,dc=com"
    AUTH_LDAP_BIND_PASSWORD = "phlebotinum"
    AUTH_LDAP_USER_SEARCH = LDAPSearch("ou=users,dc=example,dc=com",
        ldap.SCOPE_SUBTREE, "(uid=%(user)s)")
    # or perhaps:
    # AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=users,dc=example,dc=com"

    # Set up the basic group parameters.
    AUTH_LDAP_GROUP_SEARCH = LDAPSearch("ou=django,ou=groups,dc=example,dc=com",
        ldap.SCOPE_SUBTREE, "(objectClass=groupOfNames)"
    )
    AUTH_LDAP_GROUP_TYPE = GroupOfNamesType()

    # Simple group restrictions
    AUTH_LDAP_REQUIRE_GROUP = "cn=enabled,ou=django,ou=groups,dc=example,dc=com"
    AUTH_LDAP_DENY_GROUP = "cn=disabled,ou=django,ou=groups,dc=example,dc=com"

    # Populate the Django user from the LDAP directory.
    AUTH_LDAP_USER_ATTR_MAP = {
        "first_name": "givenName",
        "last_name": "sn",
        "email": "mail"
    }

    AUTH_LDAP_USER_FLAGS_BY_GROUP = {
        "is_active": "cn=active,ou=django,ou=groups,dc=example,dc=com",
        "is_staff": "cn=staff,ou=django,ou=groups,dc=example,dc=com",
        "is_superuser": "cn=superuser,ou=django,ou=groups,dc=example,dc=com"
    }

    # Use LDAP group membership to calculate group permissions.
    AUTH_LDAP_FIND_GROUP_PERMS = True

    # Cache group memberships for an hour to minimize LDAP traffic
    AUTH_LDAP_CACHE_GROUPS = True
    AUTH_LDAP_GROUP_CACHE_TIMEOUT = 3600


    # Keep ModelBackend around for per-user permissions and maybe a local
    # superuser.
    AUTHENTICATION_BACKENDS = (
        'django_auth_ldap.backend.LDAPBackend',
        'django.contrib.auth.backends.ModelBackend',
    )
"""


setup(
    name="django-auth-ldap",
    version=django_auth_ldap.version_string,
    description="Django LDAP authentication backend",
    long_description=long_description,
    url="https://github.com/django-auth-ldap/django-auth-ldap",
    author="Peter Sagerson",
    author_email="psagers@ignorare.net",
    maintainer="Jon Dufresne",
    maintainer_email="jon.dufresne@gmail.com",
    license="BSD",
    packages=["django_auth_ldap"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        "Environment :: Web Environment",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Framework :: Django",
        "Framework :: Django :: 1.11",
        "Framework :: Django :: 2.0",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords=["django", "ldap", "authentication", "auth"],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    install_requires=[
        'Django >= 1.11',
        'python-ldap >= 3.0',
    ],
    setup_requires=[
        "setuptools >= 0.6c11",
    ],
    tests_require=[
        "mock >= 2.0.0",
    ]
)
