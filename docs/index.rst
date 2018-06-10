================================
Django Authentication Using LDAP
================================

This is a Django authentication backend that authenticates against an LDAP
service. Configuration can be as simple as a single distinguished name
template, but there are many rich configuration options for working with users,
groups, and permissions.

* Documentation: https://django-auth-ldap.readthedocs.io/
* PyPI: https://pypi.org/project/django-auth-ldap/
* Repository: https://github.com/django-auth-ldap/django-auth-ldap
* Tests: http://travis-ci.org/pypa/django-auth-ldap
* License: BSD 2-Clause

This version is supported on Python 2.7 and 3.4+; and Django 1.11+. It requires
`python-ldap`_ >= 3.0.

.. toctree::
    :maxdepth: 2

    install
    authentication
    groups
    users
    permissions
    multiconfig
    logging
    performance
    example
    reference
    changes
    contributing

.. _`python-ldap`: https://pypi.org/project/python-ldap/


License
=======

.. include:: ../LICENSE
