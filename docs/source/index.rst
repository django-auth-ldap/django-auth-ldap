================================
Django Authentication Using LDAP
================================

This is a Django authentication backend that authenticates against an LDAP
service. Configuration can be as simple as a single distinguished name template,
but there are many rich configuration options for working with users, groups,
and permissions.

This version is supported on Python 2.6, 2.7, 3.3, and 3.4; and Django >= 1.3.
Under Python 2, it requires `python-ldap
<https://pypi.python.org/pypi/python-ldap>`_ >= 2.0; under Python 3, it uses
`pyldap <https://pypi.python.org/pypi/pyldap>`_.

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


Older Versions
==============

- `django-auth-ldap 1.0.19 <_static/versions/1.0.19/index.html>`_


License
=======

.. include:: ../../LICENSE
