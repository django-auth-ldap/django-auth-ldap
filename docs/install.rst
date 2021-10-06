Installation
============

Install the package with pip:

.. code-block:: sh

    $ pip install django-auth-ldap

It requires `python-ldap`_ >= 3.0. You'll need the `OpenLDAP`_ libraries and
headers available on your system.

To use the auth backend in a Django project, add
``'django_auth_ldap.backend.LDAPBackend'`` to
:setting:`AUTHENTICATION_BACKENDS`. Do not add anything to
:setting:`INSTALLED_APPS`.

.. code-block:: python

    AUTHENTICATION_BACKENDS = ["django_auth_ldap.backend.LDAPBackend"]

:class:`~django_auth_ldap.backend.LDAPBackend` should work with custom user
models, but it does assume that a database is present.

.. note::

    :class:`~django_auth_ldap.backend.LDAPBackend` does not inherit from
    :class:`~django.contrib.auth.backends.ModelBackend`. It is possible to use
    :class:`~django_auth_ldap.backend.LDAPBackend` exclusively by configuring
    it to draw group membership from the LDAP server. However, if you would
    like to assign permissions to individual users or add users to groups
    within Django, you'll need to have both backends installed:

    .. code-block:: python

        AUTHENTICATION_BACKENDS = [
            "django_auth_ldap.backend.LDAPBackend",
            "django.contrib.auth.backends.ModelBackend",
        ]

    Django will check each authentication backend in order, so you are free to
    reorder these if checking
    :class:`~django.contrib.auth.backends.ModelBackend` first is more
    applicable to your application.

.. _`python-ldap`: https://pypi.org/project/python-ldap/
.. _`OpenLDAP`: https://www.openldap.org/
