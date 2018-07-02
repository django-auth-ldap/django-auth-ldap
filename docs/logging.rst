Logging
=======

:class:`~django_auth_ldap.backend.LDAPBackend` uses the standard Python
:mod:`logging` module to log debug and warning messages to the logger named
``'django_auth_ldap'``. If you need debug messages to help with configuration
issues, you should add a handler to this logger. Using Django's
:setting:`LOGGING` setting, you can add an entry to your config.

.. code-block:: python

    LOGGING = {
        'loggers': {
            'django_auth_ldap': {
                'level': 'DEBUG',
                'handlers': ['console'],
            },
        },
    }
