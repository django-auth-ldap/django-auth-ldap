Logging
=======

:class:`~django_auth_ldap.backend.LDAPBackend` uses the standard logging module
to log debug and warning messages to the logger named ``'django_auth_ldap'``. If
you need debug messages to help with configuration issues, you should add a
handler to this logger. Note that this logger is initialized with a level of
NOTSET, so you may need to change the level of the logger in order to get debug
messages.

.. code-block:: python

    import logging

    logger = logging.getLogger('django_auth_ldap')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

Or if you're using Django's `LOGGING setting`_, you can add an entry to your
logging config:

.. _LOGGING setting: https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-LOGGING

.. code-block:: python

    LOGGING = {
        'loggers': {
            'django_auth_ldap': {
                'level': 'DEBUG',
                'handlers': ['console'],
            },
        },
    }
