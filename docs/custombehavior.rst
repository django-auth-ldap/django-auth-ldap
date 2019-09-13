Custom Behavior
===============

There are times that the default :class:`~django_auth_ldap.backend.LDAPBackend`
behavior may be insufficient for your needs. In those cases, you can further 
customize the behavior by following these general steps:


* Create your own :class:`~django_auth_ldap.backend.LDAPBackend` subclass.
* Use :attr:`~django_auth_ldap.backend.LDAPBackend.default_settings` to define
  any custom settings you may want to use.
* Override :meth:`~django_auth_ldap.backend.LDAPBackend.authenticate_ldap_user` 
  hook and/or any other method as needed.
* Define additional methods and attributes as needed.
* Access your custom settings via ``self.settings`` inside your 
  :class:`~django_auth_ldap.backend.LDAPBackend` subclass.


Subclassing LDAPBackend
-----------------------

You can implement your own :class:`~django_auth_ldap.backend.LDAPBackend` subclass
if you need some custom behavior. For example, you want to only allow 50 login 
attempts every 30 minutes, and those numbers may change as needed. Furthermore, 
any successful login attempt against the LDAP server must send out an SMS 
notification, but there should be an option to limit this behavior to a 
specific set of usernames based on a regex. One can accomplish that by doing 
something like this:

.. code-block:: python

    # mypackage.ldap

    import re

    from django.core.cache import cache

    from django_auth_ldap.backend import LDAPBackend


    class CustomLDAPBackend(LDAPBackend):
        default_settings = {
            "LOGIN_COUNTER_KEY": "CUSTOM_LDAP_LOGIN_ATTEMPT_COUNT",
            "LOGIN_ATTEMPT_LIMIT": 50,
            "RESET_TIME": 30 * 60,
            "USERNAME_REGEX": r"^.*$",
        }

        def authenticate_ldap_user(self, ldap_user, password):
            if self.exceeded_login_attempt_limit():
                # Or you can raise a 403 if you do not want
                # to continue checking other auth backends
                print("Login attempts exceeded.")
                return None
            self.increment_login_attempt_count()
            user = ldap_user.authenticate(password)
            if user and self.username_matches_regex(user.username):
                self.send_sms(user.username)
            return user

        @property
        def login_attempt_count(self):
            return cache.get_or_set(
                self.settings.LOGIN_COUNTER_KEY, 0, self.settings.RESET_TIME
            )

        def increment_login_attempt_count(self):
            try:
                cache.incr(self.settings.LOGIN_COUNTER_KEY)
            except ValueError:
                cache.set(self.settings.LOGIN_COUNTER_KEY, 1, self.settings.RESET_TIME)

        def exceeded_login_attempt_limit(self):
            return self.login_attempt_count >= self.settings.LOGIN_ATTEMPT_LIMIT

        def username_matches_regex(self, username):
            return re.match(self.settings.USERNAME_REGEX, username)

        def send_sms(self, username):
            # Implement your SMS logic here
            print("SMS sent!")



.. code-block:: python

    # settings.py

    AUTHENTICATION_BACKENDS = [
        # ...
        "mypackage.ldap.CustomLDAPBackend",
        # ...
    ]


Using default_settings
----------------------

While you can use your own custom Django settings to create something similar 
to the sample code above, there are a couple of advantages in using 
:attr:`~django_auth_ldap.backend.LDAPBackend.default_settings` instead. 

Following the sample code above, one advantage is that the subclass will now 
automatically check your Django settings for ``AUTH_LDAP_LOGIN_COUNTER_KEY``, 
``AUTH_LDAP_LOGIN_ATTEMPT_LIMIT``, ``AUTH_LDAP_RESET_TIME``, and 
``AUTH_LDAP_USERNAME_REGEX``. Another advantage is that for each setting not 
explicitly defined in your Django settings, the subclass will then use the 
corresponding default values. This behavior will be very handy in case you 
will need to override certain settings. 


Overriding default_settings
---------------------------

If down the line, you want to increase the login attempt limit to 100 every 
15 minutes, and you only want SMS notifications for usernames with a "zz\_" 
prefix, then you can simply modify your settings.py like so.

.. code-block:: python

    # settings.py

    AUTH_LDAP_LOGIN_ATTEMPT_LIMIT = 100
    AUTH_LDAP_RESET_TIME = 15 * 60
    AUTH_LDAP_USERNAME_REGEX = r"^zz_.*$"

    AUTHENTICATION_BACKENDS = [
        # ...
        "mypackage.ldap.CustomLDAPBackend",
        # ...
    ]

If the :attr:`~django_auth_ldap.backend.LDAPBackend.settings_prefix` of the
subclass was also changed, then the prefix must also be used in your settings. 
For example, if the prefix was changed to "AUTH_LDAP_1\_", then it should look 
like this.

.. code-block:: python

    # settings.py

    AUTH_LDAP_1_LOGIN_ATTEMPT_LIMIT = 100
    AUTH_LDAP_1_RESET_TIME = 15 * 60
    AUTH_LDAP_1_USERNAME_REGEX = r"^zz_.*$"

    AUTHENTICATION_BACKENDS = [
        # ...
        "mypackage.ldap.CustomLDAPBackend",
        # ...
    ]
