Change Log
==========

.. important:: The releases are now tracked using the `GitHub releases
   <https://github.com/django-auth-ldap/django-auth-ldap/releases>`_. The
   following remains for historical purposes.

Old changes
-----------

Breaking changes
^^^^^^^^^^^^^^^^

- The signal ``ldap_error`` now has an additional ``request`` keyword argument.

- Added support for Python 3.10.
- Added support for Django 4.0.

3.0.0 — 2021-07-19
------------------

- Dropped support for Django 3.0.

Breaking changes
^^^^^^^^^^^^^^^^

- Dropped deprecated setting ``AUTH_LDAP_CACHE_GROUPS``.
- Callables passed to ``AUTH_LDAP_SERVER_URI`` must now take a ``request`` positional argument.

2.4.0 - 2021-04-06
------------------

- Added support for Django 3.2.

2.3.0 - 2021-02-15
------------------

- Removed support for end of life Django 1.11. django-auth-ldap now requires
  Django 2.2+.
- Removed support for end of life Python 3.5.
- Added support for Django 3.1.
- Added support for Python 3.9.
- Removed ``dev-requirements.txt`` in favor of :doc:`tox <tox:index>`.

2.2.0 - 2020-06-02
------------------

- Added support for the escape argument in ``LDAPSearchUnion.execute()``.

2.1.1 - 2020-03-26

- Removed drepecated ``providing_args`` from ``Signal`` instances.

2.1.0 - 2019-12-03
------------------

- Reject authentication requests without a username.
- Added support for Django 3.0 and Python 3.8.
- Removed support for end of life Django 2.1.

2.0.0 - 2019-06-05
------------------

- Removed support for Python 2 and 3.4.
- Removed support for end of life Django 2.0.
- Added support for Django 2.2.
- Add testing and support for Python 3.7 with Django 1.11 and 2.1.
- When :setting:`AUTH_LDAP_SERVER_URI` is set to a callable, it is now passed a
  positional ``request`` argument. Support for no arguments will continue for
  backwards compatibility but will be removed in a future version.
- Added new :setting:`AUTH_LDAP_NO_NEW_USERS` to prevent the creation of new
  users during authentication. Any users not already in the Django user
  database will not be able to login.

1.6.1 - 2018-06-02
------------------

- Renamed ``requirements.txt`` to ``dev-requirements.txt`` to fix Read the Docs
  build.

1.6.0 - 2018-06-02
------------------

- Updated ``LDAPBackend.authenticate()`` signature to match Django's
  documentation.
- Fixed group membership queries with DNs containing non-ascii characters on
  Python 2.7.
- The setting :setting:`AUTH_LDAP_CACHE_TIMEOUT` now replaces deprecated
  `AUTH_LDAP_CACHE_GROUPS` and `AUTH_LDAP_GROUP_CACHE_TIMEOUT`. In addition to
  caching groups, it also controls caching of distinguished names (which were
  previously cached by default). A compatibility shim is provided so the
  deprecated settings will continue to work.

1.5.0 - 2018-04-18
------------------

- django-auth-ldap is now hosted at
  https://github.com/django-auth-ldap/django-auth-ldap.

- Removed NISGroupType class. It searched by attribute nisNetgroupTriple, which
  has no defined EQAULITY rule.

- The python-ldap library is now initialized with ``bytes_mode=False``,
  requiring all LDAP values to be handled as Unicode text (``str`` in Python 3
  and ``unicode`` in Python 2), not bytes. For additional information, see the
  python-ldap documentation on :ref:`bytes mode <text-bytes>`.

- Removed deprecated function ``LDAPBackend.get_or_create_user()``. Use
  :meth:`~django_auth_ldap.backend.LDAPBackend.get_or_build_user` instead.


1.4.0 - 2018-03-22
------------------

- Honor the attrlist argument to :setting:`AUTH_LDAP_GROUP_SEARCH`

- **Backwards incompatible**: Removed support for Django < 1.11.

- Support for Python 2.7 and 3.4+ now handled by the same dependency,
  `python-ldap >= 3.0 <https://pypi.org/project/python-ldap/>`_.


1.3.0 - 2017-11-20
------------------

- **Backwards incompatible**: Removed support for obsolete versions of
  Django (<=1.7, plus 1.9).

- Delay saving new users as long as possible. This will allow
  :setting:`AUTH_LDAP_USER_ATTR_MAP` to populate required fields before creating
  a new Django user.

  ``LDAPBackend.get_or_create_user()`` is now
  :meth:`~django_auth_ldap.backend.LDAPBackend.get_or_build_user` to avoid
  confusion. The old name may still be overridden for now.

- Support querying by a field other than the username field with
  :setting:`AUTH_LDAP_USER_QUERY_FIELD`.

- New method
  :meth:`~django_auth_ldap.backend.LDAPBackend.authenticate_ldap_user` to
  provide pre- and post-authentication hooks.

- Add support for Django 2.0.


1.2.16 - 2017-09-30
-------------------

- Better cache key sanitizing.

- Improved handling of LDAPError. A case existed where the error would not get
  caught while loading group permissions.


1.2.15 - 2017-08-17
-------------------

- Improved documentation for finding the official repository and contributing.


1.2.14 - 2017-07-24
-------------------

- Under search/bind mode, the user's DN will now be cached for
  performance.


1.2.13 - 2017-06-19
-------------------

- Support selective group mirroring with :setting:`AUTH_LDAP_MIRROR_GROUPS` and
  :setting:`AUTH_LDAP_MIRROR_GROUPS_EXCEPT`.

- Work around Django 1.11 bug with multiple authentication backends.


1.2.12 - 2017-05-20
-------------------

- Support for complex group queries via
  :class:`~django_auth_ldap.config.LDAPGroupQuery`.


1.2.11 - 2017-04-22
-------------------

- Some more descriptive object representations.

- Improved tox.ini organization.


1.2.9 - 2017-02-14
------------------

- Ignore python-ldap documentation and accept ``ldap.RES_SEARCH_ENTRY`` from
  :meth:`ldap.LDAPObject.result`.


1.2.8 - 2016-04-18
------------------

- Add :setting:`AUTH_LDAP_USER_ATTRLIST` to override the set of attributes
  requested from the LDAP server.


1.2.7 - 2015-09-29
------------------

- Support Python 3 with `pyldap <https://pypi.org/project/pyldap/>`_.


1.2.6 - 2015-03-29
------------------

- Performance improvements to group mirroring (from
  `Denver Janke <https://bitbucket.org/denverjanke>`_).

- Add :data:`django_auth_ldap.backend.ldap_error` signal for custom handling of
  :exc:`~ldap.LDAPError` exceptions.

- Add :data:`django_auth_ldap.backend.LDAPBackend.default_settings` for
  per-subclass default settings.


1.2.5 - 2015-01-30
------------------

- Fix interaction between :setting:`AUTH_LDAP_AUTHORIZE_ALL_USERS` and
  :setting:`AUTH_LDAP_USER_SEARCH`.


1.2.4 - 2014-12-28
------------------

- Add support for nisNetgroup groups (thanks to Christopher Bartz).


1.2.3 - 2014-11-18
------------------

- Improved escaping for filter strings.

- Accept (and ignore) arbitrary keyword arguments to
  ``LDAPBackend.authenticate``.


1.2.2 - 2014-09-22
------------------

- Include test harness in source distribution. Some package maintainers find
  this helpful.


1.2.1 - 2014-08-24
------------------

- More verbose log messages for authentication failures.


1.2.0 - 2014-04-10
------------------

- django-auth-ldap now provides experimental Python 3 support. Python 2.5 was
  dropped.

  To sum up, django-auth-ldap works with Python 2.6, 2.7, 3.3 and 3.4.

  Since python-ldap isn't making progress toward Python 3, if you're using
  Python 3, you need to install a fork:

  .. code-block:: bash

      $ pip install git+https://github.com/rbarrois/python-ldap.git@py3

  Thanks to `Aymeric Augustin <https://myks.org/en/>`_ for making this happen.


1.1.8 - 2014-02-01
------------------

* Update :class:`~django_auth_ldap.config.LDAPSearchUnion` to work for group
  searches in addition to user searches.

* Tox no longer supports Python 2.5, so our tests now run on 2.6 and 2.7 only.


1.1.7 - 2013-11-19
------------------

* Bug fix: :setting:`AUTH_LDAP_GLOBAL_OPTIONS` could be ignored in some cases
  (such as :func:`~django_auth_ldap.backend.LDAPBackend.populate_user`).


1.1.5 - 2013-10-25
------------------

* Support POSIX group permissions with no gidNumber attribute.

* Support multiple group DNs for \*_FLAGS_BY_GROUP.


1.1.4 - 2013-03-09
------------------

* Add support for Django 1.5's custom user models.


1.1.3 - 2013-01-05
------------------

* Reject empty passwords by default.

  Unless :setting:`AUTH_LDAP_PERMIT_EMPTY_PASSWORD` is set to True,
  LDAPBackend.authenticate() will immediately return None if the password is
  empty. This is technically backwards-incompatible, but it's a more secure
  default for those LDAP servers that are configured such that binds without
  passwords always succeed.

* Add support for pickling LDAP-authenticated users.
