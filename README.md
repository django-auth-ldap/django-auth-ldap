# django-auth-ldap

This is a Django authentication backend that authenticates against an LDAP
service. Configuration can be as simple as a single distinguished name template,
but there are many rich configuration options for working with users, groups,
and permissions.

This version is supported on Python 2.7 and 3.4+; and Django 1.11+. It requires
[python-ldap][] >= 3.0.

* Repository: https://github.com/django-auth-ldap/django-auth-ldap
* Documentation: https://django-auth-ldap.readthedocs.io/


## Contributing

If you have something you'd like to contribute, the best approach is to send a
well-formed pull request, complete with tests and documentation, as needed.
Pull requests should be focused: trying to do more than one thing in a single
request will make it more difficult to process.

If you have a bug or feature request you can try [logging an issue][issues].

There's no harm in creating an issue and then submitting a pull request to
resolve it. This can be a good way to start a conversation and can serve as an
anchor point.


## Development

To get set up for development, activate your virtualenv and use pip to install
from requirements-dev.txt:

    % pip install -r requirements-dev.txt

To run the tests:

    % django-admin test --settings tests.settings

To run the full test suite in a range of environments, run [tox][] from the root
of the project:

    % tox

This includes some static analysis to detect potential runtime errors and style
issues.


[python-ldap]: https://pypi.org/project/python-ldap/
[issues]: https://github.com/django-auth-ldap/django-auth-ldap/issues
[tox]: https://tox.readthedocs.io/
