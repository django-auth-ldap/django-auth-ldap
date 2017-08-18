Contributing
============

django-auth-ldap is stable and maintained by the original author, although there
is not a lot of active development. Contributions are welcome. The official
repository is at https://bitbucket.org/illocution/django-auth-ldap.

If you'd like to report an issue or contribute a feature, but you're not sure
how to proceed, start with the `mailing list`_. This may clear up some
misunderstandings or provide a gut check on how feasible the idea is.

If you have something you'd like to contribute, the best approach is to send a
well-formed pull request, complete with tests and documentation, as needed. Pull
requests that lack tests or documentation or that break existing tests will
probably not be taken very seriously.

If you have a bug or feature request that you can't or don't wish to fix or
implement, you can try `logging an issue`_. Serious bugs should get taken care
of quickly, but less urgent issues may or may not attract any attention. It just
depends on whether anyone else finds it interesting enough to do something
about.


Development
-----------

To get set up for development, activate your virtualenv and use pip to install
from requirements-dev.txt:

.. code-block:: sh

    $ pip install -r requirements-dev.txt

To run the tests:

.. code-block:: sh

    $ cd test
    $ python manage.py test django_auth_ldap

To run the full test suite in a range of environments, run `tox`_ from the root
of the project:

.. code-block:: sh

    $ tox

This includes some static analysis to detect potential runtime errors and style
issues.

.. _mailing list: https://groups.google.com/group/django-auth-ldap
.. _logging an issue: https://bitbucket.org/illocution/django-auth-ldap/issues?status=new&status=open
.. _tox: https://tox.readthedocs.io/
