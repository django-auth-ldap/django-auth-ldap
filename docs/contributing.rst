Contributing
============

If you'd like to contribute, the best approach is to send a well-formed pull
request, complete with tests and documentation. Pull requests should be
focused: trying to do more than one thing in a single request will make it more
difficult to process.

If you have a bug or feature request you can try `logging an issue`_.

There's no harm in creating an issue and then submitting a pull request to
resolve it. This can be a good way to start a conversation and can serve as an
anchor point.

.. _`logging an issue`: https://github.com/django-auth-ldap/django-auth-ldap/issues


Development
-----------

To run the full test suite in a range of environments, run :doc:`tox <tox:index>`
from the root of the project:

.. code-block:: sh

    $ tox

This includes some static analysis to detect potential runtime errors and style
issues.

To limit to a single environment, use :ref:`tox-run--e`:

.. code-block:: console

   $ tox -e djangomain
