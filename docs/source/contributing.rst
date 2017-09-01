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

.. code-block:: none

    $ pip install -r requirements-dev.txt

To run the tests:

.. code-block:: none

    $ django-admin test --settings tests.settings

To run the full test suite in a range of environments, run `tox`_ from the root
of the project:

.. code-block:: none

    $ tox

This includes some static analysis to detect potential runtime errors and style
issues.


Mercurial
---------

django-auth-ldap uses `Mercurial`_ for source control. If you're more familiar
with Git, Mercurial is similar in many ways, but there are a few important
differences to keep in mind.

Mercurial branches are more or less permanent and thus not very good for feature
work or pull requests. If you want to work on multiple features at once,
consider using `bookmarks`_ instead. The default bookmark is called ``@``
(similar to git's master branch).

.. code-block:: none

    $ hg up @
    $ hg bookmark new-feature
    (make changes)
    $ hg ci
    $ hg push -B new-feature

Local Mercurial clones and Bitbucket forks are all (typically) `non-publishing`_
repositories. This means that new changesets remain in draft mode and can be
modified in a safe and principled manner with the `evolve`_ extension. The
author makes heavy use of `changeset evolution`_ and frequently uses it to
process pull requests while keeping the history clean and linear.

Changeset evolution is a big topic, but one of the most useful things to know is
that it's safe to amend existing draft changesets even if they've already been
shared with other non-publishing repositories:

.. code-block:: none

    $ hg up @
    $ hg bookmark new-feature
    (make changes)
    $ hg ci
    $ hg push -B new-feature
    (oops, one more change)
    $ hg amend
    $ hg push


.. _mailing list: https://groups.google.com/group/django-auth-ldap
.. _logging an issue: https://bitbucket.org/illocution/django-auth-ldap/issues?status=new&status=open
.. _tox: https://tox.readthedocs.io/
.. _Mercurial: https://www.mercurial-scm.org/
.. _bookmarks: https://www.mercurial-scm.org/wiki/Bookmarks
.. _non-publishing: https://www.mercurial-scm.org/wiki/Phases#Publishing_Repository
.. _evolve: https://www.mercurial-scm.org/wiki/EvolveExtension
.. _changeset evolution: https://www.mercurial-scm.org/wiki/ChangesetEvolution
