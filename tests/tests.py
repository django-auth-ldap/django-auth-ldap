# coding: utf-8

# Copyright (c) 2009, Peter Sagerson
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import (
    absolute_import, division, print_function, unicode_literals,
)

from copy import deepcopy
import functools
import io
import logging
import os
import pickle

import ldap
import mock
import slapdtest

from django.contrib.auth.models import Group, Permission, User
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.test.utils import override_settings

from django_auth_ldap import backend
from django_auth_ldap.config import (
    GroupOfNamesType, LDAPGroupQuery, LDAPSearch, LDAPSearchUnion,
    MemberDNGroupType, NestedMemberDNGroupType, PosixGroupType,
)

from .models import TestUser


def spy_ldap(name):
    """
    Patch the python-ldap method. The patched method records all calls and
    passes execution to the original method.
    """
    ldap_method = getattr(ldap.ldapobject.SimpleLDAPObject, name)
    ldap_mock = mock.MagicMock()

    @functools.wraps(ldap_method)
    def wrapped_ldap_method(self, *args, **kwargs):
        ldap_mock(*args, **kwargs)
        return ldap_method(self, *args, **kwargs)

    def decorator(test):
        @functools.wraps(test)
        def wrapped_test(self, *args, **kwargs):
            with mock.patch.object(ldap.ldapobject.SimpleLDAPObject, name, wrapped_ldap_method):
                return test(self, ldap_mock, *args, **kwargs)
        return wrapped_test
    return decorator


class TestSettings(backend.LDAPSettings):
    """
    A replacement for backend.LDAPSettings that does not load settings
    from django.conf.
    """
    def __init__(self, **kwargs):
        for name, default in self.defaults.items():
            value = kwargs.get(name, default)
            setattr(self, name, value)


class LDAPTest(TestCase):
    @classmethod
    def configure_logger(cls):
        logger = logging.getLogger('django_auth_ldap')
        formatter = logging.Formatter("LDAP auth - %(levelname)s - %(message)s")
        handler = logging.StreamHandler()

        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        logger.setLevel(logging.CRITICAL)

    @classmethod
    def setUpClass(cls):
        cls.configure_logger()

        here = os.path.dirname(__file__)
        cls.server = slapdtest.SlapdObject()
        with open(os.path.join(here, 'slapd.conf')) as fp:
            cls.server.slapd_conf_template = fp.read()
        cls.server.suffix = 'o=test'
        cls.server.root_dn = 'cn=%s,%s' % (cls.server.root_cn, cls.server.suffix)
        cls.server.openldap_schema_files = [
            'core.schema',
            'cosine.schema',
            'inetorgperson.schema',
            'nis.schema',
        ]
        cls.server.start()
        with io.open(os.path.join(here, 'tests.ldif')) as fp:
            ldif = fp.read()
        cls.server.ldapadd(ldif)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        cache.clear()

        self.backend = backend.LDAPBackend()
        self.backend.ldap  # Force global configuration

    #
    # Tests
    #

    def test_options(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            CONNECTION_OPTIONS={ldap.OPT_REFERRALS: 0}
        )
        user = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(user.ldap_user.connection.get_option(ldap.OPT_REFERRALS), 0)

    def test_callable_server_uri(self):
        self._init_settings(
            SERVER_URI=lambda: self.server.ldap_uri,
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username='alice', password='password')

        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.username, 'alice')
        self.assertEqual(User.objects.count(), user_count + 1)

    def test_simple_bind(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username='alice', password='password')

        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.username, 'alice')
        self.assertEqual(User.objects.count(), user_count + 1)

    def test_default_settings(self):
        class MyBackend(backend.LDAPBackend):
            default_settings = {
                'SERVER_URI': self.server.ldap_uri,
                'USER_DN_TEMPLATE': 'uid=%(user)s,ou=people,o=test',
            }
        self.backend = MyBackend()

        user_count = User.objects.count()

        user = self.backend.authenticate(username='alice', password='password')

        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.username, 'alice')
        self.assertEqual(User.objects.count(), user_count + 1)

    @override_settings(AUTH_LDAP_USER_SEARCH=LDAPSearch("ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'))
    def test_login_with_multiple_auth_backends(self):
        with override_settings(AUTH_LDAP_SERVER_URI=self.server.ldap_uri):
            auth = self.client.login(username='alice', password='password')
            self.assertTrue(auth)

    @override_settings(AUTH_LDAP_USER_SEARCH=LDAPSearch("ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'))
    def test_bad_login_with_multiple_auth_backends(self):
        with override_settings(AUTH_LDAP_SERVER_URI=self.server.ldap_uri):
            auth = self.client.login(username='invalid', password='i_do_not_exist')
            self.assertFalse(auth)

    @spy_ldap('simple_bind_s')
    def test_simple_bind_escaped(self, mock):
        """ Bind with a username that requires escaping. """
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )

        user = self.backend.authenticate(username='alice,1', password='password')

        self.assertIsNone(user)
        mock.assert_called_once_with('uid=alice\\,1,ou=people,o=test', 'password')

    def test_new_user_lowercase(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username='Alice', password='password')

        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.username, 'alice')
        self.assertEqual(User.objects.count(), user_count + 1)

    def test_deepcopy(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )

        user = self.backend.authenticate(username='Alice', password='password')
        user = deepcopy(user)

    @override_settings(AUTH_USER_MODEL='tests.TestUser')
    def test_auth_custom_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'uid_number': 'uidNumber'},
        )

        user = self.backend.authenticate(username='Alice', password='password')

        self.assertIsInstance(user, TestUser)

    @override_settings(AUTH_USER_MODEL='tests.TestUser')
    def test_get_custom_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'uid_number': 'uidNumber'},
        )

        user = self.backend.authenticate(username='Alice', password='password')
        user = self.backend.get_user(user.id)

        self.assertIsInstance(user, TestUser)

    @override_settings(AUTH_USER_MODEL='tests.TestUser')
    def test_get_custom_field(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={
                'uid_number': 'uidNumber',
            },
            USER_QUERY_FIELD='uid_number',
        )
        alice = TestUser.objects.create(identifier='abcdef', uid_number=1000)
        user = self.backend.authenticate(username='Alice', password='password')
        self.assertIsInstance(user, TestUser)
        self.assertEqual(user.pk, alice.pk)

    def test_new_user_whitespace(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username=' alice', password='password')
        user = self.backend.authenticate(username='alice ', password='password')

        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.username, 'alice')
        self.assertEqual(User.objects.count(), user_count + 1)

    def test_simple_bind_bad_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username='evil_alice', password='password')

        self.assertIsNone(user)
        self.assertEqual(User.objects.count(), user_count)

    def test_simple_bind_bad_password(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username='alice', password='bogus')

        self.assertIsNone(user)
        self.assertEqual(User.objects.count(), user_count)

    def test_existing_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        User.objects.create(username='alice')
        user_count = User.objects.count()

        user = self.backend.authenticate(username='alice', password='password')

        # Make sure we only created one user
        self.assertIsNotNone(user)
        self.assertEqual(User.objects.count(), user_count)

    def test_existing_user_insensitive(self):
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )
        User.objects.create(username='alice')

        user = self.backend.authenticate(username='Alice', password='password')

        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'alice')
        self.assertEqual(User.objects.count(), 1)

    def test_convert_username(self):
        class MyBackend(backend.LDAPBackend):
            def ldap_to_django_username(self, username):
                return 'ldap_%s' % username

            def django_to_ldap_username(self, username):
                return username[5:]

        self.backend = MyBackend()
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )
        user_count = User.objects.count()

        user1 = self.backend.authenticate(username='alice', password='password')
        user2 = self.backend.get_user(user1.pk)

        self.assertEqual(User.objects.count(), user_count + 1)
        self.assertEqual(user1.username, 'ldap_alice')
        self.assertEqual(user1.ldap_user._username, 'alice')
        self.assertEqual(user1.ldap_username, 'alice')
        self.assertEqual(user2.username, 'ldap_alice')
        self.assertEqual(user2.ldap_user._username, 'alice')
        self.assertEqual(user2.ldap_username, 'alice')

    def test_search_bind(self):
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )
        user_count = User.objects.count()

        user = self.backend.authenticate(username='alice', password='password')

        self.assertIsNotNone(user)
        self.assertEqual(User.objects.count(), user_count + 1)

    @spy_ldap('search_s')
    def test_search_bind_escaped(self, mock):
        """ Search for a username that requires escaping. """
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )

        user = self.backend.authenticate(username='alice*', password='password')

        self.assertIsNone(user)
        mock.assert_called_once_with(
            'ou=people,o=test', ldap.SCOPE_SUBTREE, '(uid=alice\\2a)', None
        )

    def test_search_bind_no_user(self):
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uidNumber=%(user)s)'
            )
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertIsNone(user)

    def test_search_bind_multiple_users(self):
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=*)'
            )
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertIsNone(user)

    def test_search_bind_bad_password(self):
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )

        user = self.backend.authenticate(username='alice', password='bogus')

        self.assertIsNone(user)

    def test_search_bind_with_credentials(self):
        self._init_settings(
            BIND_DN='uid=bob,ou=people,o=test',
            BIND_PASSWORD='password',
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertIsNotNone(user)
        self.assertIsNotNone(user.ldap_user)
        self.assertEqual(user.ldap_user.dn, 'uid=alice,ou=people,o=test')
        self.assertEqual(
            dict(user.ldap_user.attrs),
            {
                'objectClass': ['person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'],
                'cn': ['alice'],
                'uid': ['alice'],
                'userPassword': ['password'],
                'uidNumber': ['1000'],
                'gidNumber': ['1000'],
                'givenName': ['Alice'],
                'sn': ['Adams'],
                'homeDirectory': ['/home/alice'],
            }
        )

    def test_search_bind_with_bad_credentials(self):
        self._init_settings(
            BIND_DN='uid=bob,ou=people,o=test',
            BIND_PASSWORD='bogus',
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertIsNone(user)

    def test_unicode_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn'}
        )

        user = self.backend.authenticate(username='dreßler', password='password')
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'dreßler')
        self.assertEqual(user.last_name, 'Dreßler')

    def test_cidict(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
        )

        user = self.backend.authenticate(username="alice", password="password")

        self.assertIsInstance(user.ldap_user.attrs, ldap.cidict.cidict)

    def test_populate_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn'}
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(user.username, 'alice')
        self.assertEqual(user.first_name, 'Alice')
        self.assertEqual(user.last_name, 'Adams')

    def test_populate_user_with_missing_attribute(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={
                'first_name': 'givenName',
                'last_name': 'sn',
                'email': 'mail',
            }
        )

        user = self.backend.authenticate(username='alice', password='password')
        self.assertEqual(user.username, 'alice')
        self.assertEqual(user.first_name, 'Alice')
        self.assertEqual(user.last_name, 'Adams')
        self.assertEqual(user.email, '')

    @override_settings(AUTH_USER_MODEL='tests.TestUser')
    def test_authenticate_with_buggy_setter_raises_exception(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={
                'first_name': 'givenName',
                'uid_number': 'uidNumber',
            },
        )

        with self.assertRaisesMessage(Exception, 'Oops...'):
            self.backend.authenticate(username='alice', password='password')

    @override_settings(AUTH_USER_MODEL='tests.TestUser')
    def test_populate_user_with_buggy_setter_raises_exception(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={
                'first_name': 'givenName',
                'uid_number': 'uidNumber',
            },
        )

        with self.assertRaisesMessage(Exception, 'Oops...'):
            self.backend.populate_user('alice')

    @spy_ldap('search_s')
    def test_populate_with_attrlist(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn'},
            USER_ATTRLIST=['*', '+'],
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(user.username, 'alice')

        # lookup user attrs
        mock.assert_called_once_with(
            'uid=alice,ou=people,o=test', ldap.SCOPE_BASE, '(objectClass=*)', ['*', '+']
        )

    def test_bind_as_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn'},
            BIND_AS_AUTHENTICATING_USER=True,
        )

        user = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(user.username, 'alice')
        self.assertEqual(user.first_name, 'Alice')
        self.assertEqual(user.last_name, 'Adams')

    def test_signal_populate_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test'
        )

        def handle_populate_user(sender, **kwargs):
            self.assertIn('user', kwargs)
            self.assertIn('ldap_user', kwargs)
            kwargs['user'].populate_user_handled = True

        backend.populate_user.connect(handle_populate_user)
        user = self.backend.authenticate(username='alice', password='password')

        self.assertTrue(user.populate_user_handled)

        backend.populate_user.disconnect(handle_populate_user)

    def test_auth_signal_ldap_error(self):
        self._init_settings(
            BIND_DN='uid=bob,ou=people,o=test',
            BIND_PASSWORD='bogus',
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )

        def handle_ldap_error(sender, **kwargs):
            self.assertEqual(kwargs['context'], 'authenticate')
            raise kwargs['exception']

        backend.ldap_error.connect(handle_ldap_error)
        with self.assertRaises(ldap.LDAPError):
            self.backend.authenticate(username='alice', password='password')
        backend.ldap_error.disconnect(handle_ldap_error)

    def test_populate_signal_ldap_error(self):
        self._init_settings(
            BIND_DN='uid=bob,ou=people,o=test',
            BIND_PASSWORD='bogus',
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )

        user = self.backend.populate_user('alice')

        self.assertIsNone(user)

    def test_no_update_existing(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn'},
            ALWAYS_UPDATE_USER=False
        )
        User.objects.create(username='alice', first_name='Alicia', last_name='Astro')

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertEqual(alice.first_name, 'Alicia')
        self.assertEqual(alice.last_name, 'Astro')
        self.assertEqual(bob.first_name, 'Robert')
        self.assertEqual(bob.last_name, 'Barker')

    def test_require_group(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            REQUIRE_GROUP="cn=active_gon,ou=groups,o=test"
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertIsNotNone(alice)
        self.assertIsNone(bob)

    def test_simple_group_query(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=query_groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')
        query = LDAPGroupQuery('cn=alice_gon,ou=query_groups,o=test')
        self.assertTrue(query.resolve(alice.ldap_user))

    def test_negated_group_query(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=query_groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')
        query = ~LDAPGroupQuery('cn=alice_gon,ou=query_groups,o=test')
        self.assertFalse(query.resolve(alice.ldap_user))

    def test_or_group_query(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=query_groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        query = (
            LDAPGroupQuery('cn=alice_gon,ou=query_groups,o=test') |
            LDAPGroupQuery('cn=bob_gon,ou=query_groups,o=test')
        )
        self.assertTrue(query.resolve(alice.ldap_user))
        self.assertTrue(query.resolve(bob.ldap_user))

    def test_and_group_query(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=query_groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        query = (
            LDAPGroupQuery('cn=alice_gon,ou=query_groups,o=test') &
            LDAPGroupQuery('cn=mutual_gon,ou=query_groups,o=test')
        )
        self.assertTrue(query.resolve(alice.ldap_user))
        self.assertFalse(query.resolve(bob.ldap_user))

    def test_nested_group_query(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=query_groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        query = (
            (
                LDAPGroupQuery('cn=alice_gon,ou=query_groups,o=test') &
                LDAPGroupQuery('cn=mutual_gon,ou=query_groups,o=test')
            ) |
            LDAPGroupQuery('cn=bob_gon,ou=query_groups,o=test')
        )
        self.assertTrue(query.resolve(alice.ldap_user))
        self.assertTrue(query.resolve(bob.ldap_user))

    def test_require_group_as_group_query(self):
        query = (
            LDAPGroupQuery('cn=alice_gon,ou=query_groups,o=test') &
            LDAPGroupQuery('cn=mutual_gon,ou=query_groups,o=test')
        )
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=query_groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            REQUIRE_GROUP=query
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertIsNotNone(alice)
        self.assertIsNone(bob)

    def test_group_union(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearchUnion(
                LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
                LDAPSearch('ou=moregroups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)')
            ),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            REQUIRE_GROUP="cn=other_gon,ou=moregroups,o=test"
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertIsNone(alice)
        self.assertIsNotNone(bob)
        self.assertEqual(bob.ldap_user.group_names, {'other_gon'})

    def test_nested_group_union(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearchUnion(
                LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
                LDAPSearch('ou=moregroups,o=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)')
            ),
            GROUP_TYPE=NestedMemberDNGroupType(member_attr='member'),
            REQUIRE_GROUP="cn=other_gon,ou=moregroups,o=test"
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertIsNone(alice)
        self.assertIsNotNone(bob)
        self.assertEqual(bob.ldap_user.group_names, {'other_gon'})

    def test_denied_group(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            DENY_GROUP="cn=active_gon,ou=groups,o=test"
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertIsNone(alice)
        self.assertIsNotNone(bob)

    def test_group_dns(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(
            alice.ldap_user.group_dns,
            {
                'cn=active_gon,ou=groups,o=test',
                'cn=staff_gon,ou=groups,o=test',
                'cn=superuser_gon,ou=groups,o=test',
                'cn=nested_gon,ou=groups,o=test',
            },
        )

    def test_group_names(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
        )
        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(alice.ldap_user.group_names, {'active_gon', 'staff_gon', 'superuser_gon', 'nested_gon'})

    def test_dn_group_membership(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            USER_FLAGS_BY_GROUP={
                'is_active': LDAPGroupQuery("cn=active_gon,ou=groups,o=test"),
                'is_staff': ["cn=empty_gon,ou=groups,o=test",
                             "cn=staff_gon,ou=groups,o=test"],
                'is_superuser': "cn=superuser_gon,ou=groups,o=test"
            }
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertTrue(alice.is_active)
        self.assertTrue(alice.is_staff)
        self.assertTrue(alice.is_superuser)
        self.assertFalse(bob.is_active)
        self.assertFalse(bob.is_staff)
        self.assertFalse(bob.is_superuser)

    def test_user_flags_misconfigured(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            USER_FLAGS_BY_GROUP={
                'is_active': LDAPGroupQuery("cn=active_gon,ou=groups,o=test"),
                'is_staff': [],
                'is_superuser': "cn=superuser_gon,ou=groups,o=test"
            }
        )

        with self.assertRaises(ImproperlyConfigured):
            self.backend.authenticate(username='alice', password='password')

    def test_posix_membership(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=PosixGroupType(),
            USER_FLAGS_BY_GROUP={
                'is_active': "cn=active_px,ou=groups,o=test",
                'is_staff': "cn=staff_px,ou=groups,o=test",
                'is_superuser': "cn=superuser_px,ou=groups,o=test"
            }
        )

        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertTrue(alice.is_active)
        self.assertTrue(alice.is_staff)
        self.assertTrue(alice.is_superuser)
        self.assertFalse(bob.is_active)
        self.assertFalse(bob.is_staff)
        self.assertFalse(bob.is_superuser)

    def test_nested_dn_group_membership(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=NestedMemberDNGroupType(member_attr='member'),
            USER_FLAGS_BY_GROUP={
                'is_active': "cn=parent_gon,ou=groups,o=test",
                'is_staff': "cn=parent_gon,ou=groups,o=test",
            }
        )
        alice = self.backend.authenticate(username='alice', password='password')
        bob = self.backend.authenticate(username='bob', password='password')

        self.assertTrue(alice.is_active)
        self.assertTrue(alice.is_staff)
        self.assertFalse(bob.is_active)
        self.assertFalse(bob.is_staff)

    def test_posix_missing_attributes(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=PosixGroupType(),
            USER_FLAGS_BY_GROUP={
                'is_active': "cn=active_px,ou=groups,o=test"
            }
        )

        nobody = self.backend.authenticate(username='nobody', password='password')

        self.assertFalse(nobody.is_active)

    def test_dn_group_permissions(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        alice = User.objects.create(username='alice')
        alice = self.backend.get_user(alice.pk)

        self.assertEqual(self.backend.get_group_permissions(alice), {"auth.add_user", "auth.change_user"})
        self.assertEqual(self.backend.get_all_permissions(alice), {"auth.add_user", "auth.change_user"})
        self.assertTrue(self.backend.has_perm(alice, "auth.add_user"))
        self.assertTrue(self.backend.has_module_perms(alice, "auth"))

    def test_group_permissions_ldap_error(self):
        self._init_settings(
            BIND_DN='uid=bob,ou=people,o=test',
            BIND_PASSWORD='bogus',
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        alice = User.objects.create(username='alice')
        alice = self.backend.get_user(alice.pk)

        self.assertEqual(self.backend.get_group_permissions(alice), set())

    def test_empty_group_permissions(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        bob = User.objects.create(username='bob')
        bob = self.backend.get_user(bob.pk)

        self.assertEqual(self.backend.get_group_permissions(bob), set())
        self.assertEqual(self.backend.get_all_permissions(bob), set())
        self.assertFalse(self.backend.has_perm(bob, "auth.add_user"))
        self.assertFalse(self.backend.has_module_perms(bob, "auth"))

    def test_posix_group_permissions(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=posixGroup)'),
            GROUP_TYPE=PosixGroupType(),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        alice = User.objects.create(username='alice')
        alice = self.backend.get_user(alice.pk)

        self.assertEqual(self.backend.get_group_permissions(alice), {"auth.add_user", "auth.change_user"})
        self.assertEqual(self.backend.get_all_permissions(alice), {"auth.add_user", "auth.change_user"})
        self.assertTrue(self.backend.has_perm(alice, "auth.add_user"))
        self.assertTrue(self.backend.has_module_perms(alice, "auth"))

    def test_posix_group_permissions_no_gid(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=posixGroup)'),
            GROUP_TYPE=PosixGroupType(),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        nonposix = User.objects.create(username='nonposix')
        nonposix = self.backend.get_user(nonposix.pk)

        self.assertEqual(self.backend.get_group_permissions(nonposix), {"auth.add_user", "auth.change_user"})
        self.assertEqual(self.backend.get_all_permissions(nonposix), {"auth.add_user", "auth.change_user"})
        self.assertTrue(self.backend.has_perm(nonposix, "auth.add_user"))
        self.assertTrue(self.backend.has_module_perms(nonposix, "auth"))

    def test_foreign_user_permissions(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        alice = User.objects.create(username='alice')

        self.assertEqual(self.backend.get_group_permissions(alice), set())

    @spy_ldap('search_s')
    def test_group_cache(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True,
            CACHE_GROUPS=True
        )
        self._init_groups()

        alice_id = User.objects.create(username='alice').pk
        bob_id = User.objects.create(username='bob').pk

        # Check permissions twice for each user
        for i in range(2):
            alice = self.backend.get_user(alice_id)
            self.assertEqual(
                self.backend.get_group_permissions(alice),
                {"auth.add_user", "auth.change_user"}
            )

            bob = self.backend.get_user(bob_id)
            self.assertEqual(self.backend.get_group_permissions(bob), set())

        # Should have executed one LDAP search per user
        self.assertEqual(mock.call_count, 2)

    def test_group_mirroring(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=posixGroup)'),
            GROUP_TYPE=PosixGroupType(),
            MIRROR_GROUPS=True,
        )

        self.assertEqual(Group.objects.count(), 0)

        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(Group.objects.count(), 3)
        self.assertEqual(set(alice.groups.all()), set(Group.objects.all()))

    def test_nested_group_mirroring(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=groupOfNames)'),
            GROUP_TYPE=NestedMemberDNGroupType(member_attr='member'),
            MIRROR_GROUPS=True,
        )

        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(
            set(Group.objects.all().values_list('name', flat=True)),
            {'active_gon', 'staff_gon', 'superuser_gon', 'nested_gon',
             'parent_gon', 'circular_gon'}
        )
        self.assertEqual(set(alice.groups.all()), set(Group.objects.all()))

    #
    # When selectively mirroring groups, there are eight scenarios for any
    # given user/group pair:
    #
    #   (is-member-in-LDAP, not-member-in-LDAP)
    #   x (is-member-in-Django, not-member-in-Django)
    #   x (synced, not-synced)
    #
    # The four test cases below take these scenarios four at a time for each of
    # the two settings.

    def test_group_mirroring_whitelist_update(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=mirror_groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=groupOfNames)'),
            GROUP_TYPE=GroupOfNamesType(),
            MIRROR_GROUPS=['mirror1', 'mirror2']
        )

        groups = {}
        for name in ('mirror{}'.format(i) for i in range(1, 5)):
            groups[name] = Group.objects.create(name=name)
        alice = self.backend.populate_user('alice')
        alice.groups.set([groups['mirror2'], groups['mirror4']])

        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(
            set(alice.groups.values_list("name", flat=True)),
            {'mirror1', 'mirror4'}
        )

    def test_group_mirroring_whitelist_noop(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=mirror_groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=groupOfNames)'),
            GROUP_TYPE=GroupOfNamesType(),
            MIRROR_GROUPS=['mirror1', 'mirror2']
        )

        groups = {}
        for name in ('mirror{}'.format(i) for i in range(1, 5)):
            groups[name] = Group.objects.create(name=name)
        alice = self.backend.populate_user('alice')
        alice.groups.set([groups['mirror1'], groups['mirror3']])

        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(
            set(alice.groups.values_list("name", flat=True)),
            {'mirror1', 'mirror3'}
        )

    def test_group_mirroring_blacklist_update(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=mirror_groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=groupOfNames)'),
            GROUP_TYPE=GroupOfNamesType(),
            MIRROR_GROUPS_EXCEPT=['mirror1', 'mirror2']
        )

        groups = {}
        for name in ('mirror{}'.format(i) for i in range(1, 5)):
            groups[name] = Group.objects.create(name=name)
        alice = self.backend.populate_user('alice')
        alice.groups.set([groups['mirror2'], groups['mirror4']])

        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(
            set(alice.groups.values_list("name", flat=True)),
            {'mirror2', 'mirror3'}
        )

    def test_group_mirroring_blacklist_noop(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=mirror_groups,o=test', ldap.SCOPE_SUBTREE,
                                    '(objectClass=groupOfNames)'),
            GROUP_TYPE=GroupOfNamesType(),
            MIRROR_GROUPS_EXCEPT=['mirror1', 'mirror2']
        )

        groups = {}
        for name in ('mirror{}'.format(i) for i in range(1, 5)):
            groups[name] = Group.objects.create(name=name)
        alice = self.backend.populate_user('alice')
        alice.groups.set([groups['mirror1'], groups['mirror3']])

        alice = self.backend.authenticate(username='alice', password='password')

        self.assertEqual(
            set(alice.groups.values_list("name", flat=True)),
            {'mirror1', 'mirror3'}
        )

    def test_authorize_external_users(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True,
            AUTHORIZE_ALL_USERS=True
        )
        self._init_groups()

        alice = User.objects.create(username='alice')

        self.assertEqual(self.backend.get_group_permissions(alice), {"auth.add_user", "auth.change_user"})

    def test_authorize_external_unknown(self):
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            ),
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True,
            AUTHORIZE_ALL_USERS=True
        )
        self._init_groups()

        alice = User.objects.create(username='not-in-ldap')

        self.assertEqual(self.backend.get_group_permissions(alice), set())

    def test_create_without_auth(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
        )

        alice = self.backend.populate_user('alice')
        bob = self.backend.populate_user('bob')

        self.assertIsNotNone(alice)
        self.assertEqual(alice.first_name, "")
        self.assertEqual(alice.last_name, "")
        self.assertTrue(alice.is_active)
        self.assertFalse(alice.is_staff)
        self.assertFalse(alice.is_superuser)
        self.assertIsNotNone(bob)
        self.assertEqual(bob.first_name, "")
        self.assertEqual(bob.last_name, "")
        self.assertTrue(bob.is_active)
        self.assertFalse(bob.is_staff)
        self.assertFalse(bob.is_superuser)

    def test_populate_without_auth(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            ALWAYS_UPDATE_USER=False,
            USER_ATTR_MAP={'first_name': 'givenName', 'last_name': 'sn'},
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=GroupOfNamesType(),
            USER_FLAGS_BY_GROUP={
                'is_active': "cn=active_gon,ou=groups,o=test",
                'is_staff': "cn=staff_gon,ou=groups,o=test",
                'is_superuser': "cn=superuser_gon,ou=groups,o=test"
            }
        )

        User.objects.create(username='alice')
        User.objects.create(username='bob')

        alice = self.backend.populate_user('alice')
        bob = self.backend.populate_user('bob')

        self.assertIsNotNone(alice)
        self.assertEqual(alice.first_name, "Alice")
        self.assertEqual(alice.last_name, "Adams")
        self.assertTrue(alice.is_active)
        self.assertTrue(alice.is_staff)
        self.assertTrue(alice.is_superuser)
        self.assertIsNotNone(bob)
        self.assertEqual(bob.first_name, "Robert")
        self.assertEqual(bob.last_name, "Barker")
        self.assertFalse(bob.is_active)
        self.assertFalse(bob.is_staff)
        self.assertFalse(bob.is_superuser)

    def test_populate_bogus_user(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
        )

        bogus = self.backend.populate_user('bogus')

        self.assertIsNone(bogus)

    @spy_ldap('start_tls_s')
    def test_start_tls_missing(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            START_TLS=False,
        )

        self.backend.authenticate(username='alice', password='password')
        mock.assert_not_called()

    @spy_ldap('start_tls_s')
    def test_start_tls(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            START_TLS=True,
        )

        self.backend.authenticate(username='alice', password='password')
        mock.assert_called_once()

    def test_null_search_results(self):
        """
        Make sure we're not phased by referrals.
        """
        self._init_settings(
            USER_SEARCH=LDAPSearch(
                "ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'
            )
        )
        self.backend.authenticate(username='alice', password='password')

    def test_union_search(self):
        self._init_settings(
            USER_SEARCH=LDAPSearchUnion(
                LDAPSearch("ou=groups,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'),
                LDAPSearch("ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=%(user)s)'),
            )
        )
        alice = self.backend.authenticate(username='alice', password='password')

        self.assertIsNotNone(alice)

    @spy_ldap('simple_bind_s')
    def test_deny_empty_password(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
        )

        alice = self.backend.authenticate(username='alice', password='')

        self.assertIsNone(alice)
        mock.assert_not_called()

    @spy_ldap('simple_bind_s')
    def test_permit_empty_password(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            PERMIT_EMPTY_PASSWORD=True,
        )

        alice = self.backend.authenticate(username='alice', password='')

        self.assertIsNone(alice)
        mock.assert_called_once()

    @spy_ldap('simple_bind_s')
    def test_permit_null_password(self, mock):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            PERMIT_EMPTY_PASSWORD=True,
        )

        alice = self.backend.authenticate(username='alice', password=None)

        self.assertIsNone(alice)
        mock.assert_called_once()

    def test_pickle(self):
        self._init_settings(
            USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test',
            GROUP_SEARCH=LDAPSearch('ou=groups,o=test', ldap.SCOPE_SUBTREE),
            GROUP_TYPE=MemberDNGroupType(member_attr='member'),
            FIND_GROUP_PERMS=True
        )
        self._init_groups()

        alice0 = self.backend.authenticate(username='alice', password='password')

        pickled = pickle.dumps(alice0, pickle.HIGHEST_PROTOCOL)
        alice = pickle.loads(pickled)
        alice.ldap_user.backend.settings = alice0.ldap_user.backend.settings

        self.assertIsNotNone(alice)
        self.assertEqual(self.backend.get_group_permissions(alice), {"auth.add_user", "auth.change_user"})
        self.assertEqual(self.backend.get_all_permissions(alice), {"auth.add_user", "auth.change_user"})
        self.assertTrue(self.backend.has_perm(alice, "auth.add_user"))
        self.assertTrue(self.backend.has_module_perms(alice, "auth"))

    @mock.patch('ldap.ldapobject.SimpleLDAPObject.search_s')
    def test_search_attrlist(self, mock_search):
        connection = self.backend.ldap.initialize(self.server.ldap_uri, bytes_mode=False)
        search = LDAPSearch("ou=people,o=test", ldap.SCOPE_SUBTREE, '(uid=alice)', ['*', '+'])
        search.execute(connection)
        mock_search.assert_called_once_with(
            'ou=people,o=test', ldap.SCOPE_SUBTREE, '(uid=alice)', ['*', '+']
        )

    def test_override_authenticate_access_ldap_user(self):
        class MyBackend(backend.LDAPBackend):
            def authenticate_ldap_user(self, ldap_user, password):
                ldap_user.foo = 'bar'
                return super(MyBackend, self).authenticate_ldap_user(ldap_user, password)

        self.backend = MyBackend()
        self._init_settings(USER_DN_TEMPLATE='uid=%(user)s,ou=people,o=test')
        user = self.backend.authenticate(username='alice', password='password')
        self.assertEqual(user.ldap_user.foo, 'bar')

    #
    # Utilities
    #

    def _init_settings(self, **kwargs):
        kwargs.setdefault('SERVER_URI', self.server.ldap_uri)
        self.backend.settings = TestSettings(**kwargs)

    def _init_groups(self):
        permissions = [
            Permission.objects.get(codename="add_user"),
            Permission.objects.get(codename="change_user")
        ]

        active_gon = Group.objects.create(name='active_gon')
        active_gon.permissions.add(*permissions)

        active_px = Group.objects.create(name='active_px')
        active_px.permissions.add(*permissions)

        active_nis = Group.objects.create(name='active_nis')
        active_nis.permissions.add(*permissions)
