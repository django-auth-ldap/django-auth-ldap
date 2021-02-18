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

"""
This module contains classes that will be needed for configuration of LDAP
authentication. Unlike backend.py, this is safe to import into settings.py.
Please see the docstring on the backend module for more information, including
notes on naming conventions.
"""

import logging
import pprint
from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Collection,
    Dict,
    ItemsView,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
    Union,
)

from django.utils.tree import Node
from ldap3 import ALL_ATTRIBUTES, Connection
from ldap3.core.exceptions import (
    LDAPException,
    LDAPNoSuchAttributeResult,
    LDAPUndefinedAttributeTypeResult,
)
from ldap3.core.results import RESULT_COMPARE_TRUE
from ldap3.utils.conv import escape_filter_chars

if TYPE_CHECKING:
    from django_auth_ldap.backend import _LDAPUser, _LDAPUserGroups


class ConfigurationWarning(UserWarning):
    pass


class _LDAPConfig:
    """
    A private class that loads and caches some global objects.
    """

    _logger: Optional[logging.Logger] = None

    @classmethod
    def get_logger(cls) -> logging.Logger:
        """
        Initializes and returns our logger instance.
        """
        if cls._logger is None:
            cls._logger = logging.getLogger("django_auth_ldap")
            cls._logger.addHandler(logging.NullHandler())

        return cls._logger


# Our global logger
logger: logging.Logger = _LDAPConfig.get_logger()


class AbstractLDAPSearch(ABC):
    """
    The abstract base class for ldap searches.
    """

    @abstractmethod
    def search_with_additional_terms(
        self, term_dict: Dict[str, str], escape: bool = True
    ) -> "AbstractLDAPSearch":
        """
        Returns a new search object with additional search terms and-ed to the
        filter string. term_dict maps attribute names to assertion values. If
        you don't want the values escaped, pass escape=False.
        """
        pass

    @abstractmethod
    def search_with_additional_term_string(
        self, filterstr: str
    ) -> "AbstractLDAPSearch":
        """
        Returns a new search object with filterstr and-ed to the original filter
        string. The caller is responsible for passing in a properly escaped
        string.
        """
        pass

    def execute(
        self,
        connection: Connection,
        filterargs: Union[Tuple[Any, ...], Mapping[str, Any]] = (),
        escape: bool = True,
    ) -> Collection[Tuple[str, Dict[str, Any]]]:
        """
        Executes the search on the given connection. filterargs
        is an object that will be used for expansion of the filter string.
        If escape is True, values in filterargs will be escaped.
        """
        self._search(connection, filterargs, escape)

        return self._response(connection)

    @abstractmethod
    def _abandon(self, connection: Connection) -> None:
        """
        Abandon a previous asynchronous search.
        """
        pass

    @abstractmethod
    def _search(
        self,
        connection: Connection,
        filterargs: Union[Tuple[Any, ...], Mapping[str, Any]] = (),
        escape: bool = True,
    ) -> None:
        """
        Begins an asynchronous search and returns the message id to retrieve
        the results.

        filterargs is an object that will be used for expansion of the filter
        string. If escape is True, values in filterargs will be escaped.
        """
        pass

    @abstractmethod
    def _response(
        self, connection: Connection
    ) -> Collection[Tuple[str, Dict[str, Any]]]:
        """
        Returns the result of a previous asynchronous query or an empty array
        if no search has been initiated.

        The python-ldap library returns utf8-encoded strings. For the sake of
        sanity, this method will decode all result strings and return them as
        Unicode.
        """
        pass

    @classmethod
    def _escape_filterargs(
        cls, filterargs: Union[Tuple[Any, ...], Mapping[str, Any]]
    ) -> Union[Tuple[Any, ...], Mapping[str, Any]]:
        """
        Escapes all string values in filterargs and all others remain the same.

        filterargs is a value suitable for Django's string formatting operator
        (%), which means it's either a tuple or a dict. This return a new tuple
        or dict with all values escaped for use in filter strings.
        """
        if isinstance(filterargs, tuple):
            filterargs = tuple(escape_filter_chars(str(value)) for value in filterargs)
        elif isinstance(filterargs, Mapping):
            filterargs = dict(
                (key, escape_filter_chars(str(value)))
                for key, value in filterargs.items()
            )
        else:
            raise TypeError("filterargs must be a tuple or mapping.")

        return filterargs


class LDAPSearch(AbstractLDAPSearch):
    """
    Public class that holds a set of LDAP search parameters. Objects of this
    class should be considered immutable. Only the initialization method is
    documented for configuration purposes. Internal clients may use the other
    methods to refine and execute the search.
    """

    def __init__(
        self,
        base_dn: str,
        scope: str,
        filterstr: str = "(objectClass=*)",
        attrlist: Optional[Collection[str]] = None,
    ) -> None:
        """
        These parameters are the same as the first three parameters to
        ldap.search_s.
        """
        self.base_dn: str = base_dn
        self.scope: str = scope
        self.filterstr: str = filterstr
        self.attrlist: Optional[Collection[str]] = attrlist
        self.msgid: Optional[int] = None

    def __repr__(self) -> str:
        return "<{}: {}>".format(type(self).__name__, self.base_dn)

    def search_with_additional_terms(
        self, term_dict: Dict[str, str], escape: bool = True
    ) -> "LDAPSearch":
        term_strings = [self.filterstr]

        for name, value in term_dict.items():
            if escape:
                value = escape_filter_chars(value)
            term_strings.append("({}={})".format(name, value))

        filterstr = "(&{})".format("".join(term_strings))

        return type(self)(self.base_dn, self.scope, filterstr, attrlist=self.attrlist)

    def search_with_additional_term_string(self, filterstr: str) -> "LDAPSearch":
        filterstr = "(&{}{})".format(self.filterstr, filterstr)

        return type(self)(self.base_dn, self.scope, filterstr, attrlist=self.attrlist)

    def _abandon(self, connection: Connection) -> None:
        if self.msgid is not None:
            connection.abandon(self.msgid)
            self.msgid = None

    def _search(
        self,
        connection: Connection,
        filterargs: Union[Tuple[Any, ...], Mapping[str, Any]] = (),
        escape: bool = True,
    ) -> None:
        self._abandon(connection)

        if escape:
            filterargs = self._escape_filterargs(filterargs)

        filterstr = self.filterstr % filterargs

        attrlist = self.attrlist
        if attrlist is None:
            attrlist = ALL_ATTRIBUTES

        try:
            self.msgid = connection.search(
                self.base_dn,
                filterstr,
                self.scope,
                attributes=attrlist,
            )
        except LDAPException as e:
            logger.error(
                "search('{}', {}, '{}') raised {}".format(
                    self.base_dn, self.scope, filterstr, pprint.pformat(e)
                )
            )

    def _response(self, connection: Connection) -> List[Tuple[str, Dict[str, Any]]]:
        if self.msgid is None:
            raise RuntimeError(
                "The search has either not been initiated, abandoned,"
                " or the results have already been fetched"
            )

        try:
            response = [
                (entry["dn"], entry["attributes"])
                for entry in connection.get_response(self.msgid)[0]
            ]
            response_dns = [entry[0] for entry in response]
            # check encoding and no None DNs and lower case Dns

            logger.debug(
                "search('{}', {}, '{}') returned {} objects: {}".format(
                    self.base_dn,
                    self.scope,
                    self.filterstr,
                    len(response_dns),
                    "; ".join(response_dns),
                )
            )
        except LDAPException as e:
            response = []
            logger.error("result({}) raised {}".format(self.msgid, pprint.pformat(e)))

        self.msgid = None

        return response


class LDAPSearchUnion(AbstractLDAPSearch):
    """
    A compound search object that returns the union of the results. Instantiate
    it with one or more AbstractLDAPSearch objects.
    """

    def __init__(self, *args: AbstractLDAPSearch) -> None:
        self.searches: Tuple[AbstractLDAPSearch, ...] = args

    def search_with_additional_terms(
        self, term_dict: Dict[str, str], escape: bool = True
    ) -> "LDAPSearchUnion":
        searches = tuple(
            s.search_with_additional_terms(term_dict, escape) for s in self.searches
        )

        return type(self)(*searches)

    def search_with_additional_term_string(self, filterstr: str) -> "LDAPSearchUnion":
        searches = tuple(
            s.search_with_additional_term_string(filterstr) for s in self.searches
        )

        return type(self)(*searches)

    def _abandon(self, connection: Connection) -> None:
        for search in self.searches:
            search._abandon(connection)

    def _search(
        self,
        connection: Connection,
        filterargs: Union[Tuple[Any, ...], Mapping[str, Any]] = (),
        escape: bool = True,
    ) -> None:
        for search in self.searches:
            search._search(connection, filterargs, escape)

    def _response(self, connection: Connection) -> ItemsView[str, Dict[str, Any]]:
        results = dict()

        for search in self.searches:
            result = search._response(connection)
            results.update(dict(result))

        return results.items()


class LDAPGroupType(ABC):
    """
    This is an abstract base class for classes that determine LDAP group
    membership. A group can mean many different things in LDAP, so we will need
    a concrete subclass for each grouping mechanism. Clients may subclass this
    if they have a group mechanism that is not handled by a built-in
    implementation.

    name_attr is the name of the LDAP attribute from which we will take the
    Django group name.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        self.name_attr: str = name_attr

    @abstractmethod
    def user_groups(
        self, ldap_user: "_LDAPUser", group_search: AbstractLDAPSearch
    ) -> Collection[Tuple[str, Dict[str, Any]]]:
        """
        Returns a list of group_info structures, each one a group to which
        ldap_user belongs. group_search is an LDAPSearch object that returns all
        of the groups that the user might belong to. Typical implementations
        will apply additional filters to group_search and return the results of
        the search.

        This is the primitive method in the API and must be implemented.
        """
        pass

    def group_name_from_info(
        self, group_info: Tuple[str, Dict[str, Any]]
    ) -> Optional[str]:
        """
        Given the (DN, attrs) 2-tuple of an LDAP group, this returns the name of
        the Django group. This may return None to indicate that a particular
        LDAP group has no corresponding Django group.

        The base implementation returns the value of the cn attribute, or
        whichever attribute was given to __init__ in the name_attr
        parameter.
        """
        try:
            return group_info[1][self.name_attr][0]
        except (KeyError, IndexError):
            return None


class LDAPGroupTypeIsMember(LDAPGroupType):
    @abstractmethod
    def is_member(self, ldap_user: "_LDAPUser", group_dn: str) -> bool:
        """
        Returns True if the group is the user's primary group or if the user is
        listed in the group's memberUid attribute.
        """
        pass


class PosixGroupType(LDAPGroupTypeIsMember):
    """
    An LDAPGroupType subclass that handles groups of class posixGroup.
    """

    def user_groups(
        self, ldap_user: "_LDAPUser", group_search: AbstractLDAPSearch
    ) -> Collection[Tuple[str, Dict[str, Any]]]:
        """
        Searches for any group that is either the user's primary or contains the
        user as a member.
        """
        if ldap_user.attrs is None:
            raise TypeError("The attrs of the LDAP user should not be None")

        try:
            user_uid = ldap_user.get_single_attr("uid")

            if "gidNumber" in ldap_user.attrs:
                user_gid = ldap_user.get_single_attr("gidNumber")
                filterstr = "(|(gidNumber={})(memberUid={}))".format(
                    escape_filter_chars(user_gid),
                    escape_filter_chars(user_uid),
                )
            else:
                filterstr = "(memberUid={})".format(escape_filter_chars(user_uid))

            search = group_search.search_with_additional_term_string(filterstr)
            groups = search.execute(ldap_user.connection)
        except (KeyError, IndexError):
            groups = []

        return groups

    def is_member(self, ldap_user: "_LDAPUser", group_dn: str) -> bool:
        """
        Returns True if the group is the user's primary group or if the user is
        listed in the group's memberUid attribute.
        """
        try:
            user_uid = ldap_user.get_single_attr("uid")

            try:
                msgid = ldap_user.connection.compare(
                    group_dn, "memberUid", user_uid.encode()
                )
                is_member = (
                    ldap_user.connection.get_response(msgid)[1]["result"]
                    == RESULT_COMPARE_TRUE
                )
            except (LDAPUndefinedAttributeTypeResult, LDAPNoSuchAttributeResult):
                is_member = False

            if not is_member:
                try:
                    user_gid = ldap_user.get_single_attr("gidNumber")
                    msgid = ldap_user.connection.compare(
                        group_dn, "gidNumber", user_gid.encode()
                    )
                    is_member = (
                        ldap_user.connection.get_response(msgid)[1]["result"]
                        == RESULT_COMPARE_TRUE
                    )
                except (LDAPUndefinedAttributeTypeResult, LDAPNoSuchAttributeResult):
                    is_member = False
        except (KeyError, IndexError):
            is_member = False

        return is_member


class MemberDNGroupType(LDAPGroupTypeIsMember):
    """
    A group type that stores lists of members as distinguished names.
    """

    def __init__(self, member_attr: str, name_attr: str = "cn") -> None:
        """
        member_attr is the attribute on the group object that holds the list of
        member DNs.
        """
        self.member_attr: str = member_attr

        super().__init__(name_attr)

    def __repr__(self):
        return "<{}: {}>".format(type(self).__name__, self.member_attr)

    def user_groups(
        self, ldap_user: "_LDAPUser", group_search: AbstractLDAPSearch
    ) -> Collection[Tuple[str, Dict[str, Any]]]:
        if ldap_user.dn is None:
            raise TypeError("The dn of the LDAP user should not be None")

        search = group_search.search_with_additional_terms(
            {self.member_attr: ldap_user.dn}
        )
        return search.execute(ldap_user.connection)

    def is_member(self, ldap_user: "_LDAPUser", group_dn: str) -> bool:
        if ldap_user.dn is None:
            raise TypeError("The dn of the LDAP user should not be None")

        try:
            msgid = ldap_user.connection.compare(
                group_dn, self.member_attr, ldap_user.dn.encode()
            )
            return (
                ldap_user.connection.get_response(msgid)[1]["result"]
                == RESULT_COMPARE_TRUE
            )
        except (LDAPUndefinedAttributeTypeResult, LDAPNoSuchAttributeResult):
            return False


class NestedMemberDNGroupType(LDAPGroupType):
    """
    A group type that stores lists of members as distinguished names and
    supports nested groups.
    """

    def __init__(self, member_attr: str, name_attr: str = "cn") -> None:
        """
        member_attr is the attribute on the group object that holds the list of
        member DNs.
        """
        self.member_attr: str = member_attr

        super().__init__(name_attr)

    def user_groups(
        self, ldap_user: "_LDAPUser", group_search: AbstractLDAPSearch
    ) -> ItemsView[str, Dict[str, Any]]:
        """
        This searches for all of a user's groups from the bottom up. In other
        words, it returns the groups that the user belongs to, the groups that
        those groups belong to, etc. Circular references will be detected and
        pruned.
        """
        if ldap_user.dn is None:
            raise TypeError("The dn of the LDAP user should not be None")

        group_info_map = dict()  # Maps group_dn to group_info of groups we've found
        member_dn_set = {ldap_user.dn}  # Member DNs to search with next
        handled_dn_set = set()  # Member DNs that we've already searched with

        while len(member_dn_set) > 0:
            group_infos = dict(
                self._find_groups_with_any_member(
                    member_dn_set, group_search, ldap_user.connection
                )
            )
            group_info_map.update(group_infos)
            handled_dn_set.update(member_dn_set)

            # Get ready for the next iteration. To avoid cycles, we make sure
            # never to search with the same member DN twice.
            member_dn_set = set(group_infos.keys()) - handled_dn_set

        return group_info_map.items()

    def _find_groups_with_any_member(
        self,
        member_dn_set: Set[str],
        group_search: AbstractLDAPSearch,
        connection: Connection,
    ) -> Collection[Tuple[str, Dict[str, Any]]]:
        terms = [
            "({}={})".format(self.member_attr, escape_filter_chars(dn))
            for dn in member_dn_set
        ]

        filterstr = "(|{})".format("".join(terms))
        search = group_search.search_with_additional_term_string(filterstr)

        return search.execute(connection)


class GroupOfNamesType(MemberDNGroupType):
    """
    An LDAPGroupType subclass that handles groups of class groupOfNames.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("member", name_attr)


class NestedGroupOfNamesType(NestedMemberDNGroupType):
    """
    An LDAPGroupType subclass that handles groups of class groupOfNames with
    nested group references.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("member", name_attr)


class GroupOfUniqueNamesType(MemberDNGroupType):
    """
    An LDAPGroupType subclass that handles groups of class groupOfUniqueNames.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("uniqueMember", name_attr)


class NestedGroupOfUniqueNamesType(NestedMemberDNGroupType):
    """
    An LDAPGroupType subclass that handles groups of class groupOfUniqueNames
    with nested group references.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("uniqueMember", name_attr)


class ActiveDirectoryGroupType(MemberDNGroupType):
    """
    An LDAPGroupType subclass that handles Active Directory groups.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("member", name_attr)


class NestedActiveDirectoryGroupType(NestedMemberDNGroupType):
    """
    An LDAPGroupType subclass that handles Active Directory groups with nested
    group references.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("member", name_attr)


class OrganizationalRoleGroupType(MemberDNGroupType):
    """
    An LDAPGroupType subclass that handles groups of class organizationalRole.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("roleOccupant", name_attr)


class NestedOrganizationalRoleGroupType(NestedMemberDNGroupType):
    """
    An LDAPGroupType subclass that handles groups of class OrganizationalRoleGroupType
    with nested group references.
    """

    def __init__(self, name_attr: str = "cn") -> None:
        super().__init__("roleOccupant", name_attr)


class LDAPGroupQuery(Node):
    """
    Represents a compound query for group membership.

    This can be used to construct an arbitrarily complex group membership query
    with AND, OR, and NOT logical operators. Construct primitive queries with a
    group DN as the only argument. These queries can then be combined with the
    ``&``, ``|``, and ``~`` operators.

    :param str group_dns: The DN of a group to test for membership.
    """

    # Connection types
    AND = "AND"
    OR = "OR"
    default = AND

    _CONNECTORS = [AND, OR]

    def __init__(self, *group_dns: str) -> None:
        super().__init__(children=list(group_dns))

    def __and__(self, other: "LDAPGroupQuery") -> "LDAPGroupQuery":
        return self._combine(other, self.AND)

    def __or__(self, other: "LDAPGroupQuery") -> "LDAPGroupQuery":
        return self._combine(other, self.OR)

    def __invert__(self) -> "LDAPGroupQuery":
        obj = type(self)()
        obj.add(self, self.AND)
        obj.negate()

        return obj

    def _combine(self, other: "LDAPGroupQuery", conn: str) -> "LDAPGroupQuery":
        if not isinstance(other, LDAPGroupQuery):
            raise TypeError(other)
        if conn not in self._CONNECTORS:
            raise ValueError(conn)

        obj = type(self)()
        obj.connector = conn
        obj.add(self, conn)
        obj.add(other, conn)

        return obj

    def resolve(
        self, ldap_user: "_LDAPUser", groups: Optional["_LDAPUserGroups"] = None
    ) -> bool:
        if groups is None:
            groups = ldap_user._get_groups()

        result = self.aggregator(self._resolve_children(ldap_user, groups))
        if self.negated:
            result = not result

        return result

    @property
    def aggregator(self) -> Callable[[Iterable[object]], bool]:
        """
        Returns a function for aggregating a sequence of sub-results.
        """
        if self.connector == self.AND:
            aggregator = all
        elif self.connector == self.OR:
            aggregator = any
        else:
            raise ValueError(self.connector)

        return aggregator

    def _resolve_children(
        self, ldap_user: "_LDAPUser", groups: "_LDAPUserGroups"
    ) -> Iterator[bool]:
        """
        Generates the query result for each child.
        """
        for child in self.children:
            if isinstance(child, LDAPGroupQuery):
                yield child.resolve(ldap_user, groups)
            else:
                yield groups.is_member_of(child)
