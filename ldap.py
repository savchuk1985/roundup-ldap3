#!/usr/bin/env python3

# Copyright (c) 2023 Anton Savchuk <a.savchuk@gmx.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import ssl
import logging
import importlib

from urllib.parse import urlparse

from roundup.i18n import _
from roundup.cgi.actions import LoginAction
from roundup.configuration import NODEFAULT
from roundup.configuration import Option, SpaceSeparatedListOption
from roundup.configuration import BooleanOption, NullableFilePathOption
from roundup.exceptions import LoginError
from roundup.password import Password, generatePassword

try:
    import ldap3
except ImportError:
    ldap3 = None


class LdapLoginAction(LoginAction):
    """Authenticate the user against the LDAP directory.

    Authentication is performed using direct binding to the LDAP directory.
    The user properties will always be created or updated according
    to the information from the LDAP entry attributes. Database records
    are not used for authentication and are forced to be updated.

    Group membership information can also be used for authorization if
    provided. In this case, the 'memberOf' attribute will be checked first.
    Group entries will only be searched if the attribute is not found
    in the user entry.

    LDAP protocol messages are enabled and will be logged.
    """

    # use a direct descendant of 'roundup' logger
    logger = logging.getLogger('roundup.actions')
    connect = None

    def verifyLogin(self, username, password):
        """Verify the username and password from the login form."""

        # throw an import error only when trying to login
        if not ldap3:
            try:
                importlib.import_module('ldap3')
            except ImportError:
                self.logger.error("module 'ldap3' must be installed")
                raise LoginError(_("Tracker is not configured properly. "
                                   "Contact your system administrator."))

        # enable ldap3 logging
        ldap3.utils.log.logger = self.logger.getChild('ldap3')
        self.activateLdapMessages(self.db.config.ext.LDAP_LOG_ACTIVATION)
        self.detailizeLdapMessages(self.db.config.ext.LDAP_LOG_DETAILS)

        try:
            self.connect = self.startConnection(username, password)
            self.logger.info("LDAP connection is established")
            propvalues = self.parsePropsFromEntry(username)
        except ldap3.core.exceptions.LDAPBindError:
            self.logger.info("LDAP authentication failed")
            raise LoginError(_("Invalid login"))
        except ldap3.core.exceptions.LDAPExceptionError:
            self.logger.exception("failed to connect to LDAP server")
            raise LoginError(_("Unable to check login permission"))
        finally:
            self.closeConnection()

        try:
            # try to open the tracker as the current user
            self.userid = self.db.user.lookup(self.client.user)

            # open the journal as uid 1
            self.db.journaltag = 'admin'

            # bypass auditors and reactors with set_inner() since user property
            # values must always match the values in the directory entry
            self.db.user.set_inner(self.userid, **self.selectprops(propvalues))
        except KeyError:
            # or just create a new user with a random password if not found
            self.logger.info("user %s not found, trying to create" % username)
            propvalues.update(username=username,
                              password=Password(generatePassword(),
                                                config=self.db.config))
            # open the journal as uid 1
            self.db.journaltag = 'admin'
            self.userid = self.db.user.create(**self.selectprops(propvalues))
        finally:
            self.db.commit()


    def startConnection(self, username, password):
        config = self.db.config
        uri = urlparse(config.ext.LDAP_URI)

        tls = None
        if config.ext.LDAP_STARTTLS or uri.scheme == 'ldaps':
            tls = ldap3.Tls(
                local_certificate_file=config.ext.LDAP_TLS_CERTFILE,
                local_private_key_file=config.ext.LDAP_TLS_KEYFILE,
                ca_certs_file=config.ext.LDAP_TLS_CAFILE,
                validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLS
            )

        server = ldap3.Server(uri.hostname, port=uri.port,
                              use_ssl=uri.scheme == 'ldaps',
                              get_info=ldap3.ALL, tls=tls)

        binddn = self._get_userdn(username)
        conn = ldap3.Connection(server, binddn, password,
                                read_only=True,
                                client_strategy=ldap3.SYNC,
                                auto_bind=ldap3.AUTO_BIND_NONE,
                                authentication=ldap3.SIMPLE)

        if config.ext.LDAP_STARTTLS and not uri.scheme == 'ldaps':
            conn.start_tls()
        if not conn.bind():
            self.logger.info("unable to bind dn: '%s'" % binddn)
            raise ldap3.core.exceptions.LDAPBindError
        return conn


    def closeConnection(self):
        if self.connect and self.connect.bound:
            self.connect.unbind()
            self.logger.info("LDAP connection is closed")


    def parsePropsFromEntry(self, username):
        config = self.db.config
        attrs = self._get_attributes(username)
        current_groups = self._get_membership(username, attrs)
        admin_groups = config.ext.LDAP_ADMIN_GROUPS
        user_groups = config.ext.LDAP_USER_GROUPS
        props = {}

        # check if the user is in any allowed group, or select initial roles
        # if no groups are specified in the configuration, otherwise log out
        if admin_groups and any(x in current_groups for x in admin_groups):
            props['roles'] = 'Admin'
        elif not user_groups or any(x in current_groups for x in user_groups):
            props['roles'] = config.NEW_WEB_USER_ROLES
        else:
            raise LoginError(_("You do not have permission to login"))

        if 'mail' in attrs:
            # multi-valued attribute
            props['address'] = attrs['mail'][0]
            props['alternate_addresses'] = '\n'.join(attrs['mail'][1:])

        if 'displayName' in attrs:
            # single-valued attribute
            props['realname'] = attrs['displayName']

        if 'o' in attrs:
            # multi-valued attribute
            props['organization'] = attrs['o'][0]

        if 'telephoneNumber' in attrs:
            # multi-valued attribute
            props['phone'] = attrs['telephoneNumber'][0]
        elif 'mobile' in attrs:
            # multi-valued attribute
            props['phone'] = attrs['mobile'][0]

        self.logger.info("%s properties were retrieved for "
                         "the user '%s'" % (len(props) or "no", username))
        return props


    def selectprops(self, propvalues):
        # get the user class properties
        user_props = self.db.getclass('user').getprops()
        return {k: v for k, v in propvalues.items() if k in user_props}


    def _get_userdn(self, username):
        dn = '%s=%s,%s' % (self.db.config.ext.LDAP_USER_ATTR,
                           ldap3.utils.dn.escape_rdn(username),
                           self.db.config.ext.LDAP_USER_BASE)
        self.logger.info("set dn '%s' for the user '%s'" % (dn, username))
        return dn


    def _get_attributes(self, username):
        sfilter = '(%s=%s)' % (self.db.config.ext.LDAP_USER_ATTR,
                               ldap3.utils.dn.escape_rdn(username))
        self.logger.info("using filter '%s' to find user entry" % sfilter)

        attrs = {}
        if self.connect.search(self._get_userdn(username), sfilter,
                               attributes=ldap3.ALL_ATTRIBUTES,
                               search_scope=ldap3.BASE):
            response = self.connect.response
            attrs = response[0]['attributes']

        self.logger.info("%s attribute types found for the user "
                         "'%s'" % (len(attrs) or "no", username))
        return attrs


    def _get_membership(self, username, attrs):
        basedn = self.db.config.ext.LDAP_GROUP_BASE
        groups = []
        if basedn:
            try:
                groups = attrs['memberOf']
            except KeyError:
                self.logger.info("no 'memberOf' attributes are"
                                 "found, trying to find groups")
                sfilter = '(member=%s)' % self._get_userdn(username)
                self.logger.info("using filter '%s' to find "
                                 "group entries" % sfilter)
                if self.connect.search(basedn, sfilter,
                                       attributes=ldap3.NO_ATTRIBUTES,
                                       search_scope=ldap3.SUBTREE):
                    response = self.connect.response
                    groups = [entry['dn'] for entry in response]
        self.logger.info(
            "%s groups found for the user '%s'" % (len(groups) or "no",
                                                   username))
        return [ldap3.utils.dn.parse_dn(x)[0][1]
                for x in groups if x.endswith(basedn)]


    def activateLdapMessages(self, level):
        level = self._sanitize_log_level(level)
        try:
            ldap3.utils.log.set_library_log_activation_level(
                getattr(logging, level))
        except AttributeError:
            ldap3.utils.log.set_library_log_activation_level(logging.ERROR)
            self.logger.warning("failed to set log activation level to %s, "
                                "fall back to ERROR" % level)


    def detailizeLdapMessages(self, level):
        level = self._sanitize_log_level(level)
        try:
            ldap3.utils.log.set_library_log_detail_level(
                getattr(ldap3.utils.log, level))
        except AttributeError:
            ldap3.utils.log.set_library_log_detail_level(ldap3.utils.log.ERROR)
            self.logger.warning("failed to set log detail level to %s, "
                                "fall back to ERROR" % level)


    def _sanitize_log_level(self, value):
        if not value:
            value = 'ERROR'
        return value.upper()


def init(instance):
    instance.config.ext.update_option(
        'LDAP_URI', Option, default=NODEFAULT,
        description="Contains an URL of the LDAP server.")
    instance.config.ext.update_option(
        'LDAP_USER_BASE', Option, default=NODEFAULT,
        description="Contains base DN for LDAP user entries.")
    instance.config.ext.update_option(
        'LDAP_USER_ATTR', Option, default="uid",
        description="Contains LDAP user attribute.")
    instance.config.ext.update_option(
        'LDAP_GROUP_BASE', Option, default="",
        description=("Contains base DN for LDAP group entries. Only direct\n"
                     "children of this entry are checked for memebership.\n"
                     "Membership is not checked if no base DN is specified."))
    instance.config.ext.update_option(
        'LDAP_USER_GROUPS', SpaceSeparatedListOption, default="",
        description=("Contains space-separated list of user group names.\n"
                     "Membership is not checked if groups are not specified."))
    instance.config.ext.update_option(
        'LDAP_ADMIN_GROUPS', SpaceSeparatedListOption, default="",
        description=("Contains space-separated list of admin group names.\n"
                     "Membership is not checked if groups are not specified."))
    instance.config.ext.update_option(
        'LDAP_STARTTLS', BooleanOption, default="no",
        description=("Enables transport layer security for LDAP using\n"
                     "STARTTLS. Has no effect for LDAPS connections."))
    instance.config.ext.update_option(
        'LDAP_TLS_KEYFILE', NullableFilePathOption, default="",
        description="Path to a file containing the private client key.")
    instance.config.ext.update_option(
        'LDAP_TLS_CERTFILE', NullableFilePathOption, default="",
        description="Path to a file containing the client certificate.")
    instance.config.ext.update_option(
        'LDAP_TLS_CAFILE', NullableFilePathOption, default="",
        description=("Path to a file containing Certificate Authority\n"
                     "certificates used for LDAP secure connections."))
    instance.config.ext.update_option(
        'LDAP_LOG_DETAILS', Option, default="ERROR",
        description=("Minimal level of detail for LDAP protocol messages.\n"
                     "If set incorrectly, the default value will be applied.\n"
                     "Levels: OFF, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED"))
    instance.config.ext.update_option(
        'LDAP_LOG_ACTIVATION', Option, default="ERROR",
        description=("Logging activation level for LDAP protocol messages.\n"
                     "If set incorrectly, the default value will be applied.\n"
                     "Levels: NOTSET, INFO, DEBUG, WARNING, ERROR, CRITICAL"))
    instance.registerAction('login', LdapLoginAction)
