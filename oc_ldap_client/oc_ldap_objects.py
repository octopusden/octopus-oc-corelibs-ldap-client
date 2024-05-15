#!/usr/bin/env python3

# OC LDAP connection client
from .oc_ldap import OcLdap, OcLdapRecord
import ldap3
import logging


class OcLdapUserCat(OcLdap):
    """
    User catalogue-specific methods
    """

    def __init__(self, url=None, user_cert=None, user_key=None, ca_chain=None, baseDn=None,
                 user=None, password=None):
        """
        Initialization
        :param str url: OpenLDAP host URI
        :param str user_cert: path to user SSL certificate
        :param str user_key: path to user private key
        :param str ca_chain: path to CA certificates chain
        :param str baseDn: base DN to work with
        """
        super().__init__(url=url, user_cert=user_cert,
                         user_key=user_key, ca_chain=ca_chain, baseDn=baseDn,
                         user=user, password=password)
        self._userObjectClass = 'inetOrgPerson'
        self._groupObjectClass = 'groupOfUniqueNames'

    def get_user_by_login(self, login):
        """
        Get catalogue user class instance.
        Gives a class derived from LDAP if exista.
        Gives a template if not exists
        :param str login: login for user, currently 'cn' LDAP attribute
        :return: OcLdapUserRecord class or None if not found
        """

        filterstr = '(&(cn=%s)(objectClass=%s))' % (
            login, self._userObjectClass)
        logging.debug("Search filter: %s" % filterstr)

        # search user
        rslt = self.ldap_c.search(
            search_base=self.baseDn,
            search_scope=ldap3.SUBTREE,
            search_filter=filterstr,
            attributes=None,
            get_operational_attributes=False
        )

        if not rslt:
            logging.error("Record for user '%s' was not found" % login)
            return OcLdapUserRecord()

        rslt = self.ldap_c.entries

        self._check_search_rslt(rslt)
        logging.debug(rslt[0].entry_dn)

        return OcLdapUserRecord(self._get_record(rslt[0].entry_dn))

    def get_group_by_name(self, group_name):
        """
        Get catalogue group of users
        :param str group_name: group name (cn)
        """

        filterstr = '(&(cn=%s)(objectClass=%s))' % (
            group_name, self._groupObjectClass)
        logging.debug("Search filter: %s" % filterstr)

        # search group
        rslt = self.ldap_c.search(
            search_base=self.baseDn,
            search_scope=ldap3.SUBTREE,
            search_filter=filterstr,
            attributes=None,
            get_operational_attributes=False
        )

        if not rslt:
            logging.error("Record for group '%s' was not found" % group_name)
            return OcLdapGroupRecord()

        rslt = self.ldap_c.entries

        self._check_search_rslt(rslt)
        logging.debug(rslt[0].entry_dn)

        return OcLdapGroupRecord(self._get_record(rslt[0].entry_dn))

    def list_users(self, add_filter=None):
        """
        Return list of users with a filter applied
        Return all users if group_name is empty or None
        :param str add_filter: group name
        :return: list of strings with user DNs
        """

        filterstr = '(objectClass=%s)' % self._userObjectClass

        if add_filter:
            filterstr = '(&%s%s)' % (filterstr, add_filter)

        return self.list_records(filterstr)


    def list_groups(self, add_filter=None):
        """
        Return list of all groups.
        :return: list of catalogue group names
        """
        filterstr = '(objectClass=%s)' % self._groupObjectClass

        if add_filter:
            filterstr = '(&%s%s)' % (filterstr, add_filter)

        return self.list_records(filterstr)


class OcLdapGroupRecord(OcLdapRecord):
    """
    wrapper for catalogue group
    Checks for attributes
    Filling attributes
    """

    def __init__(self, ldap_record=None):
        """
        initialization
        :param dict ldap_record: a record from catalog
        """

        objectClass = 'groupOfUniqueNames'
        super().__init__(ldap_record)

        if self.get_attribute('objectClass') \
                and self.get_attribute('objectClass').lower() != objectClass.lower():
            raise TypeError("Wrong LDAP object class: %s, ought to be: %s" %
                            (self.get_attribute('objectClass'), objectClass))
        elif not self.get_attribute('objectClass'):
            self.set_attribute('objectClass', objectClass)

class OcLdapUserRecord(OcLdapRecord):
    """
    wrapper for catalogue external user LDAP object
    Checks for attributes
    Filling attributes
    """

    def __init__(self, ldap_record=None):
        """
        initialization
        :param ldap_record: a record from catalog
        :type ldap_record: dict
        """

        objectClass = 'inetOrgPerson'
        super().__init__(ldap_record)

        if self.get_attribute('objectClass') \
                and self.get_attribute('objectClass').lower() != objectClass.lower():
            raise TypeError("Wrong LDAP object class: %s, ought to be: %s" %
                            (self.get_attribute('objectClass'), objectClass))
        elif not self.get_attribute('objectClass'):
            self.set_attribute('objectClass', objectClass)

    @property
    def __lock_time_value(self):
        """
        specific constant to lock user forever
        admin only can unlock then
        """
        return b'000001010000Z'

    @property
    def is_locked(self):
        """
        Check user is locked
        """
        return self.get_attribute('pwdAccountLockedTime')

    def lock(self):
        """
        Set user account status to "locked forever".
        """
        self.set_attribute('pwdAccountLockedTime', self.__lock_time_value)

    def unlock(self):
        """
        Unlock user account
        """
        self.drop_attribute('pwdAccountLockedTime')
