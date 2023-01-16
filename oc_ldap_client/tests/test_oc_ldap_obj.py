from unittest import TestCase
from unittest.mock import patch
from .mocks.ldap3 import MockLdapConnection
from .mocks.randomizer import Randomizer
from oc_ldap_client.oc_ldap_objects import OcLdapUserCat
from oc_ldap_client.oc_ldap_objects import OcLdapGroupRecord
from oc_ldap_client.oc_ldap_objects import OcLdapUserRecord
import os

class OcLdapUserRecordTest(TestCase):
    @property
    def _random_dn(self):
        rnd = Randomizer()
        return 'cn=%s,dc=%s,dc=%s,dc=%s' %(rnd.random_str(14),rnd.random_str(6),rnd.random_str(8),rnd.random_str(3))

    def test_init(self):
        with self.assertRaises(TypeError):
            OcLdapUserRecord({'dn': self._random_dn, 'attributes': {'objectClass':'groupOfUniqueNames'}})

        self.assertEqual(OcLdapUserRecord().get_attribute('objectClass').lower(), 'inetOrgPerson'.lower())

    def test_lock(self):
        user_r = OcLdapUserRecord({'dn': self._random_dn, 'attributes':{'objectClass':'inetOrgPerson'}})
        user_r.lock()
        self.assertEqual(user_r.get_attribute('pwdAccountLockedTime'), b'000001010000Z')

    def test_unlock(self):
        rnd = Randomizer()
        user_r = OcLdapUserRecord({'dn': self._random_dn, 
            'attributes':{
                'objectClass':'inetOrgPerson',
                'pwdAccountLockedTime' : '%sZ' % rnd.random_digits(len('000001010000'))}})
        user_r.unlock()
        self.assertIsNone(user_r.get_attribute('pwdAccountLockedTime'))


class OcLdapGroupRecordTest(TestCase):
    def _random_dn(self, prefix = None):
        rnd = Randomizer()

        if not prefix:
            prefix = rnd.random_str(10,14)

        return 'cn=%s-%s,dc=%s,dc=%s,dc=%s' % \
            (prefix,rnd.random_letters(3,6),rnd.random_str(6),rnd.random_str(8),rnd.random_str(3))

    def _comp_from_dn(self, dn, comp = 'cn'):
        rslt = None

        for pair in dn.split(','):
            (_comp, _val) = pair.split('=')

            if _comp.lower() != comp.lower():
                continue

            if not rslt:
                rslt = _val
            else:
                if not isinstance(rslt, list):
                    rslt = [rslt]

                rslt.append(_val)

        return rslt

    def test_init(self):
        with self.assertRaises(TypeError):
            OcLdapGroupRecord({'dn': self._random_dn(), 'attributes': {'objectClass':'inetOrgPerson'}})

        self.assertEqual(OcLdapGroupRecord().get_attribute('objectClass').lower(), 'groupOfUniqueNames'.lower())

class OcLdapUserCatTest(TestCase):
    @patch('ldap3.Connection', new = MockLdapConnection)
    def _get_ldap(self):
        self_dir = os.path.dirname(os.path.abspath(__file__))
        key_path = os.path.join(self_dir, 'ssl_keys')
        return OcLdapUserCat(url='ldap://localhost:389', 
            user_cert=os.path.join(key_path, 'user.pem'),
            user_key=os.path.join(key_path, 'user.priv.key'),
            ca_chain=os.path.join(key_path, 'ca_chain.pem'),
            baseDn="dc=some,dc=test,dc=domain,dc=local")        

    def test_list_users(self):
        ldap_t = self._get_ldap()
        rnd = Randomizer()

        self.assertEqual(0, len(ldap_t.list_users()))

        # get initial users list
        # append users one-by-one and test its dn is in list
        list_dns = ldap_t.list_users()

        for idx in range(17, 37):
            usr = OcLdapUserRecord()
            usr.set_attribute('cn', rnd.random_letters(idx))
            usr = ldap_t.put_record(usr)
            self.assertIsNotNone(usr.dn)
            list_dns.append(usr.dn)
            self.assertListEqual(sorted(ldap_t.list_users()), sorted(list_dns))

    def test_list_groups(self):
        ldap_t = self._get_ldap()
        rnd = Randomizer()

        self.assertEqual(0, len(ldap_t.list_groups()))

        # get initial groups list
        # append groups one-by-one and test its dn is in list
        list_dns = ldap_t.list_groups()

        for idx in range(23, 53):
            grp = OcLdapGroupRecord()
            grp.set_attribute('cn', rnd.random_letters(idx))
            grp = ldap_t.put_record(grp)
            self.assertIsNotNone(grp.dn)
            list_dns.append(grp.dn)
            self.assertListEqual(sorted(ldap_t.list_groups()), sorted(list_dns))

    def test_get_user(self):
        #create user record
        rnd = Randomizer()
        usr = OcLdapUserRecord()
        usr.set_attribute('cn', rnd.random_letters(10))
        ldap_t = self._get_ldap()
        usr = ldap_t.put_record(usr)
        self.assertIsNotNone(usr.dn)
        self.assertIsInstance(usr, OcLdapUserRecord)

        #get it
        gr = ldap_t.get_user_by_login(usr.get_attribute('cn'))

        #verify
        self.assertIsInstance(gr, type(usr))
        self.assertEqual(gr.attributes, usr.attributes)

    def test_get_group(self):
        #create group record
        rnd = Randomizer()
        grp = OcLdapGroupRecord()
        grp.set_attribute('cn', rnd.random_letters(15))
        ldap_t = self._get_ldap()
        grp = ldap_t.put_record(grp)
        self.assertIsNotNone(grp.dn)
        self.assertIsInstance(grp, OcLdapGroupRecord)

        #get it
        gr = ldap_t.get_group_by_name(grp.get_attribute('cn'))

        #verify
        self.assertIsInstance(gr, type(grp))
        self.assertEqual(gr.attributes, grp.attributes)
