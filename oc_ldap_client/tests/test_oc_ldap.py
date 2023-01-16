from unittest import TestCase
from unittest.mock import patch
from unittest import expectedFailure
from .mocks.ldap3 import MockLdapConnection
from .mocks.randomizer import Randomizer
from oc_ldap_client.oc_ldap import OcLdap
from oc_ldap_client.oc_ldap import OcLdapRecord
import os
import ldap3

# remove unnecessary log output
import logging
logging.getLogger().propagate = False
logging.getLogger().disabled = True


class OcLdapTest(TestCase):

    @patch('ldap3.Connection', new=MockLdapConnection)
    def _get_ldap(self):
        self_dir = os.path.dirname(os.path.abspath(__file__))
        key_path = os.path.join(self_dir, 'ssl_keys')
        return OcLdap(url='ldap://localhost:389', 
            user_cert=os.path.join(key_path, 'user.pem'),
            user_key=os.path.join(key_path, 'user.priv.key'),
            ca_chain=os.path.join(key_path, 'ca_chain.pem'),
            baseDn='dc=some,dc=test,dc=domain,dc=local')

    def test_init(self):
        ldap_t = self._get_ldap()
        self.assertEqual(ldap_t.baseDn, "dc=some,dc=test,dc=domain,dc=local")
        self.assertTrue(ldap_t.ldap_c.tls_started)

    def test_get_record(self):
        ldap_t = self._get_ldap()
        # try to get admin group record from our json test data
        # do not forget to change it in cdt_ldap/tests/mocks/ldap_data/
        # if something is changed here
        dn = 'cn=LDAP Admins,dc=some,dc=test,dc=domain,dc=local'
        ldap_rec = ldap_t.get_record(dn)

        #compare DN with our
        self.assertEqual(dn.lower(), ldap_rec.dn.lower())

        #compare attributes
        self.assertEqual(ldap_rec.get_attribute('objectClass').lower(), 'groupOfNames'.lower())
        self.assertEqual(ldap_rec.get_attribute('cn').lower(), 'LDAP Admins'.lower())
        self.assertEqual(ldap_rec.get_attribute('ou').lower(), 'TestUnit'.lower())

    def test_update_record(self):
        #this record is taken from pre-defined test data
        # do not forget to change it in cdt_ldap/tests/mocks/ldap_data/
        # if something is changed here
        ldap_t = self._get_ldap()
        rndm = Randomizer();
        dn = 'cn=LDAP Admins,dc=some,dc=test,dc=domain,dc=local'
        dscr1 = rndm.random_str(17)
        dscr2 = rndm.random_str(23)

        ldap_r1 = ldap_t.get_record(dn)
        ldap_r1.append_attribute('description', dscr1)
        ldap_r2 = ldap_t.put_record(ldap_r1)
        self.assertEqual(ldap_r2.get_attribute('description'), dscr1)
        ldap_r2.append_attribute('description', dscr2)
        ldap_r1 = ldap_t.put_record(ldap_r2)
        self.assertEqual(sorted([dscr1, dscr2]), sorted(ldap_r1.get_attribute('description')))

    def test_rename_record(self):
        ldap_t = self._get_ldap()
        # first create some record

    def test_create_record(self):
        ldap_t = self._get_ldap()
        rndm = Randomizer()
        cn = rndm.random_str(10)
        sn = rndm.random_str(5)
        givenName = rndm.random_str(5)
        ph = list()
        
        for i in range(0, 10):
            ph.append(rndm.random_digits(10))

        ldap_record = OcLdapRecord()
        ldap_record.set_attribute('objectClass', 'inetOrgPerson')
        ldap_record.set_attribute('cn', cn)
        ldap_record.set_attribute('givenName', givenName)
        ldap_record.set_attribute('sn', sn)
        ldap_record.set_attribute('telephoneNumber', ph)

        ldap_record_n = ldap_t.put_record(ldap_record)
        self.assertEqual(ldap_record_n.dn, 'cn=%s,%s' % (cn, ldap_t.baseDn))
        self.assertEqual(ldap_record_n.get_attribute('CN'), cn)
        self.assertEqual(ldap_record_n.get_attribute('GIVENNAME'), givenName)
        self.assertEqual(ldap_record_n.get_attribute('sn'), sn)
        self.assertEqual(sorted(ldap_record_n.get_attribute('TELEpHoneNUMBER')), sorted(ph))

    def test_rename_record(self):
        ldap_t = self._get_ldap()
        rndm = Randomizer()

        # first create some record
        cn_orig = rndm.random_str(10)
        sn_orig = rndm.random_str(5)

        ldap_r1 = OcLdapRecord()
        ldap_r1.set_attribute('objectClass', 'inetOrgPerson')
        ldap_r1.set_attribute('cn', cn_orig)
        ldap_r1.set_attribute('sn', sn_orig)
        self.assertIsNone(ldap_r1.dn)
        ldap_r1 = ldap_t.put_record(ldap_r1)
        self.assertIsNotNone(ldap_r1.dn)

        # do renaming
        cn_new = rndm.random_str(9) #surely different because of length
        ldap_r2 = ldap_t.rename_record(ldap_r1, cn_new)
        self.assertEqual(ldap_r2.get_attribute('sn'), ldap_r1.get_attribute('sn'))
        self.assertNotEqual(ldap_r2.dn, ldap_r1.dn)
        self.assertTrue(ldap_t.get_record(ldap_r1.dn).is_new)

    def test_delete_record(self):
        ldap_t = self._get_ldap()
        rndm = Randomizer()

        # first create some record
        cn = rndm.random_str(10)
        sn = rndm.random_str(5)

        ldap_r = OcLdapRecord()
        ldap_r.set_attribute('objectClass', 'inetOrgPerson')
        ldap_r.set_attribute('cn', cn)
        ldap_r.set_attribute('sn', sn)
        self.assertIsNone(ldap_r.dn)
        ldap_r = ldap_t.put_record(ldap_r)
        self.assertIsNotNone(ldap_r.dn)

        # do delete
        ldap_t.delete_record(ldap_r)
        self.assertTrue(ldap_t.get_record(ldap_r.dn).is_new)

    @expectedFailure
    def test_login_as_user(self):
        ldap_t = self._get_ldap()
        prev_l = ldap_t.ldap_c.extend.standard.who_am_i()
        ldap_rec = OcLdapRecord()
        ldap_rec.set_attribute('cn', Randomizer().random_str(10))
        ldap_rec.set_attribute('objectClass', 'inetOrgPerson')
        ldap_rec.set_attribute('userPassword', Randomizer().random_str(15))
        ldap_rec = ldap_t.put_record(ldap_rec)
        now_l = ldap_t.login_as_user(ldap_rec.dn, ldap_rec.get_attribute('userPassword'))

        #this assertation have to fail because 'who_am_i()'
        #returns None always on mocketized ldap3 connection
        self.assertNotEqual(now_l, prev_l)

        self.assertEqual(now_l, ldap_rec.dn)

    def test_list_records(self):
        ldap_t = self._get_ldap()
        # put 110-150 records - randomly
        _rnd = Randomizer()
        _len = _rnd.random_number(110, 150)
        _samples = list(map(lambda x: ldap_t.get_record(x), ldap_t.list_records()))
        _classes = ['groupOfUniqueNames', 'inetOrgPerson']

        # classes for filter: first 30 - 'groupOfUniqueNames'; rest - 'inetOrgPerson'
        for _idx in range(0, _len):
            _rec = OcLdapRecord()
            _rec.set_attribute('cn', _rnd.random_str(_rnd.random_number(10,15)))
            _rec.set_attribute('objectClass', _classes[0] if _idx >= 30 else _classes[1])
            _rec = ldap_t.put_record(_rec)
            _samples.append(_rec)

        self.assertListEqual(sorted(list(map(lambda x: x.dn, _samples))), sorted(ldap_t.list_records()))

        for _class in _classes:
            _expected = list(filter(lambda x: x.get_attribute('objectClass') == _class, _samples))
            _expected = list(map(lambda x: x.dn, _expected))
            self.assertListEqual(sorted(_expected), sorted(ldap_t.list_records('(objectClass=%s)' % _class)))

class OcLdapRecordTest(TestCase):
    @property
    def _random_dn(self):
        rnd = Randomizer()
        return 'cn=%s,dc=%s,dc=%s' %(rnd.random_str(25),rnd.random_str(8),rnd.random_str(3))

    def test_init(self):
        rnd = Randomizer()

        ldap_r = OcLdapRecord()
        self.assertIsNone(ldap_r._ldap_record_orig)
        self.assertIsInstance(ldap_r._ldap_record_mod, dict)
        self.assertIsInstance(ldap_r._ldap_record_mod.get('attributes'), dict)
        self.assertIsNone(ldap_r._ldap_record_mod.get('dn'))

        rec = {'dn' : self._random_dn, 'attributes' : {rnd.random_str(10) : rnd.random_str(10)}}
        ldap_r = OcLdapRecord(rec)
        self.assertEqual(ldap_r._ldap_record_orig, rec)
        self.assertEqual(ldap_r._ldap_record_mod, rec)

        rec = {'dn' : self._random_dn, 'attributes' : 
                {rnd.random_str(10) : [rnd.random_str(10), rnd.random_str(11)],
                 rnd.random_str(10) : [rnd.random_str(10), rnd.random_str(11)]}}
        ldap_r = OcLdapRecord(rec)
        self.assertEqual(ldap_r._ldap_record_orig, rec)
        self.assertEqual(ldap_r._ldap_record_mod, rec)

    def test_dn(self):
        dn = self._random_dn
        ldap_r = OcLdapRecord({'dn': dn, 'attributes': {}})
        self.assertEqual(ldap_r.dn, dn)

    def test_is_new(self):
        self.assertTrue(OcLdapRecord().is_new)
        self.assertFalse(OcLdapRecord(
            {'dn': self._random_dn,
                'attributes': {}}).is_new)

    def test_get_attr_plane(self):
        rnd = Randomizer()
        plane_val = rnd.random_str(10)
        dn = self._random_dn
        ldap_r = OcLdapRecord({'dn': dn, 'attributes' : {'testAttribute' : plane_val}})
        self.assertEqual(ldap_r.get_attribute('testAttribute'), plane_val)
        self.assertEqual(ldap_r.get_attribute('TESTATTRIBUTE'), plane_val)
        self.assertEqual(ldap_r.get_attribute('TestAttribute'), plane_val)
        self.assertEqual(ldap_r.get_attribute('testattribute'), plane_val)

    def test_get_attr_list(self):
        rnd = Randomizer()
        list_val = [rnd.random_str(10), rnd.random_digits(10), rnd.random_letters(10)]
        dn = self._random_dn
        ldap_r = OcLdapRecord({'dn': dn, 'attributes' : {'testAttribute' : list_val}})
        self.assertEqual(sorted(ldap_r.get_attribute('testAttribute')), sorted(list_val))
        self.assertEqual(sorted(ldap_r.get_attribute('TESTATTRIBUTE')), sorted(list_val))
        self.assertEqual(sorted(ldap_r.get_attribute('TestAttribute')), sorted(list_val))
        self.assertEqual(sorted(ldap_r.get_attribute('testattribute')), sorted(list_val))

    def test_get_attr_nonexist(self):
        rnd = Randomizer()
        attr1 = rnd.random_str(10)
        attr2 = rnd.random_str(12) #surely different
        list_val = [rnd.random_str(10), rnd.random_digits(10), rnd.random_letters(10)]
        dn = self._random_dn
        ldap_r = OcLdapRecord({'dn': dn, 'attributes' : {attr1 : list_val}})
        self.assertIsNotNone(ldap_r.get_attribute(attr1))
        self.assertIsNone(ldap_r.get_attribute(attr2))

    def test_set_attr_flat(self):
        ldap_r = OcLdapRecord({'dn': self._random_dn, 'attributes' : {}})
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = rnd.random_str(25)
        ldap_r.set_attribute(attr, val)
        self.assertEqual(ldap_r.get_attribute(attr), val)

    def test_set_attr_list(self):
        ldap_r = OcLdapRecord({'dn': self._random_dn, 'attributes' : {}})
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = [rnd.random_str(25), rnd.random_digits(7), rnd.random_letters(23)]
        ldap_r.set_attribute(attr, val)
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(val))

    def test_drop_attr_exist(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = [rnd.random_str(25), rnd.random_digits(7), rnd.random_letters(23)]
        ldap_r = OcLdapRecord({'dn': self._random_dn, 'attributes' : {attr:val}})
        ldap_r.drop_attribute(attr)
        self.assertIsNone(ldap_r.get_attribute(attr))

    def test_drop_attr_nonexist(self):
        rnd = Randomizer()
        attr1 = rnd.random_str(10)
        attr2 = rnd.random_str(12) #surely different
        val = [rnd.random_str(25), rnd.random_digits(7), rnd.random_letters(23)]
        ldap_r = OcLdapRecord({'dn': self._random_dn, 'attributes' : {attr1:val}})
        self.assertIsNone(ldap_r.get_attribute(attr2))
        ldap_r.drop_attribute(attr2)
        self.assertIsNotNone(ldap_r.get_attribute(attr1))
        self.assertIsNone(ldap_r.get_attribute(attr2))

    def test_append_attr_to_flat(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val1 = rnd.random_str(11)
        val2 = rnd.random_str(12)
        ldap_r = OcLdapRecord({'dn':self._random_dn, 'attributes':{attr:val1}})
        self.assertEqual(ldap_r.get_attribute(attr), val1)
        ldap_r.append_attribute(attr, val2)
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted([val1, val2]))

    def test_append_attr_to_list(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        lsval = [rnd.random_str(11), rnd.random_str(15), rnd.random_letters(25)]
        val = rnd.random_digits(12)
        ldap_r = OcLdapRecord({'dn':self._random_dn, 'attributes':{attr:lsval}})
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(lsval))
        ldap_r.append_attribute(attr, val)
        lsval.append(val)
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(lsval))

    def test_append_attr_list_to_list(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        lsval1 = [rnd.random_str(11), rnd.random_str(15), rnd.random_letters(25)]
        lsval2 = [rnd.random_digits(12), rnd.random_str(17), rnd.random_letters(33)]
        ldap_r = OcLdapRecord({'dn':self._random_dn, 'attributes':{attr:lsval1}})
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(lsval1))
        ldap_r.append_attribute(attr, lsval2)
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(lsval1 + lsval2))

    def test_delete_attr_value_list(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        lsval = [rnd.random_str(11), rnd.random_str(15), rnd.random_letters(25)]
        ldap_r = OcLdapRecord({'dn':self._random_dn, 'attributes':{attr:lsval}})
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(lsval))

        while len(lsval):
            rmval = lsval.pop()
            self.assertIn(rmval, ldap_r.get_attribute(attr))
            ldap_r.remove_attribute_value(attr, rmval)

            if isinstance(ldap_r.get_attribute(attr), list):
                self.assertNotIn(rmval, ldap_r.get_attribute(attr))

        self.assertIsNone(ldap_r.get_attribute(attr))

    def test_delete_attr_value_flat(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = rnd.random_str(11)
        ldap_r = OcLdapRecord({'dn':self._random_dn, 'attributes':{attr:val}})
        self.assertEqual(ldap_r.get_attribute(attr), val)
        ldap_r.remove_attribute_value(attr, val)
        self.assertIsNone(ldap_r.get_attribute(attr))

    def test_delete_attr_value_nonexist(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val_ne = rnd.random_str(7) #surely different
        val = rnd.random_str(11)
        ldap_r = OcLdapRecord({'dn':self._random_dn, 'attributes':{attr:val}})
        self.assertEqual(ldap_r.get_attribute(attr), val)
        ldap_r.remove_attribute_value(attr, val_ne)
        self.assertEqual(ldap_r.get_attribute(attr), val)
        lsval = [rnd.random_str(6), rnd.random_str(5)] #surely differs from val_ne
        ldap_r.set_attribute(attr, lsval)
        ldap_r.remove_attribute_value(attr, val_ne)
        self.assertEqual(sorted(ldap_r.get_attribute(attr)), sorted(lsval))

    def test_modification_add(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = rnd.random_str(11)
        lsval = [rnd.random_str(11), rnd.random_letters(11)]

        rc_flat = OcLdapRecord({'dn': self._random_dn, 'attributes':{}})
        rc_list = OcLdapRecord({'dn': self._random_dn, 'attributes':{}})

        rc_flat.set_attribute(attr, val)
        self.assertEqual(rc_flat.modifications, {attr: [(ldap3.MODIFY_ADD, val)]})
        rc_list.set_attribute(attr, lsval)
        self.assertEqual(rc_list.modifications[attr][0][0], ldap3.MODIFY_ADD)
        self.assertEqual(sorted(rc_list.modifications[attr][0][1]), sorted(lsval))

    def test_modification_delete(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = rnd.random_str(11)
        lsval = [rnd.random_str(11), rnd.random_letters(11)]

        rc_flat = OcLdapRecord({'dn': self._random_dn, 'attributes':{attr:val}})
        rc_list = OcLdapRecord({'dn': self._random_dn, 'attributes':{attr:lsval}})

        rc_flat.drop_attribute(attr)
        self.assertEqual(rc_flat.modifications, {attr: [(ldap3.MODIFY_DELETE, [])]})
        rc_list.drop_attribute(attr)
        self.assertEqual(rc_list.modifications, {attr: [(ldap3.MODIFY_DELETE, [])]})

    def test_modification_replace(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        val = rnd.random_str(11)
        lsval = [rnd.random_str(11), rnd.random_letters(11)]

        rc_flat = OcLdapRecord({'dn': self._random_dn, 'attributes':{attr:val}})
        rc_list = OcLdapRecord({'dn': self._random_dn, 'attributes':{attr:lsval}})

        rc_flat.set_attribute(attr, lsval)
        self.assertEqual(rc_flat.modifications[attr][0][0], ldap3.MODIFY_REPLACE)
        self.assertEqual(sorted(rc_flat.modifications[attr][0][1]), sorted(lsval))
        rc_list.append_attribute(attr, val)
        lsval.append(val)
        self.assertEqual(rc_list.modifications[attr][0][0], ldap3.MODIFY_REPLACE)
        self.assertEqual(sorted(rc_list.modifications[attr][0][1]), sorted(lsval))

    def test_modificatoin_delete_val(self):
        rnd = Randomizer()
        attr = rnd.random_str(10)
        lsval = [rnd.random_str(11), rnd.random_letters(11), rnd.random_digits(12)]
        rc_r = OcLdapRecord({'dn': self._random_dn, 'attributes':{attr:lsval}})

        rmval = lsval.pop()

        rc_r.remove_attribute_value(attr, rmval)
        self.assertEqual(rc_r.modifications[attr][0][0], ldap3.MODIFY_REPLACE)
        self.assertEqual(sorted(rc_r.modifications[attr][0][1]), sorted(lsval))
