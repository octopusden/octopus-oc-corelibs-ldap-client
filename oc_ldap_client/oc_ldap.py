import logging
import ldap3
import os
import ssl
from copy import deepcopy
from urllib3.util import parse_url

# OC LDAP connection client


class OcLdap(object):
    """
    OC LDAP server connection class
    """

    def __init__(self, url=None, user_cert=None, user_key=None, ca_chain=None, baseDn=None,
                 user=None, password=None):
        """
        Initialization of connection
        :param str url: OpenLDAP host URI
        :param str user_cert: path to user SSL certificate
        :param str user_key: path to user private key
        :param str ca_chain: path to CA certificates chain
        :param str baseDn: base DN to work with
        """
        # parameters may be overriden if needed
        # system environment related values:
        # LDAP_URL
        # LDAPTLS_CERT
        # LDAPTLS_KEY
        # LDAPTLS_CACERT
        # LDAP_BASE_DN
        # LDAP_USER
        # LDAP_PASSWORD

        # default ports for supported protocols
        # taken from https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
        _port_defaults = {'ldap': 389, 'ldaps': 636, 'sldap': 636}

        self.baseDn = baseDn or os.getenv("LDAP_BASE_DN")

        if not baseDn:
            raise ValueError("'LDAP baseDn' is mandatory")

        logging.debug("baseDn: %s" % self.baseDn)

        url = url or os.getenv("LDAP_URL")

        if not url:
            raise ValueError("'LDAP URL' is mandatory")

        url = parse_url(url)
        proto = url.scheme or 'ldap'

        if proto not in _port_defaults.keys():
            raise ValueError("Protocol '%s' is not supported" % proto)

        host = url.host

        if not host:
            raise ValueError("Host is mandatory but not parsed from URL")

        port = url.port

        # correct port if not given
        # use 'proto' + defaults
        if not port:
            port = _port_defaults.get(proto)

        if not port:
            raise ValueError("Unable to find-out port number")

        url = "%s://%s" % (proto, host)
        user_key = self.__make_absolute_path(user_key or os.getenv("LDAPTLS_KEY"))
        user_cert = self.__make_absolute_path(user_cert or os.getenv("LDAPTLS_CERT"))
        ca_chain = self.__make_absolute_path(ca_chain or os.getenv("LDAPTLS_CACERT"))

        user = user or os.getenv("LDAP_USER")
        password = password or os.getenv("LDAP_PASSWORD")

        logging.debug("Host:\t%s" % url)
        logging.debug("Port:\t%d" % port)
        logging.debug("Private key:\t%s" % user_key)
        logging.debug("Certificate:\t%s" % user_cert)
        logging.debug("CA ceritificates chain:\t%s" % ca_chain)
        logging.debug("Username:\t%s" % user)
        logging.debug("Password:\t%s" % ('*' * len(password) if password else "<not set>"))

        # long definition of Tls connection
        # set the variables necessary if given
        # unfortunately we have to check every parameter for constructor
        # before calling it because of no legal possibility to set
        # those variables inside *Tls* object after creating
        # see doc: https://ldap3.readthedocs.io/en/latest/ssltls.html
        __tls_params = {
                "validate": ssl.CERT_OPTIONAL,
                "version": ssl.PROTOCOL_SSLv23
                }

        for __k, __v in [
                ("local_private_key_file", user_key),
                ("local_certificate_file", user_cert),
                ("ca_certs_file", ca_chain)]:

            if not __v:
                continue

            __tls_params[__k] = __v

        self.tls = ldap3.Tls(**__tls_params)

        self.server = ldap3.Server(
            host=url,
            port=port,
            tls=self.tls
        )

        # the same trick as above for TLS because of different authentication mechanisms
        # used for SASL and SIMPLE in case of username/password given
        __ldap_params = {
                "server": self.server,
                "version": 3,
                "authentication": ldap3.ANONYMOUS
                }

        if all([user_key, user_cert]):
            __ldap_params.update({
                "authentication": ldap3.SASL,
                "sasl_mechanism": 'EXTERNAL',
                "sasl_credentials": ''
                })
        elif all([user, password]):
            __ldap_params.update({
                "authentication": ldap3.SIMPLE,
                "user": user,
                "password": password
                })

        self.ldap_c = ldap3.Connection(**__ldap_params)

        self.ldap_c.start_tls()
        self.ldap_c.bind()


    def __make_absolute_path(self, pth):
        """
        Workaround for exception in case 'None' is passed to 'os.path.abspath'
        """

        if not pth:
            return None

        return os.path.abspath(pth)

    def _check_search_rslt(self, rslt):
        """
        Common checks for search results
        :param list rslt: list of ldap search results
        """
        if not isinstance(rslt, list):
            raise TypeError(
                'Invalid type returned from LDAP: %s' % type(rslt))

        if len(rslt) > 1:
            raise ValueError('More than one record returned')

    def _get_record(self, dn):
        """
        Get the exact record
        :param str dn: distinguished name
        :return: dictionary: {'dn': dn,  'attributes': dict(attributes)}
        """
        if not dn or not isinstance(dn, str):
            raise ValueError('Invalid DN given')

        rslt = self.ldap_c.search(
            search_base=dn,
            search_scope=ldap3.BASE,
            search_filter='(objectClass=*)',
            attributes=ldap3.ALL_ATTRIBUTES,
            get_operational_attributes=True
        )

        if not rslt:
            logging.error("Record '%s' was not found" % dn)
            return None

        rslt = self.ldap_c.entries

        self._check_search_rslt(rslt)

        logging.debug(rslt[0].entry_dn)
        # logging.debug(rslt[0].entry_attributes_as_dict)

        return {'dn': rslt[0].entry_dn, 'attributes': rslt[0].entry_attributes_as_dict}

    def _create_record(self, record):
        """
        Create new record.
        :param OcLdapRecord record: OcLdapRecord or derived class with a record to create
        :return: newly created record from server, type is the same as in source 'record'
        """

        new_record_dn = self._dn_by_cn(record.get_attribute('cn'))

        self.ldap_c.add(dn=self._dn_by_cn(record.get_attribute('cn')),
                        object_class=record.get_attribute('objectClass'),
                        attributes=record.attributes)

        return type(record)(self._get_record(new_record_dn))

    def put_record(self, record):
        """
        Add/Modify a record given
        :param OcLdapRecord record: OcLdap or derived class for record to put
        :return: modified record from server, type is the same as in source 'record'
        """

        if record.is_new:
            return self._create_record(record)

        self.ldap_c.modify(dn=record.dn, changes=record.modifications)

        return type(record)(self._get_record(record.dn))

    def _dn_by_cn(self, cn):
        """
        Transform CN to DN with suffixes
        """
        return ','.join(['='.join(['cn', cn]), self.baseDn])

    def rename_record(self, record, new_cn):
        """
        Modify record DN
        :param OcLdapRecord record: OcLdap or derived class for a record to rename
        :param str new_cn: new name
        :return: modified record from server, type is the same as in source 'record'
        """
        if record.is_new:
            raise Exception('New record renaming is not supported')

        new_dn = self._dn_by_cn(new_cn)
        new_rdn = new_dn.replace(self.baseDn, '').strip(',')
        self.ldap_c.modify_dn(
            dn=record.dn, relative_dn=new_rdn, delete_old_dn=True)

        return type(record)(self._get_record(new_dn))

    def delete_record(self, record):
        """
        Delete a recorod
        :param OcLdapRecord record: OcLdap or derived class for a record to delete
        """
        self.ldap_c.delete(dn=record.dn)

    def login_as_user(self, dn, password):
        """
        Try to authenticate as another user
        :param str dn: account DN
        :param str password: account password (plain text!)
        :return: record for a user just logged in, from server
        """
        self.ldap_c.user = dn
        self.ldap_c.password = password
        self.ldap_c.authentication = ldap3.SIMPLE
        self.ldap_c.bind()
        return self.ldap_c.extend.standard.who_am_i()

    def get_record(self, dn, rec_type=None):
        """
        Get a record by 'dn; from sever
        :param str dn: record DN to get
        :param rec_type: a class of record expected (OcLdapRecord or derived one), CLASS ITSELF, NOT AN INSTANCE OF IT
        """

        if not rec_type:
            return OcLdapRecord(ldap_record=self._get_record(dn))

        return rec_type(ldap_record=self._get_record(dn))

    def list_records(self, filterstr=None):
        """
        Return a list of DNs specified by filterstr
        :param str filterstr:  filter string
        """

        # reading by-page since list of records may be large
        # NOTE: default filter is set to something neutral, because search without a filter
        #       exhibits an error in 'ldap3.connection'
        _search_args = {
                "search_base": self.baseDn,
                "search_scope" : ldap3.SUBTREE,
                "search_filter" : "(objectClass=*)",
                "attributes" : None,
                "get_operational_attributes": False,
                "paged_size": 100}

        if filterstr:
            logging.debug("Search filter: %s" % filterstr)
            _search_args["search_filter"] = filterstr

        _initial = True
        _cookie = None
        rslt = list()

        while any([_initial, _cookie]):
            if _initial:
                self.ldap_c.search(**_search_args)
                _initial=False
            else:
                self.ldap_c.search(paged_cookie=_cookie, **_search_args)

            assert(self.ldap_c.result.get("result") == 0)

            records = list(map(lambda x: x.entry_dn, self.ldap_c.entries))
            rslt += list(filter(lambda x: x, records))
            _cookie = self.ldap_c.result

            for _attr in ['controls', '1.2.840.113556.1.4.319', 'value', 'cookie']:
                _cookie = _cookie.get(_attr)

                if not _cookie:
                    logging.debug('Cookie search failed at %s' % _attr)
                    break


        return rslt


class OcLdapRecord(object):
    """
    Common LDAP record class
    Any more specific class is to be derived from it
    """

    def __init__(self, ldap_record=None):
        """
        initialization
        :param dict ldap_record: a record from catalog
        """

        self._ldap_record_mod = deepcopy(ldap_record)
        self._ldap_record_orig = deepcopy(ldap_record)

        if not isinstance(self._ldap_record_mod, dict):
            self._ldap_record_mod = dict()
            self._ldap_record_mod['attributes'] = dict()

    def __cnv_to_str(self, cnv, allow_none=False):
        """
        Convert a value to string
        :param cnv: what to convert
        :return: string with converted value of cnv
        """
        if cnv is None:

            if allow_none:
                return None

            return ""

        if isinstance(cnv, bytes):
            cnv = cnv.decode('utf8')

        if not isinstance(cnv, str):
            cnv = str(cnv)

        return cnv

    def __search_attr(self, dict_t, attr):
        """
        Helper for case-insensitive search attribute in dict
        :param dict dict_t: dictionary
        :param str attr: attribute to search for
        :return: key from dict_t which lowercase version equals to lowercase version of attr
        """
        if not attr:
            return attr

        if 'attributes' not in dict_t.keys():
            raise ValueError("This record has no attributes")

        if isinstance(dict_t['attributes'], dict):
            keys = list(dict_t['attributes'].keys())
            keys = list(filter(lambda x: x.lower() == attr.lower(), keys))

            if keys:
                return keys.pop(0)

        return None

    def __attr_c(self, attr):
        """
        Search the attribute with case-neglection in dictioinaries
        :param str attr: attribute to search
        :return: attribute from a dictionary, or attr itself if no such attribute
        """
        if not attr:
            return attr

        # see in destination (modified) record
        ret = self.__search_attr(self._ldap_record_mod, attr)

        if ret:
            return ret

        # but perhaps this attribute is in source record only
        if not self.is_new:
            ret = self.__search_attr(self._ldap_record_orig, attr)

        if ret:
            return ret

        return attr

    def __str__(self):
        """
        Print the record itself
        """
        if not self._ldap_record_mod:
            return str(None)

        rslt = "dn:\t%s" % self.__get_dn()

        for attr in self._ldap_record_mod['attributes'].keys():
            ls_vals = self.attributes[attr]

            if not isinstance(ls_vals, list):
                ls_vals = [ls_vals]

            for value in ls_vals:
                rslt += "\n" + ":\t".join([attr, self.__cnv_to_str(value)])

        return rslt

    def set_attribute(self, attr_name, attr_value):
        """
        Set attribute to a value given.
        all attributes are to be a list of bytes, not strings
        names are strings
        encoding is assumed to be utf8
        :param str attr_name: attribute name
        :param attr_value: attribute value
        """

        if not attr_name:
            raise ValueError(
                "Incorrect attribute name: type '%s', value '%s'" % (type(attr_name), attr_name))

        attr_name = self.__attr_c(attr_name)

        if attr_value is not None: 
            self._ldap_record_mod['attributes'][attr_name] = attr_value
            return

        # we are asked to drop attribute
        if self._ldap_record_mod.get('attributes') and attr_name in self._ldap_record_mod['attributes'].keys():
            del (self._ldap_record_mod['attributes'][attr_name])


    def get_attribute(self, attr_name):
        """
        Get attribute value converted to strings.
        If attribute value is one only - return a string
        encoding is assumed to be utf8
        :param str attr_name: attribute name
        :param attr_value: attribute value
        :return: string value of an attribute, or list of strings in case of multiple values
        """
        if not attr_name:
            raise ValueError(
                "Incorrect attribute name: type '%s', value '%s'" % (type(attr_name), attr_name))

        if not self._ldap_record_mod or not self._ldap_record_mod.get('attributes'):
            return None

        attr_name = self.__attr_c(attr_name)

        result = self._ldap_record_mod['attributes'].get(attr_name)

        if not isinstance(result, list):
            return result

        if len(result) != 1:
            return result

        # do not do 'pop' since it modifies a list!
        return result[0]

    def append_attribute(self, attr_name, attr_value):
        """
        Append single value to an attribute
        :param str attr_name: attribute name
        :param attr_value: attribute value
        """

        # raises exception also if attribute is empty
        _attr_value = self.get_attribute(attr_name)

        if _attr_value is None:
            return self.set_attribute(attr_name, attr_value)

        if not isinstance(_attr_value, list):
            _attr_value = [_attr_value]

        if not isinstance(attr_value, list):
            attr_value = [attr_value]

        self.set_attribute(attr_name, list(set(attr_value + _attr_value)))

    def remove_attribute_value(self, attr_name, attr_value):
        """
        Remove single value from an attribute
        :param str attr_name: attribute name
        :param attr_value: attribute value
        """
        _attr_value = self.get_attribute(attr_name)

        if _attr_value is None:
            # do nothing
            return

        if isinstance(attr_value, str):
            attr_value = attr_value.lower()

        if not isinstance(_attr_value, list):
            if isinstance(_attr_value, str):
                _attr_value = _attr_value.lower()

            if _attr_value == attr_value:
                self.drop_attribute(attr_name)

            return

        _attr_value_t = list()

        for _val in _attr_value:
            # doing so ugly, without filtering by 'lambda', because:
            # 1. we need to save a case in target value, but comparison have to be case-insensitive
            # 2. value may be digit or binary, not a string only
            _val_t = _val.lower() if isinstance(_val, str) else _val

            if _val_t != attr_value:
                _attr_value_t.append(_val)

        if not _attr_value_t:
            # no values left, drop an attribute completely
            self.drop_attribute(attr_name)
            return

        self.set_attribute(attr_name, _attr_value_t)

    def drop_attribute(self, attr_name):
        """
        Drop attribute
        :param attr_name: attribute name
        :type attr_name: string
        """
        self.set_attribute(attr_name, None)

    def set_dn(self, dn):
        """
        Set new record DN
        :param dn: new DN
        :type dn: string
        """

        if not dn or not isinstance(dn, str):
            raise ValueError("invalid DN: type '%s', value '%s'" % (type(dn), dn))

        self._ldap_record_mod['dn'] = dn

    @property
    def dn(self):
        """
        return DN
        """
        return self.__get_dn()

    def __get_dn(self):
        """
        Helper to get a DN
        """

        if not self._ldap_record_orig or not self._ldap_record_mod: 
            return None

        return self._ldap_record_mod.get('dn')

    @property
    def attributes(self):
        """
        Get a full copy of attributes dictionary
        """
        return deepcopy(self._ldap_record_mod['attributes'])

    @property
    def is_new(self):
        """
        Return a new flag
        """
        return (self._ldap_record_orig is None) or not self.__get_dn()

    @property
    def modifications(self):
        """
        Get modification list for 'modify' ldap operation.
        """
        if self.is_new:
            raise Exception(
                'New record modification is not available, please create it first')

        result = dict()

        if self._ldap_record_orig == self._ldap_record_mod:
            return result

        # first check for deletion and modification
        for attr in self._ldap_record_orig['attributes'].keys():
            # do not search upper-lower-case version of attribute name
            # since it is fixed in set_attribute function

            if attr not in self._ldap_record_mod['attributes'].keys():
                result[attr] = [(ldap3.MODIFY_DELETE, [])]
                logging.debug('Attribute delete: %s' % attr)
                continue

            if self._ldap_record_orig['attributes'][attr] == self._ldap_record_mod['attributes'][attr]:
                logging.debug('Attribute no change: %s' % attr)
                continue

            logging.debug('Attribute replace: %s' % attr)
            result[attr] = [
                (ldap3.MODIFY_REPLACE, self._ldap_record_mod['attributes'][attr])]

        # then check for adding
        for attr in self._ldap_record_mod['attributes'].keys():
            # do not search upper-lower-case version of attribute name
            # since it is fixed in set_attribute function

            if attr in self._ldap_record_orig['attributes'].keys():
                continue

            logging.debug('Attribute add: %s' % attr)
            result[attr] = [
                (ldap3.MODIFY_ADD, self._ldap_record_mod['attributes'][attr])]

        return result
