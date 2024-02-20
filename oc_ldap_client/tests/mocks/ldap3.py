import ldap3
import os
from .randomizer import Randomizer

class MockLdapConnection(ldap3.Connection):
    def __init__(self, **kwargs):

        if not isinstance(kwargs['server'], ldap3.Server):
            raise TypeError('Server argument invalid')

        if kwargs['version'] != 3:
            raise ValueError('Version wrong')

        if kwargs['authentication'] not in [ldap3.SASL, ldap3.SIMPLE, ldap3.ANONYMOUS]:
            raise ValueError('Authentication wrong')

        ## SASL-specific check:
        if kwargs['authentication'] == ldap3.SASL and kwargs['sasl_mechanism'] != 'EXTERNAL':
                raise ValueError("SASL mechanism is wrong")

        if kwargs.get('sasl_credentials'):
            raise ValueError('SASL credentials is not necessary for external mechanism')

        # SIMPLE-specific check
        if kwargs['authentication'] == ldap3.SIMPLE:
            for __arg in ['user', 'password']:
                if not kwargs.get(__arg):
                    raise ValueError("Mandatory for SIMPLE authentication: [%s]" % __arg)

        # ANONYMOUS-specific checks
        if kwargs['authentication'] == ldap3.ANONYMOUS:
            for __arg in ['user', 'password', 'sasl_mechanism']:
                if kwargs.get(__arg):
                    raise ValueError("Have to be unset for ANONYMOUS: [%s]" % __arg)

        # replace Server with some fake values
        super().__init__ (
                client_strategy=ldap3.MOCK_SYNC, 
                server=ldap3.Server('localhost'),
                user='cn=LDAP Admin,ou=TechUsers,ou=TestUnit,dc=some,dc=test,dc=domain,dc=local',
                password=Randomizer().random_str(10))

        # now set our connection with some test data
        self.__init_data()

    def __init_data(self):
        # add administrator account
        self.strategy.add_entry(self.user, 
                {   'userPassword' : self.password, 
                    "memberOf": ["cn=LDAP Admins,dc=some,dc=test,dc=domain,dc=local"]})

        # add test data
        self_path = os.path.dirname(os.path.abspath(__file__))
        ldap_path = os.path.join(self_path, 'ldap_data')

        for (root, lsdirs, lsfiles) in os.walk(ldap_path):
            for file_nm in lsfiles:
                if not file_nm.endswith('.json.txt'):
                    continue

                file_pth = os.path.join(root, file_nm)
                self.strategy.entries_from_json(file_pth)

    # we are using mocketized LDAP, so tls is not needed
    def start_tls(self):
        self.tls_started = True
        return
