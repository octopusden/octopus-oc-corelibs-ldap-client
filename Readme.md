# Python client for OpenLDAP

This python library is designed for easy parsing of OpenLDAP objects spacially configured with two basic classes: users and groups.

## OpenLDAP autorization.

The only tehcnical user authorization way supported is *EXTERNAL SASL*
That is: technical user certificate, private key and *LDAP* server *CA SSL* certificates chain are to be provided.
Binding technical user with *DN* and *PASSWORD* is not supported.

Technical user is to be granted with respective permissions on server side.

## OpenLDAP secure connection

Connection without encryption (*TLS*) is not supported.
Currently TLS v1.2 and TLS v1.3 are supported only. See *TLS\_PROTOCOL\_MIN* in *ldap.conf* manual for details about calculating SSL/TLS version values.

## Record DN limitations:

The only template suported for creating records is: `cn=...,baseDn`
That is: `create_record` method takes `cn` argument and adds `baseDn` joined via comma.
Example: `cn=foo; baseDn='dc=foo,dc=bar,dc=local'` will create a record `dn=cn=foo,dc=foo,dc=bar,dc=local`.

## Record renaming limitations:

Leaving old record after renaming is not supported. It is purged always.

## Record encoding limitations:

All string attributes are to be in unicode (UTF-8).
Other encodings are not supported.

## Users-and-groups structure limitations:

User *objectClass* is hardcoded to *inetOrgPerson*.
Group *objectClass* is hardcoded to *groupOfUniqueNames*.
*memberOf* overlay is to be configured properly on server side for those two classes.
User name (*Login*) is hardcoded to *cn*.
Group name is hardcoded to *cn* also.
Lock attribute is *pwdAccountLockedTime* - has to be configured on server side.
