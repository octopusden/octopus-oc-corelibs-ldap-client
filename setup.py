from setuptools import setup

__version = "1.0.1"

spec = {
    "name": "oc_ldap_client",
    "version": __version,
    "license": "LGPLv2",
    "description": "Base classes for LDAP objects",
    "long_description": "",
    "long_description_content_type": "text/plain",
    "packages": ["oc_ldap_client"],
    "install_requires": [ 
        'ldap3',
        'fs',
        'urllib3'
      ],
    "python_requires": ">=3.6"
}

setup( **spec )
