LDAP extension for Roundup Issue Tracker
========================================

The extension provides authentication against an LDAP directory for Roundup
Issue Tracker. It uses the pure Python `ldap3` library to communicate over LDAP.

How It Works
------------

Authentication is performed using direct binding to the LDAP directory. User
properties stored in the database are not used for authentication and are always
created or updated according to information derived from the LDAP attributes.

Properties will be forced to update if present in the `user` class:

| Property              | Attribute                                |
| --------------------  | ---------------------------------------- |
| `address`             | `mail`                                   |
| `alternate_addresses` | `mail`, if multiple                      |
| `organization`        | `o`                                      |
| `phone`               | `telephoneNumber` or `mobile`            |
| `realname`            | `displayName`                            |
| `roles`               | `memberOf` or search result for `member` |

User passwords are not synchronized. During the user creation on the tracker, a
random password is generated. This way, user accounts are always protected, even
if LDAP authentication is disabled.

Group membership information can also be used for authorization if provided. In
this case, the `memberOf` attribute will be checked first. Group entries will
only be searched if the user entry does not contain this attribute.

The extension uses the advanced logging capabilities of the `ldap3` module. LDAP
message activation and detail levels can be set in the extension configuration.

Installation
------------

Install the `ldap3` Python module on your operating system, virtual environment,
or container, depending on how your tracker is installed. Save the extension and
configuration file in the `extensions` directory of your tracker home. Change
the configuration settings and then restart the tracker.

Testing
-------

You can also test the extension using your Roundup demo installation and the
FreeIPA demo server `ipa.demo1.freeipa.org`. This can be done using the
configuration file distributed in this repository, which already contains the
required values.

More information about the FreeIPA demo instance, including credentials, can be
found here: <https://www.freeipa.org/page/Demo>

To test secure connections, you also need to download the CA certificate from
<https://ipa.demo1.freeipa.org>, then edit the extension configuration and
specify the CA file path. Note that when using a relative path, the root
directory is `extensions` and not the tracker home.

Restrictions
------------

* This was not designed to work with complex LDAP trees
* Authentication against Active Directory is not supported
* SASL bindings are not implemented

Contributing
------------

If you would like to contribute to the project:

* Open pull request with improvements
* Discuss ideas in issues
* Spread the word
* Reach out with any feedback

License
-------

Distributed under the MIT License. See `LICENSE.txt` for more information.

Contact
-------

Anton Savchuk <mailto:a.savchuk@gmx.com>
