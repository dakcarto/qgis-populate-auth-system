Pre-population of Authentication Configurations
===============================================

Contents of directory
---------------------

- populate_qgis_creds.py. Python script that will work for the current user,
  with a known password, and generate an initial qgis-auth.db file, or use an
  existing one, for their QGIS install, which will be pre-populated with
  configurations to known network resources, using existing PKI credentials,
  which may be passphrase-protected.

  IMPORTANT: the script needs adjusted, or rewritten, relative to the desired
  result and the existing authentication requirements for the network or user.

- populate_qgis_creds_mac.sh. Wrapper shell script for setting appropriate
  environment variables for Mac OS X, then running `populate_qgis_creds.py`.

- populate_qgis_creds_win.bat. Wrapper shell script for setting appropriate
  environment variables for Windows OS (64-bit), then running
  `populate_qgis_creds.py`.

- populate_qgis_creds_user.py. Python script that will *interact* with the
  current user, asking for a master authentication password, and generate an
  initial qgis-auth.db file, or use an existing one, for their QGIS install,
  which will be pre-populated with configurations to known network resources,
  using existing PKI credentials, which may be passphrase-protected.

  IMPORTANT: the script needs adjusted, or rewritten, relative to the desired
  result and the existing authentication requirements for the network or user.

- populate_qgis_creds_user.png. Compilation PNG of sample dialogs the user will
  see when using `populate_qgis_creds_user.py`.

- populate_qgis_creds_mac_user-[app|script].sh. Wrapper shell script for
  `populate_qgis_creds_user.py` for setting appropriate environment variables
  for Mac OS X, then either launching QGIS and executing script within it, or
  executing script directly with standalone, background QGIS.

- populate_qgis_creds_win_user-[app|script].bat. Wrapper shell script for
  `populate_qgis_creds_user.py` for setting appropriate environment variables
  for Windows OS (64-bit), then either launching QGIS and executing script
  within it, or executing script directly with standalone, background QGIS.

- pki_sample_data. Same test data as for QGIS core PKI integration.

- README.txt. This file.

- test_qgsauthsystem_api-sample.py. The current Python-based unit test from QGIS
  that provides code examples for using the API to the QgsAuthManger class.
  Note: this file is for reference only, in case you wish to extend the
  populate_qgis_creds.py script, and it should not be run.

Script Usage
------------

Whether on Mac or Windows, please open and review the Python and wrapper scripts
to ensure the set environment variables and script configuration match those of
your Boundless QGIS installation.

populate_qgis_creds.py
......................

This is example output from running script on Mac. Similar results will be
displayed on Windows, though the `populate_qgis_creds_win.bat` wrapper will need
to be used from within a cmd.exe session.

Output from populate_qgis_creds.sh -h ::

  $ ./populate_qgis_creds_mac.sh -h
  usage: populate_qgis_creds.py [-h] [-u username] [-m master-password]
                                [-d directory-path]

  Script will work for current or defined user, with a defined password, and
  generate an initial qgis-auth.db file, or use an existing one, for user's QGIS
  install, which will be pre-populated with configurations to known network
  resources, using existing PKI credentials, which may be passphrase-protected.

  optional arguments:
    -h, --help            show this help message and exit
    -u username, --user username
                          QGIS user's name
    -m master-password, --masterpass master-password
                          QGIS user's master password
    -d directory-path, --pki-dir directory-path
                          User's PKI components directory path

Example ::

  $ ./populate_qgis_creds.sh -u user -m password
  Setting authentication config using:
    user: user
    master pass: password
    pkidir: /Users/user/PKI

  ...Possibly lots of application debug output...

  settings.fileName(): /Users/user/Library/Preferences/org.qgis.QGIS2.plist
  settings.organizationName(): qgis.org
  settings.applicationName(): QGIS2

The script has descriptions of how to customize it within the in-code comments.

populate_qgis_creds_user.py
...........................

Example commands for running script on Windows. On Mac the
`populate_qgis_creds_mac_user-[app|script].sh` wrapper should be used instead.

This script *requires* user interaction, since it uses Python bindings related
to some authentication system GUI elements of QGIS.

Run the appropriate .bat file directly from the file browser, by
double-clicking, relative to whether you want the dialogs that interact with the
user to be within the QGIS desktop GUI or standalone::

  populate_qgis_creds_win_user-app.bat
  - OR -
  populate_qgis_creds_win_user-script.bat

The script has descriptions of how to customize it within the in-code comments.

Accessing Windows Local Certificate Store
-----------------------------------------

By default QGIS works with the OpenSSL key stores. On Windows, you can try using
the `wincertstore` Python package to retrieve existing client certs, via OIDs
for enhanced key usages like CLIENT_AUTH, then export those to PEM or PKCS#12
format, IF such store entries are exportable.

See: https://pypi.python.org/pypi/wincertstore

Such support for accessing the local OS store will need to be added to the
script.

Scenarios of Pre-population of Configurations or Network Resources
------------------------------------------------------------------

The above script assumes it is intended to be run *just after* initial QGIS
installation, and before the user has launched QGIS. However, the script will
work if the user has already launched QGIS and initialized the authentication
system and its database. In such a case, the script will only work IF the user's
defined master password is known.

Another potential solution for pre-populating, once a user has been using QGIS
for some time, and the authentication database has many records and an unknown
master password: use a PyQGIS plugin, which when run, will prompt the user to
enter their master password via a call to QgsAuthManager.instance(), then pull
configuration settings from a local network query and install them into the
authentication database.
