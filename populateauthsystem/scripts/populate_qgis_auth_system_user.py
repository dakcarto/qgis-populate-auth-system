#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Pre-populate QGIS authentication database with user config and (optionally)
generate OWS server configurations associated with it.

Script requires the follow environment variables to be set:
  PYTHONHOME <-- path to any custom Python Home
  PYTHONPATH <-- path to custom Python site-packages or QGIS python directory
  QGIS_PREFIX_PATH <-- path to QGIS install directory

NOTE: this script needs adjusted, or rewritten, relative to the desired result
and the existing authentication requirements for the network or user.

As it is coded, script will interact with the current user, asking for a master
authentication password, and generate an initial qgis-auth.db file, or use an
existing one, for their QGIS install, which will be pre-populated with
configurations to known network resources, using existing PKI credentials, which
may be passphrase-protected.

Some comments and syntax in this document are instructions to the PyCharm
Python IDE, e.g. # noinspection PyTypeChecker OR variable type definitions.

.. note:: This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
"""
__author__ = 'Larry Shaffer'
__date__ = '2015/06/15'
__copyright__ = 'Copyright 2014-5, Boundless Spatial, Inc.'
# This will get replaced with a git SHA1 when you do a git archive
__revision__ = '$Format:%H$'

import sys

from qgis.core import *
from qgis.gui import *
from qgis.utils import *

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

SCRIPT_TITLE = "PKI Setup Script"

PKI_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'certs-keys')
CA_CERTS = os.path.join(
    PKI_DIR,
    'subissuer-issuer-root-ca_issuer-2-root-2-ca_chains.pem')
CLIENT_CERT = os.path.join(PKI_DIR, 'tom-cert.pem')
CLIENT_KEY = os.path.join(PKI_DIR, 'tom-key_w-pass.pem')

print CLIENT_CERT
print CLIENT_KEY

def msgbox(msg, kind='warn'):
    if kind == 'warn':
        # noinspection PyTypeChecker,PyArgumentList
        QMessageBox.warning(None, SCRIPT_TITLE, msg)
    elif kind == 'info':
        # noinspection PyTypeChecker,PyArgumentList
        QMessageBox.information(None, SCRIPT_TITLE, msg)


def main():

    qgsapp = None
    """:type : QgsApplication"""
    mw = None
    """:type : QMainWindow"""

    if iface:
        # Running within QGIS, so we have reference to iface object
        mw = iface.mainWindow()
        mw.raise_()
        mw.activateWindow()
    else:
        # Instantiate standalone QGIS (no desktop GUI)
        qgsapp = QgsApplication(sys.argv, True)

        # These are for referencing the correct QSettings for the QGIS app
        # noinspection PyTypeChecker,PyArgumentList,PyCallByClass
        QCoreApplication.setOrganizationName('QGIS')
        # noinspection PyTypeChecker,PyArgumentList,PyCallByClass
        QCoreApplication.setOrganizationDomain('qgis.org')
        # noinspection PyTypeChecker,PyArgumentList,PyCallByClass
        QCoreApplication.setApplicationName('QGIS2')

        # Initialize QGIS
        qgsapp.initQgis()

    dlg = QgsDialog(mw)
    """:type: QgsDialog"""
    dlg.setMinimumSize(QSize(480, 480))
    dlg.setWindowTitle(SCRIPT_TITLE)
    txtedit = QTextEdit(dlg)
    txtedit.setReadOnly(True)
    txtedit.setText("""
<html><head/><body>
<h2>Define PKI Configuration</h2>
<p>Clicking OK will ask you to enter your current <strong>master password
   </strong> or a new one, if it has not been stored yet; then, take you to an
   authentication configuration dialog to define your PKI credentials.</p>
<p>The resultant configuration will be assigned to pre-defined OWS services
(WMS, WCS, WFS).</p>
</body></html>
    """)
    btnbx = dlg.buttonBox()
    """:type: QDialogButtonBox"""
    btnbx.addButton(QDialogButtonBox.Ok)
    dlglyout = dlg.layout()
    """:type: QLayout"""
    dlglyout.addWidget(txtedit)
    dlg.raise_()
    if not dlg.exec_():
        return

    # Initialize the auth system
    # noinspection PyArgumentList
    authm = QgsAuthManager.instance()

    # first store the CA(s) in database
    ca_certs = QgsAuthCertUtils.certsFromFile(CA_CERTS)
    authm.storeCertAuthorities(ca_certs)
    authm.rebuildCaCertsCache()
    authm.rebuildTrustedCaCertsCache()

    # noinspection PyUnusedLocal
    creds = None
    if qgsapp:
        # Do some inits that are done normally on QGIS desktop app's launch
        # Instantiate the QgsCredentials singleton dialog
        # noinspection PyUnusedLocal
        creds = QgsCredentialDialog()
        # Set up the authentication system
        authm.init()

    # Ask user for authentication master password and store it in qgis-auth.db.
    # This also verifies the set password by comparing password against its
    # derived hash stored in auth db.
    if not authm.setMasterPassword(True):
        msgbox("Master password is not defined or does not match existing. "
               "Canceling script.")
        return

    # Now that we have a master password set/stored, we can use it to
    # encrypt and store authentication configurations.

    # If we know the path to the user's PEM files, auto create it now
    if os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
        with open(CLIENT_KEY, 'r') as f:
            key_data = f.read()

        client_certs = QgsAuthCertUtils.certsFromFile(CLIENT_CERT)
        if not client_certs:
            msgbox("Client certificate key could not be read. Canceling script.")
            return
        client_cert = client_certs[0]
        cert_sha = QgsAuthCertUtils.shaHexForCert(client_cert)

        psswd, ok = QInputDialog.getText(mw, "Client Certificate Key",
                                       "Key password:", QLineEdit.Normal)
        if not ok:
            msgbox("No certificate key password defined. Canceling script.")
            return

        client_key = QSslKey(key_data, QSsl.Rsa, QSsl.Pem, QSsl.PrivateKey, psswd)

        if not authm.storeCertIdentity(client_cert, client_key):
            msgbox("Client certificate could not be stored. Canceling script.")
            return

        config = QgsAuthConfigIdentityCert()
        config.setName('My identity')
        config.setCertId(cert_sha)

        authm.storeAuthenticationConfig(config)
        configid = config.id()
        if configid is None or configid == "":
            msgbox("No configuration defined. Canceling script.")
            return
    else:
        # There are 4 configurations that can be stored (as of June 2015), and
        # examples of their initialization are in the unit tests for
        # QGIS-with-PKI source tree (test_qgsauthsystem_api-sample.py).

        # Get the user's defined authentication config
        aw = QgsAuthConfigWidget(mw)
        if not aw.exec_():
            msgbox("No configuration defined. Canceling script.")
            return

        # The auth config has been given a unique ID from the auth system when it
        # was stored; retrieve it, so it can be linked to custom server config(s).
        configid = aw.configId()
        if configid is None or configid == "":
            msgbox("No configuration defined. Canceling script.")
            return

    # If the user does not have the OWS connection(s) that this auth config is
    # meant to connect to, define now.
    # NOTE: this assumes the individual connections do not already exist. If the
    # connection settings do exist, this will OVERWRITE them.

    settings = QSettings()  # get application's settings object

    qDebug('settings.fileName(): {0}'.format(settings.fileName()))
    qDebug('settings.organizationName(): {0}'
           .format(settings.organizationName()))
    qDebug('settings.applicationName(): {0}'
           .format(settings.applicationName()))

    connections = []

    # WMS
    connkind = 'WMS'
    connname = 'My {0} SSL Server'.format(connkind)
    connections.append(connname)
    credskey = '/Qgis/{0}/{1}'.format(connkind, connname)
    connkey = '/Qgis/connections-{0}/{1}'.format(connkind.lower(), connname)

    settings.setValue(credskey + '/authid', configid)  # link to auth config
    settings.setValue(credskey + '/username', '')  # deprecated; use auth config
    settings.setValue(credskey + '/password', '')  # deprecated; use auth config

    settings.setValue(connkey + '/url', 'https://localhost:8443/geoserver/wms')

    # Optional settings for WMS (these are the defaults)
    # dpiMode: 0=Off, 1=QGIS, 2=UMN, 4=GeoServer, 7=All (default)
    settings.setValue(connkey + '/dpiMode', 7)
    settings.setValue(connkey + '/ignoreAxisOrientation', False)
    settings.setValue(connkey + '/ignoreGetFeatureInfoURI', False)
    settings.setValue(connkey + '/ignoreGetMapURI', False)
    settings.setValue(connkey + '/invertAxisOrientation', False)
    settings.setValue(connkey + '/referer', '')
    settings.setValue(connkey + '/smoothPixmapTransform', False)

    # WCS
    connkind = 'WCS'
    connname = 'My {0} SSL Server'.format(connkind)
    connections.append(connname)
    credskey = '/Qgis/{0}/{1}'.format(connkind, connname)
    connkey = '/Qgis/connections-{0}/{1}'.format(connkind.lower(), connname)

    settings.setValue(credskey + '/authid', configid)  # link to auth config
    settings.setValue(credskey + '/username', '')  # deprecated; use auth config
    settings.setValue(credskey + '/password', '')  # deprecated; use auth config

    settings.setValue(connkey + '/url', 'https://localhost:8443/geoserver/wcs')

    # Optional settings for WCS (these are the defaults)
    # dpiMode: 0=Off, 1=QGIS, 2=UMN, 4=GeoServer, 7=All (default)
    settings.setValue(connkey + '/dpiMode', 7)
    settings.setValue(connkey + '/ignoreAxisOrientation', False)
    settings.setValue(connkey + '/ignoreGetMapURI', False)
    settings.setValue(connkey + '/invertAxisOrientation', False)
    settings.setValue(connkey + '/referer', '')
    settings.setValue(connkey + '/smoothPixmapTransform', False)

    # WFS
    connkind = 'WFS'
    connname = 'My {0} SSL Server'.format(connkind)
    connections.append(connname)
    credskey = '/Qgis/{0}/{1}'.format(connkind, connname)
    connkey = '/Qgis/connections-{0}/{1}'.format(connkind.lower(), connname)

    settings.setValue(credskey + '/authid', configid)  # link to auth config
    settings.setValue(credskey + '/username', '')  # deprecated; use auth config
    settings.setValue(credskey + '/password', '')  # deprecated; use auth config

    settings.setValue(connkey + '/url', 'https://localhost:8443/geoserver/wfs')

    # Optional settings for WFS (these are the defaults)
    settings.setValue(connkey + '/referer', '')

    msgbox("The authentication configuration was saved and has been assigned "
           "to the following server configurations:\n\n{0}"
           .format("\n".join(connections)),
           kind='info')


if __name__ == '__main__':
    main()
