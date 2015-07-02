#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Populate QGIS authentication database with user config and (optionally)
generate OWS server configurations associated with it.

As it is coded, script will interact with the current user, asking for a master
authentication password, and pre-populate database with existing identity
credentials, which may be passphrase-protected, and optionally associate those
with OWS configurations.

NOTE: this script needs adjusted, or rewritten, relative to the desired result
and the existing authentication requirements for the network or user.

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


class AuthSystem:

    # Title used in user messages and dialog title bars
    TITLE = 'Authentication System'

    # For semi-automated population, change these for PKCS#12 and CAs files
    # Supported file type extensions are:
    #   PKCS#12 = .p12 or .pfx
    #   CAs file = .pem or .der
    # NOTE: any CA cert chains contained in any PKCS#12 file will also be added;
    #       however, CA certs with identical signatures will not be duplicated
    PKI_DIR = os.path.join(os.path.expanduser('~'), 'qgis-pki')
    # Pre-formatted file names of identities/CAs, located in PKI_DIR
    PKCS_FILES = ['identity1.p12', 'identity2.p12']  # OR '= None'
    # Extra Certifiate Authorities, if all CAs are not defined in PKCS file(s)
    CA_CERTS = 'ca.pem'  # OR  = None
    # File name of identity, whose auth config is applied to OWS configs
    PKCS_OWS = 'identity1.p12'  # OR  = None

    # Whether PKCS files are always password-protected (triggers a prompt to
    # the user for their PKCS password during semi-automated population), unless
    # PKCS_PASS is set.
    PKCS_PROTECTED = True

    # If using a standard password for temporary PKCS files, set it here.
    # NOTE: this is not a wise strategy
    PKCS_PASS = ''

    # Whether to delete the PKI_DIR after successful semi-automated population
    # NOTE: recommended to delete, or else the PKI components might be loaded at
    #       every launching of QGIS application (depending upon implementation).
    DELETE_PKI_DIR = False

    # Whether server configs should be added during semi-automated population.
    ADD_SERVERS = False

    def __init__(self, qgis_iface, messagebar=None):
        # note, this could be a mock iface implementation, as when testing
        self.iface = qgis_iface
        """:type : QgisInterface"""

        self.mw = None
        if self.iface is not None:
            self.mw = iface.mainWindow()
            """:type : QMainWindow"""

        self.in_plugin = True
        if self.mw is None:
            # we are running outside of a plugin
            self.in_plugin = False

        self.msgbar = None
        if self.in_plugin:
            if messagebar is not None:
                self.msgbar = messagebar
                """:type : QgsMessageBar"""
            else:
                self.msgbar = self.iface.messageBar()
                """:type : QgsMessageBar"""

        # Result caches
        # dictionary of identity cert sha and its related auth config ID:
        #   {'cert_sha': 'authcfg_id', ...}
        self.identity_configs = {}
        # string lists of results
        self.identities = []
        self.authconfigs = []
        self.authorities = []
        self.servers = []
        self.connections = []

    def clear_results(self):
        self.identity_configs = {}
        self.identities = []
        self.authconfigs = []
        self.authorities = []
        self.servers = []
        self.connections = []

    def msg(self, msg, kind='warn'):
        if kind == 'warn':
            if self.in_plugin:
                self.msgbar.pushWarning(self.TITLE, msg)
            else:
                # noinspection PyTypeChecker,PyArgumentList,PyCallByClass
                QMessageBox.warning(self.mw, self.TITLE, msg)
        elif kind == 'info':
            if self.in_plugin:
                self.msgbar.pushInfo(self.TITLE, msg)
            else:
                # noinspection PyTypeChecker,PyArgumentList, PyCallByClass
                QMessageBox.information(self.mw, self.TITLE, msg)

    def master_pass_set(self):
        """
        Set master password or check master password is set.
        Asks user for authentication master password and stores it in
        qgis-auth.db. This also verifies the set password by comparing password
        against its derived hash stored in auth db.

        :return: bool Whether it is set or verifies
        """
        # noinspection PyArgumentList
        res = QgsAuthManager.instance().setMasterPassword(True)
        if not res:
            self.msg("Master password not defined or does not match existing. "
                     "Canceling operation.")
        return res

    def populate_identities(self, multiple=False, from_filesys=False):
        """
        Import certificate-based identities into authentication database.
        Any CA cert chains contained in any PKCS#12 file will also be added.

        :param from_filesys: bool Skip user interaction and load from filesystem
        :return: bool Whether operation was successful
        """
        if not self.master_pass_set():
            return False

        pkibundles = []
        if from_filesys and self.PKCS_FILES is not None:
            for pkcs_name in self.PKCS_FILES:
                pkcs_path = os.path.join(PKI_DIR, pkcs_name)
                if not os.path.exists(pkcs_path):
                    continue
                psswd = self.PKCS_PASS
                if self.PKCS_PROTECTED and self.PKCS_PASS != '':
                    psswd, ok = QInputDialog.getText(
                        mw,
                        "Client Certificate Key",
                        "'{0}' password:".format(pkcs_name), QLineEdit.Normal)
                    if not ok:
                        continue
                # noinspection PyCallByClass,PyTypeChecker
                bundle = QgsPkiBundle.fromPkcs12Paths(pkcs_path, psswd)
                if not bundle.isNull():
                    pkibundles.append(bundle)
                else:
                    self.msg("Could not load identity file, continuing ({0})"
                             .format(pkcs_name))
        else:
            def import_identity(parent):
                dlg = QgsAuthImportIdentityDialog(
                    QgsAuthImportIdentityDialog.CertIdentity, parent)
                dlg.setWindowModality(Qt.WindowModal)
                dlg.resize(400, 250)
                if dlg.exec_():
                    bndle = dlg.pkiBundleToImport()
                    if bndle.isNull():
                        self.msg("Could not load identity file")
                        return None, True
                    return bndle, True
                return None, False

            while True:
                pkibundle, imprt_res = import_identity(self.mw)
                if pkibundle is not None:
                    pkibundles.append(pkibundle)
                if multiple and imprt_res:
                    continue
                break

        if not pkibundles:
            return False

        # Now try to store identities in the database
        for bundle in pkibundles:
            bundle_cert = bundle.clientCert()
            bundle_key = bundle.clientKey()
            bundle_cert_sha = bundle.certId()
            bundle_ca_chain = bundle.caChain()

            # noinspection PyArgumentList
            if QgsAuthManager.instance().existsCertIdentity(bundle_cert_sha):
                continue

            # noinspection PyArgumentList
            if not QgsAuthManager.instance().\
                    storeCertIdentity(bundle_cert, bundle_key):
                self.msg("Could not store identity in auth database")
                return False

            # noinspection PyArgumentList
            subj_issu = "{0} (issued by: {1})".format(
                QgsAuthCertUtils.resolvedCertName(bundle_cert),
                QgsAuthCertUtils.resolvedCertName(bundle_cert, True)
            )
            self.identities.append(subj_issu)

            # Now try to assign the identity to an auth config
            # noinspection PyArgumentList
            config_name = 'Identity - {0}'.format(
                QgsAuthCertUtils.resolvedCertName())
            bundle_config = QgsAuthConfigIdentityCert()
            bundle_config.setName(config_name)
            bundle_config.setCertId(bundle_cert_sha)

            # noinspection PyArgumentList
            if not QgsAuthManager.instance().\
                    storeAuthenticationConfig(bundle_config):
                self.msg("Could not store bundle identity config")
                return False

            bundle_configid = bundle_config.id()
            if not bundle_configid:
                self.msg("Could not retrieve identity config id from database")
                return False

            self.authconfigs.append(config_name)

            self.identity_configs[bundle_cert_sha] = bundle_configid

            if bundle_ca_chain:  # this can fail (user is notified)
                self.populate_ca_certs(bundle_ca_chain)

            return True

    def populate_ca_certs(self, ca_certs=None, from_filesys=False):
        """
        Import Certificate Authorities into authentication database.
        Certs with identical signatures will not be duplicated.

        :param ca_certs: [QSslCertificate] Certs to add
        :param from_filesys: bool Skip user interaction and load from filesystem
        :return: bool Whether operation was successful
        """
        if not self.master_pass_set():
            return False

        if from_filesys and self.CA_CERTS is not None:
            ca_certs_path = os.path.join(PKI_DIR, self.CA_CERTS)
            if os.path.exists(ca_certs_path):
                # noinspection PyArgumentList,PyTypeChecker,PyCallByClass
                ca_certs = QgsAuthCertUtils.certsFromFile(ca_certs_path)
        elif ca_certs is None:
            dlg = QgsAuthImportCertDialog(self.mw,
                                          QgsAuthImportCertDialog.CaFilter,
                                          QgsAuthImportCertDialog.FileInput)
            dlg.setWindowModality(Qt.WindowModal)
            dlg.resize(400, 250)
            if dlg.exec_():
                ca_certs = dlg.certificatesToImport()

        if ca_certs is not None:
            # noinspection PyArgumentList
            if not QgsAuthManager.instance().storeCertAuthorities(ca_certs):
                self.msg(
                    "Could not store Certificate Authorities in auth database")
                return False
            # noinspection PyArgumentList
            QgsAuthManager.instance().rebuildCaCertsCache()
            # noinspection PyArgumentList
            QgsAuthManager.instance().rebuildTrustedCaCertsCache()

            for ca_cert in ca_certs:
                # noinspection PyArgumentList
                subj_issu = "{0} ({1})".format(
                    QgsAuthCertUtils.resolvedCertName(ca_cert),
                    QgsAuthCertUtils.resolvedCertName(ca_cert, True)
                )
                self.authorities.append(subj_issu)

        return True

    def populate_servers(self):
        """

        :return: bool Whether operation was successful
        """
        if not self.master_pass_set():
            return False

    def config_ows_connections(self):
        """
        If the user does not have the OWS connection(s) that this auth config is
        meant to connect to, define now.

        NOTE: this assumes the individual connections do not already exist.
        If the connection settings do exist, this will OVERWRITE them.

        :return: bool Whether operation was successful
        """
        if not self.identity_configs:
            return False

        settings = QSettings()  # get application's settings object

        qDebug('settings.fileName(): {0}'.format(settings.fileName()))
        qDebug('settings.organizationName(): {0}'
               .format(settings.organizationName()))
        qDebug('settings.applicationName(): {0}'
               .format(settings.applicationName()))

        self.connections = []

        # WMS
        connkind = 'WMS'
        connname = 'My {0} SSL Server'.format(connkind)
        self.connections.append(connname)
        credskey = '/Qgis/{0}/{1}'.format(connkind, connname)
        connkey = '/Qgis/connections-{0}/{1}'.format(connkind.lower(), connname)

        settings.setValue(credskey + '/authid',
                          configid)  # link to auth config
        settings.setValue(credskey + '/username', '')  # deprecated; use config
        settings.setValue(credskey + '/password', '')  # deprecated; use config

        settings.setValue(connkey + '/url',
                          'https://localhost:8443/geoserver/wms')

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
        self.connections.append(connname)
        credskey = '/Qgis/{0}/{1}'.format(connkind, connname)
        connkey = '/Qgis/connections-{0}/{1}'.format(connkind.lower(), connname)

        settings.setValue(credskey + '/authid',
                          configid)  # link to auth config
        settings.setValue(credskey + '/username', '')  # deprecated; use config
        settings.setValue(credskey + '/password', '')  # deprecated; use config

        settings.setValue(connkey + '/url',
                          'https://localhost:8443/geoserver/wcs')

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
        self.connections.append(connname)
        credskey = '/Qgis/{0}/{1}'.format(connkind, connname)
        connkey = '/Qgis/connections-{0}/{1}'.format(connkind.lower(), connname)

        settings.setValue(credskey + '/authid',
                          configid)  # link to auth config
        settings.setValue(credskey + '/username', '')  # deprecated; use config
        settings.setValue(credskey + '/password', '')  # deprecated; use config

        settings.setValue(connkey + '/url',
                          'https://localhost:8443/geoserver/wfs')

        # Optional settings for WFS (these are the defaults)
        settings.setValue(connkey + '/referer', '')

        return True

    def population_results(self):
        res = ""
        if self.identities:
            res += "Personal identities imported:\n{0}".format(
                "\n".join(["  " + i for i in self.identities]))
        if self.authconfigs:
            res += "Authentication configurations created:\n{0}".format(
                "\n".join(["  " + a for a in self.authconfigs]))
        if self.authorities:
            res += "Certificate Authorities imported:\n{0}".format(
                "\n".join(["  " + a for a in self.authorities]))
        if self.servers:
            res += "SSL server configs created:\n{0}".format(
                "\n".join(["  " + s for s in self.servers]))
        if self.connections:
            res += "OWS connection configs created:\n{0}".format(
                "\n".join(["  " + c for c in self.connections]))

        return res

def main():
    # first store the CA(s) in database

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

        # The auth config has been given a unique ID from the auth system when
        # it was stored; retrieve it, so it can be linked to server config(s).
        configid = aw.configId()
        if configid is None or configid == "":
            msgbox("No configuration defined. Canceling script.")
            return


    msgbox("The authentication configuration was saved and has been assigned "
           "to the following server configurations:\n\n{0}"
           .format("\n".join(connections)),
           kind='info')
