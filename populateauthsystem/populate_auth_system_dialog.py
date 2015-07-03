# -*- coding: utf-8 -*-
"""
/***************************************************************************
 PopulateAuthSystemDialog

 Plugin dialog to populate the authentication database
                             -------------------
        begin                : 2015-06-18
        git sha              : $Format:%H$
        copyright            : (C) 2014-15 by
                               Larry Shaffer/Boundless Spatial Inc.
        email                : lshaffer@boundlessgeo.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
"""

import os

from qgis.core import *
from qgis.gui import *
from qgis.utils import *

from PyQt4 import uic
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

from qgis_auth_system import AuthSystem
import resources_rc

FORM_CLASS, _ = uic.loadUiType(os.path.join(
    os.path.dirname(__file__), 'populate_auth_system_dialog.ui'))


class PopulateBasicDialog(QDialog):

    def __init__(self, parent=None,
                 flags=Qt.Dialog, buttons=QDialogButtonBox.Close):
        QDialog.__init__(self, parent, flags)

        dlg_layout = QVBoxLayout()
        self.layout = QVBoxLayout()
        self.layout.setSpacing(12)
        dlg_layout.addItem(self.layout)

        self.buttonbox = QDialogButtonBox(buttons, Qt.Horizontal, self)
        self.buttonbox.accepted.connect(self.accept)
        self.buttonbox.rejected.connect(self.reject)
        dlg_layout.addWidget(self.buttonbox)

        self.setLayout(dlg_layout)


class PkiPasswordDialog(PopulateBasicDialog):

    def __init__(self, parent=None, message=None):
        PopulateBasicDialog.__init__(
            self, parent=parent,
            buttons=QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        if message is not None:
            lblmsg = QLabel(message, self)
            self.layout.addWidget(lblmsg)

        hlayout = QHBoxLayout()
        hlayout.setSpacing(8)
        self.le_pass = QLineEdit(self)
        self.le_pass.setEchoMode(QLineEdit.Password)
        hlayout.addWidget(self.le_pass)
        self.chk_show = QCheckBox(self.tr('Show'), self)
        hlayout.addWidget(self.chk_show)
        self.layout.addLayout(hlayout)

        self.chk_show.stateChanged[int].connect(self.show_statechanged)

    def show_statechanged(self, state):
        self.le_pass.setEchoMode(
            QLineEdit.Normal if state > 0 else QLineEdit.Password)

    def password(self):
        return self.le_pass.text()


class PkiIdentitySelectDialog(PopulateBasicDialog):

    def __init__(self, parent=None,
                 idents1=None, idents1msg='',
                 idents2=None, idents2msg=''):
        PopulateBasicDialog.__init__(
            self, parent=parent,
            buttons=QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        self.idents1 = idents1
        self.idents2 = idents2

        self.ident1_cmbbx = self.identities_selector(idents1)
        self.ident2_cmbbx = self.identities_selector(idents2)

        if idents1 is not None:
            if idents1msg:
                lbl1msg = QLabel(idents1msg, self)
                self.layout.addWidget(lbl1msg)
            self.layout.addWidget(self.ident1_cmbbx)

        if idents2 is not None:
            if idents2msg:
                lbl2msg = QLabel(idents2msg, self)
                self.layout.addWidget(lbl2msg)
            self.layout.addWidget(self.ident2_cmbbx)

    def ident1_id(self):
        if self.idents1 is None:
            return ''
        return self.ident1_cmbbx.itemData(self.ident1_cmbbx.currentIndex())

    def ident2_id(self):
        if self.idents2 is None:
            return ''
        return self.ident2_cmbbx.itemData(self.ident2_cmbbx.currentIndex())

    def identities_selector(self, identities):
        """
        :type identities: list[QSslCertificate]
        :rtype: QComboBox
        """
        cmbbx = QComboBox(self)
        cmbbx.setIconSize(QSize(26, 22))
        if identities is None:
            return cmbbx
        for cert in identities:
            org = cert.subjectInfo(QSslCertificate.Organization)
            if not org:
                org = "Organization not defined"
            # noinspection PyCallByClass,PyTypeChecker,PyArgumentList
            txt = "{0} ({1})".format(QgsAuthCertUtils.resolvedCertName(cert),
                                     org)
            # noinspection PyCallByClass,PyTypeChecker,PyArgumentList
            sha = QgsAuthCertUtils.shaHexForCert(cert)
            cmbbx.addItem(
                QIcon(':/plugins/populateauthsystem/icon.png'),
                txt, sha)
        return cmbbx


class PopulateAuthSystemDialog(QDialog, FORM_CLASS):

    def __init__(self, parent=None, qgis_iface=None, title=None, init_run=True):
        """Constructor."""
        super(PopulateAuthSystemDialog, self).__init__(parent)
        self.iface = qgis_iface
        self.init_run_type = init_run
        self.replaced_identity_configs = []
        self.replacement_results = ''

        # Set up the user interface from Designer.
        # After setupUI you can access any designer object by doing
        # self.<objectname>, and you can use autoconnect slots - see
        # http://qt-project.org/doc/qt-4.8/designer-using-a-ui-file.html
        # #widgets-and-dialogs-with-auto-connect
        self.setupUi(self)
        self.msgbar = QgsMessageBar(self)
        self.frameMsgBar.layout().addWidget(self.msgbar)

        self.buttonBox.accepted.connect(self.ok_clicked)
        self.buttonBox.rejected.connect(self.reject)

        self.lblIcon.setPixmap(
            QPixmap(':/plugins/populateauthsystem/images/'
                    'certificate_trusted_48.png'))
        if title is not None:
            self.lblTitle.setText(title)
        self.short_title = self.tr("Populate Auth System")

        self.set_text(
            self.init_run_text() if init_run else self.manual_run_text())

        self.grpbxOptions.setHidden(self.init_run_type)

        self.chkReconfig.setEnabled(False)
        self.radioGroup.buttonClicked[int].connect(self.update_gui)

        self.resize(640, 500)

    def update_gui(self):
        self.chkReconfig.setEnabled(self.radioEraseDb.isChecked())

    # noinspection PyMethodMayBeStatic
    def password_dlg(self, parent, message):
        """
        :return: A password dialog
        :rtype: QDialog
        """
        return PkiPasswordDialog(parent, message)

    def auth_sys(self):
        """
        :return: An instance of the AuthSystem interface for populating
        :rtype: AuthSystem
        """
        return AuthSystem(parent=self, in_plugin=True,
                          qgis_iface=self.iface, messagebar=self.msgbar)

    def ok_clicked(self):
        self.init_run() if self.init_run_type else self.manual_run()

    def init_run(self):
        """
        Semi-automated pre-population with minimal user interaction, but only at
        end of app launch, not after (like when loading via Plugin Manager).
        """
        authsys = self.auth_sys()

        if not os.path.exists(authsys.PKI_DIR):
            self.msgbar.pushWarning(
                self.short_title,
                "Pre-configured PKI directory was not found")

        identities = [os.path.exists(os.path.join(authsys.PKI_DIR, i))
                      for i in authsys.PKCS_FILES]
        if not any(identities):
            self.msgbar.pushWarning(
                self.short_title,
                "No PKI identities found")

        if not authsys.master_pass_set():
            return

        if not authsys.populate_ca_certs(from_filesys=True):
            self.msgbar.pushWarning(
                self.short_title,
                "Incomplete populating of CA certs")
            return  # so PKI_DIR is not deleted
        if not authsys.populate_identities(
                from_filesys=True, password_dlg_func=self.password_dlg):
            self.msgbar.pushWarning(
                self.short_title,
                "Incomplete populating of identities")
            return  # so PKI_DIR is not deleted

        # these can fail (user notified), but should not stop population
        if (authsys.ADD_OWS_CONNECTIONS
                and not authsys.config_ows_connections(from_filesys=True)):
            self.msgbar.pushWarning(
                self.short_title,
                "Incomplete populating of OWS connections")
        if (authsys.ADD_SSL_SERVERS
                and not authsys.populate_servers(from_filesys=True)):
            self.msgbar.pushWarning(
                self.short_title,
                "Incomplete populating of SSL server configs")

        if authsys.DELETE_PKI_DIR:
            shutil.rmtree(authsys.PKI_DIR, ignore_errors=True)

        self.show_results(authsys.population_results())

        self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(False)

    def manual_run(self):
        """
        Manual population with full user interaction.
        """
        authsys = self.auth_sys()

        if not authsys.master_pass_set():
            return

        cur_identities = []
        if self.radioReplaceIdent.isChecked():
            # noinspection PyArgumentList
            cur_identities = QgsAuthManager.instance().getCertIdentities()
        elif self.radioEraseDb.isChecked():
            backup = None
            # noinspection PyArgumentList
            erase, backup = \
                QgsAuthManager.instance().eraseAuthenticationDatabase(True,
                                                                      backup)
            if not erase:
                if not backup:
                    self.msgbar.pushWarning(
                        self.short_title,
                        "Could not backup database")
                else:
                    self.msgbar.pushWarning(
                        self.short_title,
                        "Could not erase database")
                return
            else:
                self.msgbar.pushInfo(
                    self.short_title,
                    "Database backed up to {0}".format(backup))

        if self.chkExtraCaFile.isChecked() and not authsys.populate_ca_certs():
            self.msgbar.pushWarning(
                self.short_title,
                "Incomplete populating of CA certs")
            return

        if not authsys.populate_identities(password_dlg_func=self.password_dlg):
            self.msgbar.pushWarning(
                self.short_title,
                "Incomplete populating of identities")
            return

        identity_ids = authsys.identity_configs.keys()

        if self.radioReplaceIdent.isChecked():
            new_identities = []
            for ident_id in identity_ids:
                # noinspection PyArgumentList
                identity = QgsAuthManager.instance().getCertIdentity(ident_id)
                if not identity.isNull():
                    new_identities.append(identity)

            if cur_identities and new_identities:
                new_msg = "Imported identity to replace existing:"
                cur_msg = "Existing identity to replace:"
                dlg = PkiIdentitySelectDialog(self, new_identities, new_msg,
                                              cur_identities, cur_msg)
                if dlg.exec_():
                    new_id = dlg.ident1_id()
                    old_id = dlg.ident2_id()
                    if old_id and new_id:
                        self.replace_identity_in_authcfg(old_id, new_id)
                    if self.replaced_identity_configs:
                        # noinspection PyArgumentList
                        new_ident = \
                            QgsAuthManager.instance().getCertIdentity(new_id)
                        """:type: QSslCertificate"""
                        # noinspection PyArgumentList,PyCallByClass
                        # noinspection PyTypeChecker
                        new_name = QgsAuthCertUtils.resolvedCertName(new_ident)
                        res = "Auth configs updated:\n"
                        for cfg in self.replaced_identity_configs:
                            res += ("  '{0}' replaced with '{1}' identity\n"
                                    .format(cfg, new_name))
                        res += "\n\n"
                        self.replacement_results = res
                else:
                    self.msgbar.pushInfo(
                        self.short_title,
                        "Identity replacement cancelled")
            else:
                self.msgbar.pushInfo(
                    self.short_title,
                    "No identities found for replacement")

        elif self.radioEraseDb.isChecked():
            if self.chkReconfig:
                msg = "Imported identity to use in reconfiguring:"
                # noinspection PyArgumentList
                dlg = PkiIdentitySelectDialog(
                    self, QgsAuthManager.instance().getCertIdentities(), msg)
                if dlg.exec_() and dlg.ident1_id():
                    ident_cfg = authsys.identity_configs[dlg.ident1_id()]
                    # can fail (user notified); should not stop population
                    if not authsys.config_ows_connections(authcfg=ident_cfg):
                        self.msgbar.pushWarning(
                            self.short_title,
                            "Incomplete populating of OWS connections")

            self.msgbar.pushCritical(
                self.short_title,
                "RESTART QGIS (active authentication database has been erased)")

        self.show_results(authsys.population_results())

        self.grpbxOptions.setHidden(True)
        self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(False)

    # noinspection PyArgumentList
    def replace_identity_in_authcfg(self, old_id, new_id):
        identcfgs = []
        """:type: list[QgsAuthConfigIdentityCert]"""
        for configid in QgsAuthManager.instance().configIds():
            if (QgsAuthManager.instance().configProviderType(configid) ==
                    QgsAuthType.IdentityCert):
                cfg = QgsAuthConfigIdentityCert()
                if QgsAuthManager.instance().loadAuthenticationConfig(
                        configid, cfg, True):
                    identcfgs.append(cfg)
                else:
                    self.msgbar.pushWarning(
                        self.short_title,
                        "Could not load identity auth config to replace")
                    return  # don't continue, even if just one fails

        for identcfg in identcfgs:
            if identcfg.certId() != old_id:
                continue
            identcfg.setCertId(new_id)
            if not QgsAuthManager.instance().updateAuthenticationConfig(
                    identcfg):
                self.msgbar.pushWarning(
                    self.short_title,
                    "Could not update identity auth config being replaced")
                return  # don't continue, even if just one fails
            else:
                self.replaced_identity_configs.append(identcfg.name())

    def set_text(self, text):
        self.teDescription.setPlainText(text)

    def plugin_title(self):
        return self.lblTitle.text()

    @staticmethod
    def init_run_text():
        return (
            "Continue with semi-automated population of authentication"
            " database?\n\n"
            "(You will need to enter a master password and any password for PKI"
            " components)"
        )

    def manual_run_text(self):
        # TODO: add description of options in GUI
        return(
            "Continue with workflow to import identities and set up the"
            " authentication database?\n\n"
            "(You will need to enter a master password and any password for PKI"
            " components)\n\n"
            "You can run '{0}' from the Plugins menu later, at any time."
            .format(self.plugin_title())
        )

    def show_results(self, res=""):
        msg = self.tr("No authentication database changes were made.\n\n"
                      "It could be that the components you were trying to"
                      " import already exist in the database.")
        if self.replacement_results:
            res += self.replacement_results
        if res != "":
            msg = "{0}\n\n{1}".format(
                self.tr("Authentication database changes were made..."), res)
        self.set_text(msg)
