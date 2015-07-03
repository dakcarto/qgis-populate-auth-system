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


class PopulateAuthSystemDialog(QDialog, FORM_CLASS):

    def __init__(self, parent=None, qgis_iface=None, title=None, init_run=True):
        """Constructor."""
        super(PopulateAuthSystemDialog, self).__init__(parent)
        self.iface = qgis_iface
        self.init_run_type = init_run

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

        self.resize(640, 420)

    # noinspection PyMethodMayBeStatic
    def password_dlg(self, parent, message):
        """
        :return: A password dialog
        :rtype: QDialog
        """
        return PkiPasswordDialog(parent, message)

    def ok_clicked(self):
        self.init_run() if self.init_run_type else self.manual_run()

    def init_run(self):
        """
        Semi-automated pre-population with minimal user interaction, but only at
        end of app launch, not after (like when loading via Plugin Manager).
        """
        # Initialize the auth system module
        authsys = AuthSystem(qgis_iface=self.iface, messagebar=self.msgbar)

        if os.path.exists(authsys.PKI_DIR) and authsys.master_pass_set():

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
        else:
            self.msgbar.pushWarning(
                self.short_title,
                "Pre-configured PKI directory was not found")

        self.buttonBox.button(QDialogButtonBox.Ok).setEnabled(False)

    def manual_run(self):
        pass

    def set_text(self, text):
        self.teDescription.setPlainText(text)

    def plugin_title(self):
        return self.lblTitle.text()

    @staticmethod
    def init_run_text():
        return (
            "Continue with workflow to import identities and set up the"
            " authentication database?\n\n"
            "(You will need to enter a master password and any password for PKI"
            " components)"
        )

    def manual_run_text(self):
        return(
            "Continue with semi-automated population of authentication"
            " database?\n\n"
            "(You will need to enter a master password and any password for PKI"
            " components)\n\n"
            "You can run '{0}' from the Plugins menu later, at any time."
            .format(self.plugin_title())
        )

    def show_results(self, res):
        if res == "":
            return
        msg = "{0}\n\n{1}".format(
            self.tr("Authentication database changes were made"), res)
        self.set_text(msg)
