# -*- coding: utf-8 -*-
"""
/***************************************************************************
 PopulateAuthSystem
                                 A QGIS plugin
 Plugin to populate the authentication database
                              -------------------
        begin                : 2014-10-31
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
import shutil

from qgis.core import QgsAuthManager
from qgis.gui import QgisInterface, QgsDialog, QgsMessageBar
from PyQt4.QtCore import QSettings, qVersion, QCoreApplication, qDebug, \
    QSize, Qt
from PyQt4.QtGui import QMainWindow, QAction, QIcon, QPlainTextEdit, \
    QDialogButtonBox, QMessageBox, QBoxLayout, QHBoxLayout, QLabel, \
    QSizePolicy, QPixmap
# Initialize Qt resources from resources_rc.py (compiled from resources.qrc)
import resources_rc
# Import the code for the dialog
from populate_auth_system_dialog import PopulateAuthSystemDialog
from qgis_auth_system import AuthSystem


class PopulateAuthSystem:
    """QGIS Plugin Implementation."""

    def __init__(self, iface):
        """Constructor.

        :param iface: An interface instance that will be passed to this class
            which provides the hook by which you can manipulate the QGIS
            application at run time.
        :type iface: QgsInterface
        """
        # Save reference to the QGIS interface
        self.iface = iface
        """:type : QgsInterface"""
        self.mw = iface.mainWindow()
        """:type : QMainWindow"""
        self.msgbar = self.iface.messageBar()
        """:type : QgsMessageBar"""

        # initialize plugin directory
        self.plugin_dir = os.path.dirname(__file__)

        # initialize locale
        locale = QSettings().value('locale/userLocale')[0:2]
        locale_path = os.path.join(
            self.plugin_dir,
            'i18n',
            'populateauthsystem_{}.qm'.format(locale))

        if os.path.exists(locale_path):
            self.translator = QTranslator()
            self.translator.load(locale_path)
            if qVersion() > '4.3.3':
                # noinspection PyArgumentList
                QCoreApplication.installTranslator(self.translator)

        # Declare instance attributes
        self.title = self.tr(u'Populate Authentication Database')
        self.action = None

        # Set up automated enacting of plugin at end of app launch
        self.iface.initializationCompleted.connect(self.app_initialized)

    # noinspection PyMethodMayBeStatic
    def tr(self, message):
        """Get the translation for a string using Qt translation API.

        We implement this ourselves since we do not inherit QObject.

        :param message: String for translation.
        :type message: str, QString

        :returns: Translated version of message.
        :rtype: QString
        """
        # noinspection PyTypeChecker,PyArgumentList,PyCallByClass
        return QCoreApplication.translate('populateauthsystem', message)

    # noinspection PyPep8Naming
    def initGui(self):
        """Create the menu entries and toolbar icons inside the QGIS GUI."""

        icon_path = ':/plugins/populateauthsystem/icon.png'
        icon = QIcon(icon_path)
        self.action = QAction(icon, self.tr(u'Run'),
                              self.iface.mainWindow())
        self.action.triggered.connect(self.run_gui)

        self.iface.addPluginToMenu(self.title, self.action)

    def unload(self):
        """Removes the plugin menu item and icon from QGIS GUI."""
        self.iface.removePluginMenu(self.title, self.action)

    def app_initialized(self):
        """
        Semi-automated pre-population with minimal user interaction, but only at
        end of app launch, not after (like when loading via Plugin Manager).
        """
        # Initialize the auth system module
        authsys = AuthSystem(qgis_iface=self.iface)
        # noinspection PyArgumentList
        if (not QgsAuthManager.instance().masterPasswordHashInDb()
                or not QgsAuthManager.instance().getCertIdentities()):

            msg = ("Continue with semi-automated population of"
                   " authentication database?\n\n"
                   "(You will need to enter a master password and "
                   "any password for PKI components)\n\n"
                   "You can run '{0}' from the Plugins menu later, at any time."
                   .format(self.title))
            dlg = self.dialog(
                msg, buttons=QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            dlg.resize(400, 320)

            if os.path.exists(authsys.PKI_DIR) and dlg.exec_():

                if not authsys.populate_ca_certs(from_filesys=True):
                    self.msgbar.pushWarning(
                        self.title, "Error populating CA certs")
                    return  # so PKI_DIR is not deleted
                if not authsys.populate_identities(from_filesys=True):
                    self.msgbar.pushWarning(
                        self.title, "Error populating identities")
                    return  # so PKI_DIR is not deleted

                # these can fail (user notified), but should not stop population
                if authsys.ADD_OWS_CONNECTIONS and \
                        not authsys.config_ows_connections(from_filesys=True):
                    self.msgbar.pushWarning(
                        self.title, "Error populating OWS connections")
                if authsys.ADD_SSL_SERVERS \
                        and not authsys.populate_servers(from_filesys=True):
                    self.msgbar.pushWarning(
                        self.title, "Error populating SSL server configs ")

                if authsys.DELETE_PKI_DIR:
                    shutil.rmtree(authsys.PKI_DIR, ignore_errors=True)

                self.show_results(authsys.population_results())

    def run_gui(self):
        """
        Pre-population with full user interaction.
        """
        # show the dialog
        # Create the dialog (after translation) and keep reference
        authdlg = PopulateAuthSystemDialog(self.title, self.mw)
        authdlg.show()
        # Run the dialog event loop
        result = authdlg.exec_()
        # See if OK was pressed
        if result:
            # Do something useful here - delete the line containing pass and
            # substitute with your code.
            pass

    def show_results(self, res):
        if res != "":
            msg = "{0}\n\n{1}".format(
                self.tr("Authentication database changes were made"), res)
            dlg = self.dialog(msg)
            dlg.resize(500, 480)
            dlg.exec_()

    def dialog(self, msg, buttons=QDialogButtonBox.Close):
        # noinspection PyArgumentList
        dlg = QgsDialog(self.mw, buttons=buttons)
        """:type: QgsDialog"""
        dlg.setMinimumSize(QSize(320, 320))
        # dlg.setWindowTitle(self.title)
        dlglyout = dlg.layout()
        """:type: QBoxLayout"""

        # icon and title
        hlayout = QHBoxLayout(dlg)
        hlayout.setSpacing(20)
        lblicon = QLabel(dlg)
        lblicon.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        lblicon.setPixmap(
            QPixmap(':/plugins/populateauthsystem/images/'
                    'certificate_trusted_48.png'))
        hlayout.addWidget(lblicon)
        lbltxt = QLabel(self.title, dlg)
        hlayout.addWidget(lbltxt)
        dlglyout.addLayout(hlayout)

        # text area
        txtedit = QPlainTextEdit(dlg)
        txtedit.setReadOnly(True)
        txtedit.setPlainText(msg)
        dlglyout.addWidget(txtedit)
        return dlg
