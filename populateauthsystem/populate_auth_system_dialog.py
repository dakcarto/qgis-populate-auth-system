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

from PyQt4 import uic
from PyQt4.QtGui import QDialog, QPixmap

import resources_rc

FORM_CLASS, _ = uic.loadUiType(os.path.join(
    os.path.dirname(__file__), 'populate_auth_system_dialog.ui'))


class PopulateAuthSystemDialog(QDialog, FORM_CLASS):
    def __init__(self, title=None, parent=None):
        """Constructor."""
        super(PopulateAuthSystemDialog, self).__init__(parent)
        # Set up the user interface from Designer.
        # After setupUI you can access any designer object by doing
        # self.<objectname>, and you can use autoconnect slots - see
        # http://qt-project.org/doc/qt-4.8/designer-using-a-ui-file.html
        # #widgets-and-dialogs-with-auto-connect
        self.setupUi(self)
        if title is not None:
            self.lblTitle.setText(title)
        self.lblIcon.setPixmap(
            QPixmap(':/plugins/populateauthsystem/images/'
                    'certificate_trusted_48.png'))
        self.teDescription.setText("""
<html><head/><body>
    <p>Continue with workflow to import identities and set up the
       authentication database?</p>
   <p>(You will need to enter a master password and any password for PKI
      components)</p>
</body></html>
    """)
        self.resize(500, 400)
