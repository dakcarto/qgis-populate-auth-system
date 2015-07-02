# -*- coding: utf-8 -*-
"""
/***************************************************************************
 PopulateAuthSystem
                                 A QGIS plugin
 Plugin to populate the authentication database
                             -------------------
        begin                : 2015-06-15
        copyright            : (C) 2015 by Larry Shaffer/Boundless Spatial Inc.
        email                : lshaffer@boundlessgeo.com
        git sha              : $Format:%H$
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
 This script initializes the plugin, making it known to QGIS.
"""


# noinspection PyPep8Naming
def classFactory(iface):  # pylint: disable=invalid-name
    """Load PopulateAuthSystem class from file PopulateAuthSystem.

    :param iface: A QGIS interface instance.
    :type iface: QgsInterface
    """
    #
    from .populate_auth_system import PopulateAuthSystem
    return PopulateAuthSystem(iface)
