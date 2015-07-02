#!/bin/bash

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd -P)

### First Set Up Environment ###

# For Boundless installations
BQGIS=/Applications/QGIS.app/Contents

export PATH=${BQGIS}/MacOS/bin:$PATH
export DYLD_VERSIONED_LIBRARY_PATH=${BQGIS}/MacOS/lib:${BQGIS}/PlugIns/qgis
export DYLD_FRAMEWORK_PATH=${BQGIS}/Frameworks:/System/Library/Frameworks
export QGIS_PREFIX_PATH=${BQGIS}/MacOS
export PYTHONPATH=${BQGIS}/Resources/python:/Library/Python/2.7/site-packages:$PYTHONPATH

# FIXME: below
# export GDAL_DRIVER_PATH=/usr/local/lib/gdalplugins
# export GRASS_PREFIX=/usr/local/opt/grass-64/grass-6.4.4
# export OSG_LIBRARY_PATH=/usr/local/lib/osgPlugins-3.2.0


# For development builds, based off of OSGeo4Mac: https://github.com/OSGeo/homebrew-osgeo4mac
#export PATH=/usr/local/bin:$PATH
#export DYLD_VERSIONED_LIBRARY_PATH=/Volumes/Scratch/qgis-boundless/output/lib:/Volumes/Scratch/qgis-boundless/PlugIns/qgis:/usr/local/opt/sqlite/lib:/usr/local/opt/libxml2/lib:/usr/local/lib
#export DYLD_FRAMEWORK_PATH=/usr/local/Frameworks:/System/Library/Frameworks
#export QGIS_PREFIX_PATH=/Users/larrys/QGIS/github.com/QGIS_APPS_boundless/QGIS.app/Contents/MacOS
#export PYTHONHOME=/usr/local/Frameworks/Python.framework/Versions/2.7
#export PYTHONPATH=/Volumes/Scratch/qgis-boundless/output/python/:/usr/local/lib/python2.7/site-packages:$PYTHONPATH
#export PYQGIS_STARTUP=/usr/local/opt/qgis-26/libexec/pyqgis_startup.py
#export GDAL_DRIVER_PATH=/usr/local/lib/gdalplugins
#export GRASS_PREFIX=/usr/local/opt/grass-64/grass-6.4.4
#export OSG_LIBRARY_PATH=/usr/local/lib/osgPlugins-3.2.0

### Then, Run Script ###
${SCRIPT_DIR}/populate_qgis_creds_user.py
