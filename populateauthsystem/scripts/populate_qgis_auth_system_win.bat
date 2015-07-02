@echo off
set OSGEO4W_ROOT=C:\progra~2\Boundless\QGIS\qgis
call "%OSGEO4W_ROOT%"\bin\o4w_env.bat
call "%OSGEO4W_ROOT%"\apps\grass\grass-6.4.3\etc\env.bat
@echo off
path %OSGEO4W_ROOT%\apps\qgis\bin;%OSGEO4W_ROOT%\apps\grass\grass-6.4.3\lib;%PATH%
set PYTHONPATH=%OSGEO4W_ROOT%\apps\qgis\python;%PYTHONPATH%
set QGIS_PREFIX_PATH=%OSGEO4W_ROOT:\=/%/apps/qgis
set GDAL_FILENAME_IS_UTF8=YES
rem Set VSI cache to be used as buffer, see #6448
set VSI_CACHE=TRUE
set VSI_CACHE_SIZE=1000000

cmd /k python.exe "%~dp0\populate_qgis_creds.py" %*
