import fnmatch
import os
from optparse import make_option
from paver.easy import *
# this pulls in the sphinx target
from paver.doctools import html
from paver.setuputils import setup
import xmlrpclib
import zipfile


def base_excludes():
    return [
        '.DS_Store',  # on Mac
        '*.pyc',
        'pylintrc',
        'resources.qrc',
        'scripts'
    ]


def full_excludes():
    excl = base_excludes()
    excl.extend([
        'test',
        'test-output',
    ])
    return excl


setup(
    name="populateauthsystem",
    packages=['populateauthsystem'],
    version="0.1",
    url="http://boundlessgeo.com/",
    author="Larry Shaffer",
    author_email="lshaffer@boundlessgeo.com"
)


options(
    plugin=Bunch(
        name='populateauthsystem',
        source_dir=path('populateauthsystem'),
        resources_qrcs=['resources'],
        package_dir=path('package'),
        base_excludes=base_excludes(),
        excludes=full_excludes(),
        # skip certain files inadvertently found by exclude pattern globbing
        skip_exclude=['']
    ),

    # Default Server Params (can be overridden)
    plugin_server=Bunch(
        server='qgis.boundlessgeo.com',
        port=80,
        protocol='http',
        end_point='/RPC2/'
    ),

    sphinx=Bunch(
        docroot='doc',
        sourcedir='source',
        builddir='build'
    )
)


@task
def qrcs(options):
    """run all .qrc files through pyrcc4 to generate resource modules"""
    for rsrc in options.plugin.source_dir.walkfiles('*.qrc'):
        sh('pyrcc4 -o {0}_rc.py {0}.qrc'.format(rsrc.namebase),
           cwd=rsrc.parent)


@task
@needs('paver.doctools.html')
def html(options):
    """build documentation and install it into plugin/help"""
    builtdocs = path(options.sphinx.docroot) / options.sphinx.builddir / 'html'
    help_dir = options.plugin.source_dir / 'help'
    help_dir.rmtree()
    builtdocs.move(help_dir)


@task
def install(options):
    """install plugin to qgis"""
    call_task('qrcs')
    plugin_name = options.plugin.name
    src = path(__file__).dirname() / plugin_name
    dst = path('~').expanduser() / '.qgis2' / 'python' / 'plugins' / plugin_name
    src = src.abspath()
    dst = dst.abspath()
    if not hasattr(os, 'symlink'):
        dst.rmtree()
        src.copytree(dst)
    elif not dst.exists():
        src.symlink(dst)


@task
@cmdopts([
    make_option("-t", "--with-tests", action="store_true",
                dest="with_tests", help="package with tests", default=False)
])
def package(options):
    """create filtered package for plugin release"""
    call_task('qrcs')
    call_task('html')
    options.plugin.package_dir.mkdir()
    package_file = options.plugin.package_dir / ('%s.zip' % options.plugin.name)
    package_file.remove()
    with zipfile.ZipFile(package_file, 'w', zipfile.ZIP_DEFLATED) as zip:
        make_zip(zip, options, basefilters=options.package.with_tests)
    return package_file


@task
def package_with_tests():
    """create filtered package for plugin that includes the test suite"""
    call_task('package', options={
        'with_tests': True
    })


def make_zip(zip, options, basefilters=False):
    excludes = set(
        options.plugin.base_excludes if basefilters else options.plugin.excludes
    )
    skips = options.plugin.skip_exclude

    src_dir = options.plugin.source_dir
    exclude = lambda p: any([fnmatch.fnmatch(p, e) for e in excludes])

    def filter_excludes(root, items):
        if not items:
            return []
        # to prevent descending into dirs, modify the list in place
        for item in list(items):  # copy list or iteration values change
            itempath = path(os.path.relpath(root, src_dir)) / item
            if exclude(item) and item not in skips:
                debug('excluding %s' % itempath)
                items.remove(item)
        return items

    for root, dirs, files in os.walk(src_dir):
        for f in filter_excludes(root, files):
            relpath = os.path.relpath(root, src_dir)
            zip.write(path(root) / f, path(relpath) / f)
        filter_excludes(root, dirs)


@task
@cmdopts([
    ('user=', 'u', 'upload user'),
    ('passwd=', 'p', 'upload password'),
    ('server=', 's', 'alternate server'),
    ('end_point=', 'e', 'alternate endpoint'),
    ('port=', 't', 'alternate port'),
])
def upload(options):
    """upload the package to the server"""
    package_file = package(options)
    user, passwd = getattr(options, 'user', None), \
        getattr(options, 'passwd', None)
    if not user or not passwd:
        raise BuildFailure('provide user and passwd options to upload task')
    # create URL for XML-RPC calls
    s = options.plugin_server
    server, end_point, port = getattr(options, 'server', None), \
        getattr(options, 'end_point', None), \
        getattr(options, 'port', None)
    if server is None:
        server = s.server
    if end_point is None:
        end_point = s.end_point
    if port is None:
        port = s.port
    uri = "%s://%s:%s@%s:%s%s" % (s.protocol,
                                  options['user'], options['passwd'],
                                  server, port, end_point)
    info('uploading to %s', uri)
    server = xmlrpclib.ServerProxy(uri, verbose=False)
    try:
        plugin_id, version_id = \
            server.plugin.upload(xmlrpclib.Binary(package_file.bytes()))
        info("Plugin ID: %s", plugin_id)
        info("Version ID: %s", version_id)
        package_file.unlink()
    except xmlrpclib.Fault, err:
        error("A fault occurred")
        error("Fault code: %d", err.faultCode)
        error("Fault string: %s", err.faultString)
    except xmlrpclib.ProtocolError, err:
        error("Protocol error")
        error("%s : %s", err.errcode, err.errmsg)
        if err.errcode == 403:
            error("Invalid name and password?")
