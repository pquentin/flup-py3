# Bootstrap setuptools
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages
setup(
    name = 'flup',
    version = '1.0.2',
    packages = find_packages(),
    zip_safe = True,
    
    entry_points = """
    [paste.server_runner]
    ajp = flup.server.paste_factory:run_ajp_thread
    fcgi = flup.server.paste_factory:run_fcgi_thread
    scgi = flup.server.paste_factory:run_scgi_thread
    ajp_thread = flup.server.paste_factory:run_ajp_thread
    fcgi_thread = flup.server.paste_factory:run_fcgi_thread
    scgi_thread = flup.server.paste_factory:run_scgi_thread
    ajp_fork = flup.server.paste_factory:run_ajp_fork
    fcgi_fork = flup.server.paste_factory:run_fcgi_fork
    scgi_fork = flup.server.paste_factory:run_scgi_fork
    """,
    
    author = 'Allan Saddi',
    author_email = 'allan@saddi.com',
    description = 'Random assortment of WSGI servers',
    license = 'BSD',
    url='http://www.saddi.com/software/flup/',
    classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Web Environment',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Topic :: Internet :: WWW/HTTP :: WSGI :: Server',
    'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    )
