#!/usr/bin/env python

setuptools_extras = {}

try:
    from setuptools import setup
    setuptools_extras['entry_points'] = """
        [paste.server_factory]
        ajp = flup.server.ajp:factory
        fcgi = flup.server.fcgi:factory
        scgi = flup.server.scgi:factory
        ajp_fork = flup.server.ajp_fork:factory
        fcgi_fork = flup.server.fcgi_fork:factory
        scgi_fork = flup.server.scgi_fork:factory
        """
except ImportError:
    from distutils.core import setup

setup(name='flup',
      version='0.5',
      description='Random assortment of WSGI servers, middleware',
      author='Allan Saddi',
      author_email='allan@saddi.com',
      url='http://www.saddi.com/software/flup/',
      packages=['flup', 'flup.client', 'flup.middleware', 'flup.resolver',
                'flup.server'],
      **setuptools_extras)
