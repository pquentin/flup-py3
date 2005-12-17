#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='flup',
      version='0.5',
      description='Random assortment of WSGI servers, middleware',
      author='Allan Saddi',
      author_email='allan@saddi.com',
      url='http://www.saddi.com/software/flup/',
      packages=['flup', 'flup.middleware', 'flup.resolver', 'flup.server'])
