# Copyright (c) 2005 Allan Saddi <allan@saddi.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id$

__author__ = 'Allan Saddi <allan@saddi.com>'
__version__ = '$Revision$'

import struct
import time
import zlib

__all__ = ['GzipMiddleware']

# This gzip middleware component differentiates itself from others in that
# it (hopefully) follows the spec more closely. Namely with regard to the
# application iterator and buffering. (It doesn't buffer.)
# See <http://www.python.org/peps/pep-0333.html#middleware-handling-of-block-boundaries>
#
# Of course this all comes with a price... just LOOK at this mess! :)
#
# The inner workings of gzip and the gzip file format were gleaned from gzip.py

def _gzipHeader():
    """Returns a gzip header (with no filename)."""
    # See GzipFile._write_gzip_header in gzip.py
    return '\037\213' \
           '\010' \
           '\0' + \
           struct.pack('<L', long(time.time())) + \
           '\002' \
           '\377'

class _iterWrapper(object):
    """
    gzip iterator wrapper. It ensures that: the application iterator's close()
    method (if any) is called by the parent server; and at least one value
    is yielded each time the application's iterator yields a value.

    If the application's iterator yields N values, this iterator will yield
    N+1 values. This is to account for the gzip trailer.
    """
    def __init__(self, appIter, gzipMiddleware):
        self._g = gzipMiddleware
        self._next = iter(appIter).next

        self._last = False # True if appIter has yielded last value.
        self._trailerSent = False

        if hasattr(appIter, 'close'):
            self.close = appIter.close

    def __iter__(self):
        return self

    # This would've been a lot easier had I used a generator. But then I'd have
    # to wrap the generator anyway to ensure that any existing close() method
    # was called. (Calling it within the generator is not the same thing,
    # namely it does not ensure that it will be called no matter what!)
    def next(self):
        if not self._last:
            # Need to catch StopIteration here so we can append trailer.
            try:
                data = self._next()
            except StopIteration:
                self._last = True

        if not self._last:
            if self._g.gzipOk:
                return self._g.gzipData(data)
            else:
                return data
        else:
            # See if trailer needs to be sent.
            if self._g.headerSent and not self._trailerSent:
                self._trailerSent = True
                return self._g.gzipTrailer()
            # Otherwise, that's the end of this iterator.
            raise StopIteration

class _gzipMiddleware(object):
    """
    The actual gzip middleware component. Holds compression state as well
    implementations of start_response and write. Instantiated before each
    call to the underlying application.

    This class is private. See GzipMiddleware for the public interface.
    """
    def __init__(self, start_response, mimeTypes, compresslevel):
        self._start_response = start_response
        self._mimeTypes = mimeTypes

        self.gzipOk = False
        self.headerSent = False

        # See GzipFile.__init__ and GzipFile._init_write in gzip.py
        self._crc = zlib.crc32('')
        self._size = 0
        self._compress = zlib.compressobj(compresslevel,
                                          zlib.DEFLATED,
                                          -zlib.MAX_WBITS,
                                          zlib.DEF_MEM_LEVEL,
                                          0)

    def gzipData(self, data):
        """
        Compresses the given data, prepending the gzip header if necessary.
        Returns the result as a string.
        """
        if not self.headerSent:
            self.headerSent = True
            out = _gzipHeader()
        else:
            out = ''

        # See GzipFile.write in gzip.py
        length = len(data)
        if length > 0:
            self._size += length
            self._crc = zlib.crc32(data, self._crc)
            out += self._compress.compress(data)
        return out
        
    def gzipTrailer(self):
        # See GzipFile.close in gzip.py
        return self._compress.flush() + \
               struct.pack('<l', self._crc) + \
               struct.pack('<L', self._size & 0xffffffffL)

    def start_response(self, status, headers, exc_info=None):
        self.gzipOk = False

        # Scan the headers. Only allow gzip compression if the Content-Type
        # is one that we're flagged to compress AND the headers do not
        # already contain Content-Encoding.
        for name,value in headers:
            name = name.lower()
            if name == 'content-type' and value in self._mimeTypes:
                self.gzipOk = True
            elif name == 'content-encoding':
                self.gzipOk = False
                break

        if self.gzipOk:
            # Remove Content-Length, if present, because compression will
            # most surely change it. (And unfortunately, we can't predict
            # the final size...)
            headers = [(name,value) for name,value in headers
                       if name.lower() != 'content-length']
            headers.append(('Content-Encoding', 'gzip'))

        _write = self._start_response(status, headers, exc_info)

        if self.gzipOk:
            def write_gzip(data):
                _write(self.gzipData(data))
            return write_gzip
        else:
            return _write

class GzipMiddleware(object):
    """
    WSGI middleware component that gzip compresses the application's output
    (if the client supports gzip compression - gleaned  from the
    Accept-Encoding request header).

    mimeTypes should be a list of Content-Types that are OK to compress.

    compresslevel is the gzip compression level, an integer from 1 to 9; 1
    is the fastest and produces the least compression, and 9 is the slowest,
    producing the most compression.
    """
    def __init__(self, application, mimeTypes=None, compresslevel=9):
        if mimeTypes is None:
            mimeTypes = ['text/html']

        self._application = application
        self._mimeTypes = mimeTypes
        self._compresslevel = compresslevel

    def __call__(self, environ, start_response):
        """WSGI application interface."""
        # If the client doesn't support gzip encoding, just pass through
        # directly to the application.
        if 'gzip' not in environ.get('HTTP_ACCEPT_ENCODING', ''):
            return self._application(environ, start_response)

        # All of the work is done in _gzipMiddleware and _iterWrapper.
        g = _gzipMiddleware(start_response, self._mimeTypes,
                            self._compresslevel)

        result = self._application(environ, g.start_response)

        # See if it's a length 1 iterable...
        try:
            shortcut = len(result) == 1
        except:
            shortcut = False

        if shortcut:
            # Special handling if application returns a length 1 iterable:
            # also return a length 1 iterable!
            try:
                i = iter(result)
                # Hmmm, if we get a StopIteration here, the application's
                # broken (__len__ lied!)
                data = i.next()
                if g.gzipOk:
                    return [g.gzipData(data) + g.gzipTrailer()]
                else:
                    return [data]
            finally:
                if hasattr(result, 'close'):
                    result.close()

        return _iterWrapper(result, g)

if __name__ == '__main__':
    def myapp(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/html')])
        return ['Hello World!\n']
    app = GzipMiddleware(myapp)

    from ajp import WSGIServer
    import logging
    WSGIServer(app, loggingLevel=logging.DEBUG).run()
