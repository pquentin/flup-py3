# flup-py3 for Python 3.4+

[flup-py3](https://hg.saddi.com/flup-py3.0/) fork and updated for Python 3.4+.

Please note that [WSGI](https://www.python.org/dev/peps/pep-0333/) is the preferable way for
Python based web applications.

## Installation

You may install this package by using [pip] for Python 3. Optionally with the help
of [venv].

The actual command is different among operation systems. For example,
[Debian / Ubuntu package][python3-pip3] name it as **pip3**.

Add this line to your `requirements.txt`:

```text
git+https://github.com/pquentin/flup-py3.git
```

Then run this command (assume the command is **pip3**):

```text
pip3 install -r requirements.txt
```

[pip]: https://pypi.python.org/pypi/pip
[venv]: https://docs.python.org/3/library/venv.html
[python3-pip3]: https://packages.debian.org/jessie/python/python3-pip

## Usage

A simple hello world app (reference: [Python 3.4 Documentations][webserver])

```python
import sys, os, logging
from html import escape
from flup.server.fcgi import WSGIServer

def app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    yield "hello world"

def main():
    try:
        WSGIServer(app, bindAddress='./hello-world.sock', umask=0000).run()
    except (KeyboardInterrupt, SystemExit, SystemError):
        logging.info("Shutdown requested...exiting")
    except Exception:
        traceback.print_exc(file=sys.stdout)
```

[webserver]: https://docs.python.org/3.4/howto/webservers.html

## Maintenance

Github Repository: [github.com/pquentin/flup-py3][github]

[github]: github.com/pquentin/flup-py3
