# -*- coding:utf-8 -*-

import logging, os, sys, traceback, re, inspect, json
try:
    from urllib.parse import parse_qs, urlparse
except:
    from cgi import parse_qs
    from urlparse import urlparse


from BaseHTTPServer import _quote_html
from websockify.websocketproxy import ProxyRequestHandler, WebSocketProxy


from .globals import requests_stack
from .util.compat import integer_types
from .util import reraise_exception, get_caller_name



class HTTPError(Exception):
    code = None
    msg = None
    def __init__(self, err_code, msg=None):
        self.code = err_code
        self.msg = msg



# wesockify.websocket.WebSocketServer 
#   <- websockify.websocketproxy.WebSocketProxy 
#   <- WsWebServer
class WsWebServer(WebSocketProxy):
    """
        A websocket proxy and a web server.
        Inheriting from WebSocketProxy.
        Added features:
            A tiny web framework inspired by flask.
            In daemon mode, pid file will be created (only if current user has root priviliege).
    """
    pidfile_path=os.path.normpath('/var/run/websockify/fronwebsockify.pid')
    _daemon_pid = None

    def __init__(self, *args, **kwargs):
        self.config = kwargs.copy()
        kwargs.pop('credential', None)
        kwargs.pop('display', None)
        super(WsWebServer, self).__init__(*args, **kwargs)

    def daemonize(self, *args, **kwargs):
        if self.daemon_pid and self.run_as_root:
            self.warn('run daemon as a service, but pidfile already exists, pid: %s'% \
                    self.daemon_pid)
            self.warn('exit 0')
            sys.exit(0)
        super(WsWebServer, self).daemonize(*args, **kwargs)
        stdin = kwargs.pop('stdin', None)
        stdout = kwargs.pop('stdout', '/var/log/wsweb_std.log')
        stderr = kwargs.pop('stderr', '/var/log/wsweb_std.log')
        if stdin:
            sys.stdin = open(stdin, 'r')
        if stdout:
            sys.stdout = open(stdout, 'a', False)
        if stderr:
            sys.stderr = open(stderr, 'a', False)
        if self.run_as_root:
            self.msg('root user, run daemon as service.')
            self.create_pidfile()
        else:
            self.warn('normal user, run daemon.')

    @property
    def pid(self):
        return os.getpid()

    @property
    def run_as_root(self):
        return os.getuid() == 0

    @property
    def daemon_pid(self):
        if not self._daemon_pid:
            if os.path.exists(self.pidfile_path):
                with open(self.pidfile_path, 'r') as f:
                    pid = f.read()
                # no value guard
                self._daemon_pid = int(pid)
        return self._daemon_pid

    # called when daemonize
    def create_pidfile(self):
        dirname = os.path.dirname(self.pidfile_path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(self.pidfile_path, 'w') as pidfile:
            pid = self.pid
            self.vmsg('create pidfile, pid: %d' % pid)
            pidfile.write(str(self.pid))


    # called before terminate
    def delete_pidfile(self):
        if os.path.exists(self.pidfile_path):
            os.remove(self.pidfile_path)


    def error(self, *args, **kwargs):
        """ Output message as error """
        self.logger.log(logging.ERROR, *args, **kwargs)


    def start_server(self):
        try:
            super(WsWebServer, self).start_server()
        except:
            self.error(traceback.format_exc())
        finally:
            if self.daemon and self.run_as_root:
                self.delete_pidfile()





### Inheritance ###
# SocketServer.BaseRequestHandler
# |     __init__:  setup -> handel -> finish
# |
# SocketServer.StreamRequestHandler 
# |     setup: rfile, wfile
# |     finish: close file, wfile
# |
# BaseHTTPServer.BaseHTTPRequestHandler
# |     handle: 
# |         while not close_connection:
# |             handle_one_request
# |     handle_one_request:
# |         parse_request
# |         call do_[method] -> if no such method, return 501
# |     parse_request:
# |         parse first line (like "GET /path HTTP/1.1")
# |         command <- "GET"
# |         path <- "/path"
# |         version <- "HTTP/1.1"
# |         headers = mimetools.Message(rfile, 0)
# |         if headers['Connection'] == 'keep-alive': -> close_connection = False
# |         elif headers['Connection'] == 'close': close_connection = True
# |
# SimpleHTTPServer.SimpleHTTPRequestHandler
# |     do_GET:
# |         f = send_head()
# |         if f: -> shutil.copyfileobj(f, wfile) -> f.close()
# |     do_HEAD:
# |         f = send_head()
# |         if f: f.close()
# |
# websockify.websocket.WebSocketRequestHandler
# |     __init__: store some cfg -> SimpleHTTPRequestHandler.__init__(...)
# |     do_GET:
# |         if is_websocket: -> handle websocket request
# |         else: SimpleHTTPRequestHandler.do_GET(...)
# |
# websockify.websocket.ProxyRequestHandler
# |
# |
# |WsWebHandler
# |
# |
#####

class WsWebHandler(ProxyRequestHandler, object):
    """
        Implementing dynamic url handling with python regex (re module)
        note:
            Processing dynamic url is prior to serving static files
            If there is both a dynamic url and a static url with same name,
            dynamic url handler will always be called.
    """

    # when handling websocket, this indicate the target host.
    _token = None

    # to store query string arguments.
    # a dict like:
    # {'arg1': val1, 'arg2': val2, ...}
    _args = None

    # request message body
    # _body = None

    # to store routes
    # _url_mappings = {
    #     re.compile('pattern') : handler,
    #     ...
    # }
    _url_mappings = {}

    # to store exception handlers
    # _usr_exceptions = {
    #     None : {exception_cls : handler, ...},    # custom exception
    #     status_code : handler,    # custom status handler
    #     ...
    # }
    _usr_exceptions = {}

    # to store callback funcs which will be called after connection.
    _finished_cbs = []


    default_headers = {
        'Content-Type': 'text/html',
        'Server': 'Fron-Awesome',
        'Connection': 'close'   # deactive keep-alive
        }

    error_message_format = """\
<head>
<title>Error Response</title>
</head>
<body>
<h1>Error Response</h1>
<p>Error Code %(code)d</p>
<p>Message: %(message)s</p>
<p>Description: </p>
<pre>
%(explain)s
</pre>
</body>
"""

    default_status = 200

    class HandlerException(Exception):
        """
            any other fatal exceptions (may replace it with assertion)
        """
        pass

    class ErrButDoNothing(Exception):
        """
            scenario:
                parse_request return False
                -> which means an error occured, but error responed is already sent by parse_request
        """
        pass

    def __init__(self, *args, **kwargs):
        requests_stack.push(self)  # requests stack
        ProxyRequestHandler.__init__(self, *args, **kwargs)

    # def __del__(self):
    #     requests_stack.pop()


    ##########################
    # debug tools
    ##########################
    def log_error(self, format, *args):
        self.logger.error("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))


    ##########################
    # properties from server
    ##########################
    @property
    def config(self):
        return self.server.config

    @property
    def targets(self):
        return self.config.get('token_plugin', None)

    @property
    def target_display(self):
        return self.config.get('display', None)

    @property
    def target_credential(self):
        return self.config.get('credential', None)


    @property
    def ws_connection(self):
        return self.server.ws_connection


    ###########################
    # properties
    ###########################
    @property
    def content_length(self):
        _len = self.headers.get('content-length', None)
        if _len is not None:
            return int(_len)
        else:
            return None

    @property
    def content_type(self):
        return self.headers.get('content-type', None)

    @property
    def body(self):
        """
            if Transfer-Encoding or Content-Length in headers, there is body.
            but here we only check Content-length
        """
        _body = getattr(self, '_body', None)
        if _body is None:
            if self.content_length:
                _body = self._body = self.rfile.read(self.content_length)

        return _body

    @property
    def json(self):
        if self.body:
            if self.content_type == 'application/json':
                return json.loads(self.body)
        return None

    @property
    def data(self):
        if self.body:
            if self.content_type == 'application/x-www-form-urlencoded':
                # pairs = self.body.split('&')
                # _data = dict(v.split('=', 1) for v in pairs)
                _data = parse_qs(self.body)
                _data = dict((k,v[0] if len(v) == 1 else v) for (k,v) in _data.iteritems())
                return _data
        return None

    @property
    def args(self):
        """
            query string arguments
        """
        if self._args is None:
            _args = parse_qs(urlparse(self.path)[4])
            self._args = dict((k,v[0] if len(v) == 1 else v) for (k,v) in _args.iteritems())
        return self._args

    @property
    def token(self):
        """
            websockify target token.
            how it was gotten:
                When there is a token, 
                current request's path: 
                    GET(/?token=asdfasdf)
                and updated to websocket.
        """
        if self._token is None:
            if 'token'  in self.args:
                self._token = self.args['token'].rstrip('\n')

        return self._token


    ######################
    # route
    ######################

    @classmethod
    def add_url_rule(cls, url_pattern, handler, methods):
        url_repattern = re.compile(url_pattern)
        methods = set(m.upper() for m in methods)

        # # may be an exception should be raised, as for this classmethod is an outer interface.
        # assert cls._url_mappings.get(url_repattern, None) is None   # never been registered
        if cls._url_mappings.get(url_repattern, None) is not None:
            raise WsWebHandler.HandlerException, "url mapping '%s' exists" % url_pattern

        cls._url_mappings[url_repattern] = (handler, methods)


    @classmethod
    def route(cls, url_pattern, methods=('GET',)):
        """
            url_pattern -> regex url_pattern representing a url
            methods -> subset of ['GET', 'POST']

            calling example:
                @WsWebHandler.route('/index', ['GET', 'POST']):
                def index():
                    return 
        """
        def decorator(f):
            cls.add_url_rule(url_pattern, f, methods)
            return f
        return decorator


    def handle_route(self):
        method = self.command.upper()
        url = self.path
        for url_ptn, (handler, methods) in self._url_mappings.iteritems():
            m = url_ptn.match(url)
            if m:
                if method in methods:
                    # refernce to django
                    kwargs = m.groupdict()
                    if kwargs:
                        return handler(**kwargs)
                    else:
                        args = m.groups()
                        return handler(*args)
                else:
                    raise HTTPError(501, 'method %s is not allowed for url "%s"' % (method, url))
        raise HTTPError(404, 'not registered url "%s"' % url)  # not found



    ##################
    # make response
    ##################

    def make_response(self, rv, default_status=200, extra_headers={}):
        if isinstance(rv, tuple):
            if len(rv) == 2:
                content, headers = rv
                status = default_status
            elif len(rv) == 3:
                content, status, headers = rv
            else:
                raise WsWebHandler.HandlerException, 'make_response: wrong parameter: %r' % rv
        else:
            assert isinstance(rv, (str, unicode))
            content = rv
            status = default_status
            headers = {}

        headers.update(extra_headers)
        return content, status, headers

    def make_error_response(self, status, desc=None, extra_headers={}):
        assert status >= 400, ("make_error_response, invalid error status code: %r", status)
        default_responses = self.responses  # BaseHTTPRequestHandler
        if default_responses.has_key(status):
            phrase, explain = default_responses[status]
        else:
            phrase, explain = '???', '???'

        if not desc:
            desc = explain

        content = self.error_message_format % { # BaseHTTPRequestHandler
            'code': status,
            'message': _quote_html(phrase),
            'explain': _quote_html(desc)
            # 'explain':desc
        }

        headers = {
                'Connection': 'close',
                'Content-Type': self.error_content_type # BaseHTTPRequestHandler
            }
        headers.update(extra_headers)
        return content, status, headers


    ###################
    # error handler
    ###################

    @classmethod
    def _register_error_handler(cls, code_or_ecls, f):
        if isinstance(code_or_ecls, integer_types):
            status_code = code_or_ecls
            cls._usr_exceptions[status_code] = f    # custom handlers for http error
        else:
            assert inspect.isclass(code_or_ecls)
            ename = code_or_ecls.__name__
            cls._usr_exceptions.setdefault(None, {})[ename] = f     # handlers for custom exceptions


    @classmethod
    def errorhandler(cls, code_or_ecls):
        """
            register custom exception handler
            Example:
            # custom exception handler
            @WsWebHandler.error(KeyError)
            def keyerror_handler(e):
                return content, headers [, code] # note: default code is 500
            # custom http error handler
            @WsWebHandler.error(401)
            def unauthorized_handler(e):
                return content, headers [, code]   # note: default code is registered code
        """
        def decorator(f):
            cls._register_error_handler(code_or_ecls, f)
            return f
        return decorator


    def handle_http_exception(self, e):
        assert isinstance(e, HTTPError)
        status_code = e.code
        handlers = self._usr_exceptions
        if handlers.has_key(status_code):
            handler = handlers[status_code]
            return self.make_response(handler(e), default_status=status_code, 
                                extra_headers={'Connection': 'close'})

        return self.make_error_response(e.code, e.msg)


    def handle_user_exception(self, e):
        if isinstance(e, HTTPError):
            return self.handle_http_exception(e)

        ename = e.__class__.__name__
        custom_handlers = self._usr_exceptions.get(None, None)
        if custom_handlers:
            if custom_handlers.has_key(ename):
                handler = custom_handlers[ename]
                return self.make_response(handler(e), default_status=500,
                                extra_headers={'Connection': 'close'})

        reraise_exception(e)


    def handle_exception(self, e):
        # refer to flask.app.Flask.handle_exception, return a formatted traceback.
        return self.make_error_response(500, traceback.format_exc())


    ##########################
    # finished callback
    ##########################

    @classmethod
    def finished(cls, f):
        """
            register a callback func which will be called after sending the response.
            the last process.
            example:
                @WsWebHandler.finished
                def finished_handler(req):
                    print req
        """
        assert not f in cls._finished_cbs
        assert callable(f)
        cls._finished_cbs.append(f)
        return f


    def handle_finished_cbs(self):
        super(WsWebHandler, self).finish()
        for cb in self._finished_cbs:
            cb(self)


    ###########################
    # internals
    ###########################

    def _parse(self):
        """
            Parse http packet.
        """
        self.raw_requestline = self.rfile.readline()
        if not self.raw_requestline:
            # raise HTTPError(500, 'No data received.')
            raise WsWebHandler.ErrButDoNothing('No data received, and we treat it as a close connection, and just ignore it.')
        if not self.parse_request():    # An error code has been sent, just exit
            raise WsWebHandler.ErrButDoNothing('http parsing error, but exception handling is ready done.')


    # note:
    #   There's a process_request method in WsWebServer.
    #   Do not misjudge them.
    def process_request(self):
        try:
            rv = None
            self._parse()
            # ---{rv = before_request()}---
            if not rv:
                mname = 'do_' + self.command
                if hasattr(self, mname):
                    method = getattr(self, mname)
                    rv = method()
                else:
                    rv = self._common_process()
        except Exception, e:
            rv = self.handle_user_exception(e)

        response = None
        if rv:
            response = self.make_response(rv)
        # ---{after request(response=None)}---
        return response

    def send(self, content, code=200, extra_headers={}):
        headers = self.default_headers
        headers.update(extra_headers)
        content_length = len(content)
        if content_length > 0:
            headers.update({'Content-Length': str(content_length)})

        # BaseHTTPServer:BaseHTTPRequestHandler.send_response
        self.send_response(code)
        for h,v in headers.iteritems():
            self.send_header(h, v)
        self.end_headers()

        self.wfile.write(content)
        self.wfile.flush()

    # # rewriting BaseHTTPServer:BaseHTTPRequestHandler.handle 
    # #     -> disable keep-alive
    # def handle(self):
    #     super(WsWebHandler, self).handle()
    #     # self.handle_one_request()

    # BaseHTTPServer.BaseHTTPHandler.handle_one_request
    # (called by BaseHTTPServer.BaseHTTPHandler.handle_request)
    def handle_one_request(self):
        """
            Rewriting BaseHTTPHandler.handle_one_request
        """
        # ---{init req ctx}---
        try:
            response = None
            try:
                response = self.process_request()
            except WsWebHandler.ErrButDoNothing, e:
                self.log_message('ErrButDoNothing: %r' % e)
            except Exception, e:
                self.log_error('%s', traceback.format_exc())
                response = self.make_response(self.handle_exception(e))

            if response:
                content, status, headers = response
                self.send(content, status, headers)

            self.handle_finished_cbs()  # finished callbacks
        finally:
            requests_stack.pop()
            self.close_connection = 1   # disable keep-alive


    def _common_process(self):
        return self.handle_route()


    def do_GET(self):
        """
            First, try to retrieve registered route.
            If no corresponding route registered (which will rasie HTTPError(404)),
            try to call ProxyRequestHandler.do_GET (which handles websocket and static serving).
        """
        try:
            return self._common_process()
        except HTTPError, e:
            if e.code == 404:
                # websocket and static file serving
                super(WsWebHandler, self).do_GET()  # return no response
            else:
                reraise_exception(e)


    do_PUT = _common_process
    do_POST = _common_process
    do_DELETE = _common_process



def abort(code, msg=None):
    """
        abort with an HTTP status code.
    """
    raise HTTPError(code, msg)



def get_logger():
    return WsWebServer.get_logger()

logger = get_logger()

def msg(msg, *args, **kwargs):
    global logger
    logger.log(logging.INFO, msg, *args, **kwargs)

def debug(msg, *args, **kwargs):
    global logger
    logger.log(logging.DEBUG, msg, *args, **kwargs)

def warn(msg, *args, **kwargs):
    global logger
    logger.log(logging.WARN, msg, *args, **kwargs)



