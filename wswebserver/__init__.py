import re
import logging, os, sys, traceback
import inspect

try:
    from urllib.parse import parse_qs, urlparse
except:
    from cgi import parse_qs
    from urlparse import urlparse

from BaseHTTPServer import _quote_html

from websockify import websocket
from websockify.websocketproxy import (
        ProxyRequestHandler, WebSocketProxy, LibProxyServer
    )
from websockify.websocketproxy import logger_init


from plugins import CredentialFile
from _compat import integer_types, reraise


# app/process scope (app_ctx), normally readonly after starting to handle requests.

# req ctx, created per-request.


# These 2 plugins are used to access config files and credential files (app/process scope)
tokens = None
credentials = None


def reraise_exception(e):
    exc_type, exc_value, tb = sys.exc_info()
    reraise(exc_type, exc_value, tb)


# def quote_html(html):
#     html = _quote_html(html)
#     html = html.replace('\r\n', '<br />')
#     html = html.replace('\n\r', '<br />')
#     html = html.replace('\r', '<br />')
#     html = html.replace('\n', '<br />')
#     return html


class HTTPError(Exception):
    code = None
    msg = None
    def __init__(self, err_code, msg=None):
        self.code = err_code
        self.msg = msg



# wesockify.websocket.WebSocketServer <- websockify.websocketproxy.WebSocketProxy <- WsWebServer
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

    # @staticmethod
    # def get_logger():
    #     return logging.getLogger(WebSocketProxy.log_prefix)

    def daemonize(self, *args, **kwargs):
        if self.daemon_pid and self.run_as_root:
            self.warn('run daemon as a service, but pidfile already exists, pid: %s'% \
                    self.daemon_pid)
            self.warn('exit 0')
            sys.exit(0)
        super(WsWebServer, self).daemonize(*args, **kwargs)
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

    ##########################
    # debug tools
    ##########################
    def log_error(self, format, *args):
        self.logger.error("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))


    ###########################
    # properties
    ###########################

    @property
    def args(self):
        """
            query string arguments
        """
        if self._args is None:
            self._args = parse_qs(urlparse(self.path)[4])
        return self._args


    @property
    def ws_connection(self):
        return self.server.ws_connection

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
                self._token = self.args['token'][0].rstrip('\n')

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


    # # rewriting BaseHTTPRequestHandler.handle -> disable keep-alive
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
                print 'adsasdfasdf'
                response = self.make_response(self.handle_exception(e))

            if response:
                content, status, headers = response
                print 'headers:', headers
                print 'content:'
                print content
                print 'status:', status
                self.send(content, status, headers)

            self.handle_finished_cbs()  # finished callbacks
        finally:
            # ---{destroy req ctx}---
            self.close_connection = 1   # disable keep-alive

    # send_response is defined under BaseHTTPRequestHandler
    def send(self, content, code=200, extra_headers={}):
        headers = self.default_headers
        headers.update(extra_headers)
        headers.update({'Content-Length': str(len(content))})

        self.send_response(code)
        for h,v in headers.iteritems():
            self.send_header(h, v)
        self.end_headers()

        self.wfile.write(content)
        self.wfile.flush()

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

    # do_PUT = _common_process
    # do_POST = _common_process



# debug tools
def get_caller_name():
    return inspect.stack()[2][3]


def abort(code, msg=None):
    """
        abort with an HTTP status code.
    """
    raise HTTPError(code, msg)


import optparse

# re-implement websocketproxy.websockify_init
# add an option --target-credential
def runserver(HandlerCls=None):
    logger_init()

    usage = "\n    %prog [options]"
    usage += " [source_addr:]source_port [target_addr:target_port]"
    usage += "\n    %prog [options]"
    usage += " [source_addr:]source_port -- WRAP_COMMAND_LINE"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("--verbose", "-v", action="store_true",
            help="verbose messages")
    parser.add_option("--traffic", action="store_true",
            help="per frame traffic")
    parser.add_option("--record",
            help="record sessions to FILE.[session_number]", metavar="FILE")
    parser.add_option("--daemon", "-D",
            dest="daemon", action="store_true",
            help="become a daemon (background process)")
    parser.add_option("--run-once", action="store_true",
            help="handle a single WebSocket connection and exit")
    parser.add_option("--timeout", type=int, default=0,
            help="after TIMEOUT seconds exit when not connected")
    parser.add_option("--idle-timeout", type=int, default=0,
            help="server exits after TIMEOUT seconds if there are no "
                 "active connections")
    parser.add_option("--cert", default="self.pem",
            help="SSL certificate file")
    parser.add_option("--key", default=None,
            help="SSL key file (if separate from cert)")
    parser.add_option("--ssl-only", action="store_true",
            help="disallow non-encrypted client connections")
    parser.add_option("--ssl-target", action="store_true",
            help="connect to SSL target as SSL client")
    parser.add_option("--unix-target",
            help="connect to unix socket target", metavar="FILE")
    parser.add_option("--web", default=None, metavar="DIR",
            help="run webserver on same port. Serve files from DIR.")
    parser.add_option("--wrap-mode", default="exit", metavar="MODE",
            choices=["exit", "ignore", "respawn"],
            help="action to take when the wrapped program exits "
            "or daemonizes: exit (default), ignore, respawn")
    parser.add_option("--prefer-ipv6", "-6",
            action="store_true", dest="source_is_ipv6",
            help="prefer IPv6 when resolving source_addr")
    parser.add_option("--libserver", action="store_true",
            help="use Python library SocketServer engine")
    parser.add_option("--target-config", metavar="FILE",
            dest="target_cfg",
            help="Configuration file containing valid targets "
            "in the form 'token: host:port' or, alternatively, a "
            "directory containing configuration files of this form "
            "(DEPRECATED: use `--token-plugin TokenFile --token-source "
            " path/to/token/file` instead)")

    # config file storing target credential (token: password)
    parser.add_option("--target-credential", metavar="FILE",
            dest="target_credential",
            help="Configuration file containing valid targets credential"
            "records in this file correspond to that in target-config file"
            "in the form 'token: password' or, alternatively, a "
            "directory containing configuration files of this form "
            "(for fronware web server)")

    parser.add_option("--token-plugin", default=None, metavar="PLUGIN",
                      help="use the given Python class to process tokens "
                           "into host:port pairs")
    parser.add_option("--token-source", default=None, metavar="ARG",
                      help="an argument to be passed to the token plugin"
                           "on instantiation")
    parser.add_option("--auth-plugin", default=None, metavar="PLUGIN",
                      help="use the given Python class to determine if "
                           "a connection is allowed")
    parser.add_option("--auth-source", default=None, metavar="ARG",
                      help="an argument to be passed to the auth plugin"
                           "on instantiation")
    parser.add_option("--auto-pong", action="store_true",
            help="Automatically respond to ping frames with a pong")
    parser.add_option("--heartbeat", type=int, default=0,
            help="send a ping to the client every HEARTBEAT seconds")
    parser.add_option("--log-file", metavar="FILE",
            dest="log_file",
            help="File where logs will be saved")


    (opts, args) = parser.parse_args()

    if opts.log_file:
        opts.log_file = os.path.abspath(opts.log_file)
        handler = logging.FileHandler(opts.log_file)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger(WebSocketProxy.log_prefix).addHandler(handler)

    del opts.log_file

    if opts.verbose:
        logging.getLogger(WebSocketProxy.log_prefix).setLevel(logging.DEBUG)

    if opts.token_source and not opts.token_plugin:
        parser.error("You must use --token-plugin to use --token-source")

    if opts.auth_source and not opts.auth_plugin:
        parser.error("You must use --auth-plugin to use --auth-source")


    # Transform to absolute path as daemon may chdir
    if opts.target_cfg:
        opts.target_cfg = os.path.abspath(opts.target_cfg)

    if opts.target_cfg:
        opts.token_plugin = 'TokenFile'
        opts.token_source = opts.target_cfg

    del opts.target_cfg


    # credential file  for fronware
    if opts.target_credential:
        global credentials
        opts.target_credential = os.path.abspath(opts.target_credential)
        credentials = CredentialFile(opts.target_credential)
    del opts.target_credential


    # Sanity checks
    if len(args) < 2 and not (opts.token_plugin or opts.unix_target):
        parser.error("Too few arguments")
    if sys.argv.count('--'):
        opts.wrap_cmd = args[1:]
    else:
        opts.wrap_cmd = None
        if len(args) > 2:
            parser.error("Too many arguments")

    if not websocket.ssl and opts.ssl_target:
        parser.error("SSL target requested and Python SSL module not loaded.");

    if opts.ssl_only and not os.path.exists(opts.cert):
        parser.error("SSL only and %s not found" % opts.cert)

    # Parse host:port and convert ports to numbers
    if args[0].count(':') > 0:
        opts.listen_host, opts.listen_port = args[0].rsplit(':', 1)
        opts.listen_host = opts.listen_host.strip('[]')
    else:
        opts.listen_host, opts.listen_port = '', args[0]

    try:    opts.listen_port = int(opts.listen_port)
    except: parser.error("Error parsing listen port")

    if opts.wrap_cmd or opts.unix_target or opts.token_plugin:
        opts.target_host = None
        opts.target_port = None
    else:
        if args[1].count(':') > 0:
            opts.target_host, opts.target_port = args[1].rsplit(':', 1)
            opts.target_host = opts.target_host.strip('[]')
        else:
            parser.error("Error parsing target")
        try:    opts.target_port = int(opts.target_port)
        except: parser.error("Error parsing target port")

    if opts.token_plugin is not None:
        if '.' not in opts.token_plugin:
            opts.token_plugin = (
                'websockify.token_plugins.%s' % opts.token_plugin)

        token_plugin_module, token_plugin_cls = opts.token_plugin.rsplit('.', 1)

        __import__(token_plugin_module)
        token_plugin_cls = getattr(sys.modules[token_plugin_module], token_plugin_cls)

        opts.token_plugin = token_plugin_cls(opts.token_source)

        global tokens
        tokens = opts.token_plugin

    del opts.token_source

    if opts.auth_plugin is not None:
        if '.' not in opts.auth_plugin:
            opts.auth_plugin = 'websockify.auth_plugins.%s' % opts.auth_plugin

        auth_plugin_module, auth_plugin_cls = opts.auth_plugin.rsplit('.', 1)

        __import__(auth_plugin_module)
        auth_plugin_cls = getattr(sys.modules[auth_plugin_module], auth_plugin_cls)

        opts.auth_plugin = auth_plugin_cls(opts.auth_source)

    del opts.auth_source

    if HandlerCls != None:
        opts.RequestHandlerClass = HandlerCls
    else:
        # static file serving and websocket proxy
        opts.RequestHandlerClass = WsWebHandler

    # Create and start the WebSockets proxy
    libserver = opts.libserver
    del opts.libserver
    if libserver:
        # Use standard Python SocketServer framework
        server = LibProxyServer(**opts.__dict__)
        server.serve_forever()
    else:
        # Use internal service framework
        # server = WebSocketProxy(**opts.__dict__)
        server = WsWebServer(**opts.__dict__)
        server.start_server()





if __name__ == '__main__':
    runserver(WsWebHandler)



