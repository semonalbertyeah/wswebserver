import re
from string import Template
import logging, os, sys, traceback
import inspect

from websockify import websocket
from websockify.websocketproxy import (
        ProxyRequestHandler, WebSocketProxy, LibProxyServer
    )
from websockify.websocketproxy import logger_init

from plugins import CredentialFile


class HTTPError(Exception):
    def __init__(self, err_code, msg=None):
        self.err_code = err_code
        self.msg = msg


# These 2 plugins are used to access config files and credential files
_token_plugin = None
_credential_plugin = None


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
    url_mappings = {}
    default_headers = {
        'Content-Type': 'text/html',
        'Server': 'Fronware-custom'
        }

    class ProxyRequestHandlerFWException(Exception):
        pass

    class DoNothing(Exception):
        """
            scenario:
                parse_request return False
                -> which means an error occured, but error responed is already sent by parse_request
        """
        pass


    # def finish(self):
    #     super(WsWebHandler, self).finish()
    #     print '---- handling finished, pid:', os.getpid()
    #     if self.server.ws_connection:
    #         print '---- websocket connection, do something'

    @classmethod
    def add_url_rule(cls, url_pattern, handler, methods):
        url_repattern = re.compile(url_pattern)
        methods = set(m.upper() for m in methods)
        old_handler, old_methods = cls.url_mappings.get(url_repattern, (None, None))
        if old_handler is not None and old_handler != handler:
            raise WsWebHandler.ProxyRequestHandlerFWException, "url mapping '%s' exists" % url_pattern

        cls.url_mappings[url_repattern] = (handler, methods)

    @classmethod
    def route(cls, url_pattern, methods=('GET',)):
        """
            url_pattern -> regex url_pattern representing a url
            methods -> subset of ['GET', 'POST']

            calling example:
                @WsWebHandler.route('/index', ['GET', 'POST'])
        """
        def decorator(f):
            cls.add_url_rule(url_pattern, f, methods)
            return f
        return decorator


    def handle_route(self):
        method = self.command.upper()
        url = self.path
        for url_ptn, (handler, methods) in self.url_mappings.iteritems():
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
                    raise HTTPError(501, 'not allowed method %s' % method)
        raise HTTPError(404, "no matching url: %s" % url)  # not found

    def handle_user_exception(self, e):
        if isinstance(e, HTTPError):
            handle_http_exception(e)
            return
        # handle user registered exceptions

    def handle_http_exception(self, e):
        self.send_error(e.err_code, e.msg)

    def handle_exception(self, e):
        # refer to flask.app.Flask.handle_exception, return a formatted traceback.
        self.send_error(500, traceback.format_exc())

    def _parse(self):
        self.raw_requestline = self.rfile.readline()
        if not self.raw_requestline:
            raise HTTPError(500, 'No data received.')
        if not self.parse_request():    # An error code has been sent, just exit
            raise self.DoNothing()

    # BaseHTTPServer.BaseHTTPHandler.handle_one_request (called by BaseHTTPServer.BaseHTTPHandler.handle_request)
    def handle_one_request(self):
        """
            Where the request is handled.
        """
        self.error('debug info: WsWebHandler.handle_one_request')
        try:
            try:
                self._parse()
                # before_request
                mname = 'do_' + self.command
                if not hasattr(self, mname):
                    raise HTTPError(501, 'Unsupported method (%r)' % self.command)
                method = getattr(self, mname)
                method()
            except Exception, e:
                self.handle_user_exception(e)
        except Exception e:
            self.handle_exception(e)

    # send_response is defined under BaseHTTPRequestHandler
    def send_response_content(self, content, extra_headers={}, code=200):
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
        r = self.handle_route()
        if isinstance(r, tuple):
            if len(r) == 2:
                r, headers = r
                self.send_response_content(r, extra_headers=headers)
            elif len(r) == 3:
                r, headers, code = r
                self.send_response_content(r, extra_headers=headers, code=code)
            else:
                raise WsWebHandler.ProxyRequestHandlerFWException, "wrong return value from handlers for %s" % self.path
        else:
            self.send_response_content(r)


    def do_GET(self):
        """
            method handler called by BaseHTTPRequestHandler.handle_one_request
        """
        try:
            self._common_process()
        except HTTPError, e:
            if e.err_code == 404:
                # if no dynamic url handler -> try to serve static file.
                super(WsWebHandler, self).do_GET()
            else:
                raise e # -> reraise

    do_PUT = _common_process
    do_POST = _common_process



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
        global _credential_plugin
        opts.target_credential = os.path.abspath(opts.target_credential)
        _credential_plugin = CredentialFile(opts.target_credential)
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

        global _token_plugin
        _token_plugin = opts.token_plugin

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



