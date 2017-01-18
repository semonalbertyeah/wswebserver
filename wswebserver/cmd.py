# -*- coding:utf-8 -*-

import logging, os, sys
import optparse

from websockify import websocket
from websockify.websocketproxy import (
    WebSocketProxy, LibProxyServer, logger_init
)

from .wsweb import WsWebServer
# from .plugins import CredentialFile
from .plugins import ConfigFile


# These 2 plugins are used to access config files and credential files (app/process scope)
tokens = None
credentials = None


# # re-implementing websocketproxy.websockify_init
# # add option "--target-credential"
# def runserver(HandlerCls=None):
#     logger_init()

#     usage = "\n    %prog [options]"
#     usage += " [source_addr:]source_port [target_addr:target_port]"
#     usage += "\n    %prog [options]"
#     usage += " [source_addr:]source_port -- WRAP_COMMAND_LINE"
#     parser = optparse.OptionParser(usage=usage)
#     parser.add_option("--verbose", "-v", action="store_true",
#             help="verbose messages")
#     parser.add_option("--traffic", action="store_true",
#             help="per frame traffic")
#     parser.add_option("--record",
#             help="record sessions to FILE.[session_number]", metavar="FILE")
#     parser.add_option("--daemon", "-D",
#             dest="daemon", action="store_true",
#             help="become a daemon (background process)")
#     parser.add_option("--run-once", action="store_true",
#             help="handle a single WebSocket connection and exit")
#     parser.add_option("--timeout", type=int, default=0,
#             help="after TIMEOUT seconds exit when not connected")
#     parser.add_option("--idle-timeout", type=int, default=0,
#             help="server exits after TIMEOUT seconds if there are no "
#                  "active connections")
#     parser.add_option("--cert", default="self.pem",
#             help="SSL certificate file")
#     parser.add_option("--key", default=None,
#             help="SSL key file (if separate from cert)")
#     parser.add_option("--ssl-only", action="store_true",
#             help="disallow non-encrypted client connections")
#     parser.add_option("--ssl-target", action="store_true",
#             help="connect to SSL target as SSL client")
#     parser.add_option("--unix-target",
#             help="connect to unix socket target", metavar="FILE")
#     parser.add_option("--web", default=None, metavar="DIR",
#             help="run webserver on same port. Serve files from DIR.")
#     parser.add_option("--wrap-mode", default="exit", metavar="MODE",
#             choices=["exit", "ignore", "respawn"],
#             help="action to take when the wrapped program exits "
#             "or daemonizes: exit (default), ignore, respawn")
#     parser.add_option("--prefer-ipv6", "-6",
#             action="store_true", dest="source_is_ipv6",
#             help="prefer IPv6 when resolving source_addr")
#     parser.add_option("--libserver", action="store_true",
#             help="use Python library SocketServer engine")
#     parser.add_option("--target-config", metavar="FILE",
#             dest="target_cfg",
#             help="Configuration file containing valid targets "
#             "in the form 'token: host:port' or, alternatively, a "
#             "directory containing configuration files of this form "
#             "(DEPRECATED: use `--token-plugin TokenFile --token-source "
#             " path/to/token/file` instead)")

#     # config file storing target credential (token: password)
#     parser.add_option("--target-credential", metavar="FILE",
#             dest="target_credential",
#             help="Configuration file containing valid targets credential"
#             "records in this file correspond to that in target-config file"
#             "in the form 'token: password' or, alternatively, a "
#             "directory containing configuration files of this form "
#             "(for fronware web server)")

#     # config file storing target display info (on title)
#     parser.add_option("--target-display", metavar="FILE",
#             dest='target_display',
#             help="Configuration file containing valid targets display"
#             "records in this file correspond to that in target-config file"
#             "in the form 'token: string'")

#     parser.add_option("--token-plugin", default=None, metavar="PLUGIN",
#                       help="use the given Python class to process tokens "
#                            "into host:port pairs")
#     parser.add_option("--token-source", default=None, metavar="ARG",
#                       help="an argument to be passed to the token plugin"
#                            "on instantiation")
#     parser.add_option("--auth-plugin", default=None, metavar="PLUGIN",
#                       help="use the given Python class to determine if "
#                            "a connection is allowed")
#     parser.add_option("--auth-source", default=None, metavar="ARG",
#                       help="an argument to be passed to the auth plugin"
#                            "on instantiation")
#     parser.add_option("--auto-pong", action="store_true",
#             help="Automatically respond to ping frames with a pong")
#     parser.add_option("--heartbeat", type=int, default=0,
#             help="send a ping to the client every HEARTBEAT seconds")
#     parser.add_option("--log-file", metavar="FILE",
#             dest="log_file",
#             help="File where logs will be saved")


#     (opts, args) = parser.parse_args()

#     if opts.log_file:
#         opts.log_file = os.path.abspath(opts.log_file)
#         handler = logging.FileHandler(opts.log_file)
#         handler.setLevel(logging.DEBUG)
#         handler.setFormatter(logging.Formatter("%(message)s"))
#         logging.getLogger(WebSocketProxy.log_prefix).addHandler(handler)

#     del opts.log_file

#     if opts.verbose:
#         logging.getLogger(WebSocketProxy.log_prefix).setLevel(logging.DEBUG)

#     if opts.token_source and not opts.token_plugin:
#         parser.error("You must use --token-plugin to use --token-source")

#     if opts.auth_source and not opts.auth_plugin:
#         parser.error("You must use --auth-plugin to use --auth-source")


#     # Transform to absolute path as daemon may chdir
#     if opts.target_cfg:
#         opts.target_cfg = os.path.abspath(opts.target_cfg)

#     if opts.target_cfg:
#         opts.token_plugin = 'TokenFile'
#         opts.token_source = opts.target_cfg

#     del opts.target_cfg


#     # credential file  for fronware
#     if opts.target_credential:
#         global credentials
#         opts.target_credential = os.path.abspath(opts.target_credential)
#         # credentials = CredentialFile(opts.target_credential)
#         credentials = ConfigFile(opts.target_credential)
#     del opts.target_credential


#     # Sanity checks
#     if len(args) < 2 and not (opts.token_plugin or opts.unix_target):
#         parser.error("Too few arguments")
#     if sys.argv.count('--'):
#         opts.wrap_cmd = args[1:]
#     else:
#         opts.wrap_cmd = None
#         if len(args) > 2:
#             parser.error("Too many arguments")

#     if not websocket.ssl and opts.ssl_target:
#         parser.error("SSL target requested and Python SSL module not loaded.");

#     if opts.ssl_only and not os.path.exists(opts.cert):
#         parser.error("SSL only and %s not found" % opts.cert)

#     # Parse host:port and convert ports to numbers
#     if args[0].count(':') > 0:
#         opts.listen_host, opts.listen_port = args[0].rsplit(':', 1)
#         opts.listen_host = opts.listen_host.strip('[]')
#     else:
#         opts.listen_host, opts.listen_port = '', args[0]

#     try:    opts.listen_port = int(opts.listen_port)
#     except: parser.error("Error parsing listen port")

#     if opts.wrap_cmd or opts.unix_target or opts.token_plugin:
#         opts.target_host = None
#         opts.target_port = None
#     else:
#         if args[1].count(':') > 0:
#             opts.target_host, opts.target_port = args[1].rsplit(':', 1)
#             opts.target_host = opts.target_host.strip('[]')
#         else:
#             parser.error("Error parsing target")
#         try:    opts.target_port = int(opts.target_port)
#         except: parser.error("Error parsing target port")

#     if opts.token_plugin is not None:
#         if '.' not in opts.token_plugin:
#             opts.token_plugin = (
#                 'websockify.token_plugins.%s' % opts.token_plugin)

#         token_plugin_module, token_plugin_cls = opts.token_plugin.rsplit('.', 1)

#         __import__(token_plugin_module)
#         token_plugin_cls = getattr(sys.modules[token_plugin_module], token_plugin_cls)

#         opts.token_plugin = token_plugin_cls(opts.token_source)

#         global tokens
#         tokens = opts.token_plugin

#     del opts.token_source

#     if opts.auth_plugin is not None:
#         if '.' not in opts.auth_plugin:
#             opts.auth_plugin = 'websockify.auth_plugins.%s' % opts.auth_plugin

#         auth_plugin_module, auth_plugin_cls = opts.auth_plugin.rsplit('.', 1)

#         __import__(auth_plugin_module)
#         auth_plugin_cls = getattr(sys.modules[auth_plugin_module], auth_plugin_cls)

#         opts.auth_plugin = auth_plugin_cls(opts.auth_source)

#     del opts.auth_source

#     if HandlerCls != None:
#         opts.RequestHandlerClass = HandlerCls
#     else:
#         # static file serving and websocket proxy
#         opts.RequestHandlerClass = WsWebHandler

#     # Create and start the WebSockets proxy
#     libserver = opts.libserver
#     del opts.libserver
#     if libserver:
#         # Use standard Python SocketServer framework
#         server = LibProxyServer(**opts.__dict__)
#         server.serve_forever()
#     else:
#         # Use internal service framework
#         # server = WebSocketProxy(**opts.__dict__)
#         server = WsWebServer(**opts.__dict__)
#         server.start_server()

import argparse
from .plugins import ConfigFile
def runserver2():
    parser = argparse.ArgumentParser(description='wswebserver')
    parser.add_argument('--web', action='store', type=str, dest='web',
                        default='/usr/share/novnc/', metavar='DIR',
                        help='path to novnc web folder.')
    parser.add_argument('--daemon', action='store_true', dest='daemon',
                        help='if to start in daemon mode.')
    parser.add_argument('--target-config', action='store', type=str, 
                        dest='target_config', default='/etc/websockify/tokens',
                        metavar='FILE', help='vnc target config file, which stores ip:port.') #
    parser.add_argument('--target-credential', action='store', type=str,
                        dest='target_credential', default='/etc/websockify/passwds',
                        metavar='FILE', help='target credential, which stores target vnc passwords') #
    parser.add_argument('--target-display', action='store', type=str,
                        dest='target_display', default='/etc/websockify/display',
                        metavar='FILE',
                        help='target display file, which stores display name of target vnc hosts.') #
    parser.add_argument('--log-file', action='store', type=str, dest='log_file',
                        metavar='FILE', help='') #
    parser.add_argument('--verbose', action='store_true', dest='verbose', 
                        help='verbose message') #
    parser.add_argument('--auto-pong', action='store_true', dest='auto_pong',
                        help='Automatically respond to ping frames with a pong')
    parser.add_argument('--heartbeat', action='store', type=int, dest='heartbeat',
                        default=0, metavar='INT',
                        help="send a ping to the client every HEARTBEAT seconds")

    args = parser.parse_args()

    target_config = os.path.abspath(args.target_config)
    args.token_plugin = ConfigFile(target_config)
    del args.target_config

    target_credential = os.path.abspath(args.target_credential)
    args.credential = ConfigFile(target_credential)
    del args.target_credential

    target_display = os.path.abspath(args.target_display)
    args.display = ConfigFile(target_display)
    del args.target_display

    if args.log_file:
        log_file = os.path.abspath(args.log_file)
        handler = logging.FileHandler(log_file)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger(WebSocketProxy.log_prefix).addHandler(handler)

    del args.log_file

    if args.verbose:
        logging.getLogger(WebSocketProxy.log_prefix).setLevel(logging.DEBUG)

    server = WsWebServer(**args)
    server.start_server()



if __name__ == '__main__':
    runserver2(WsWebHandler)



