# -*- coding:utf-8 -*-
"""
    fronware websocket server logic.
"""

import os
from string import Template


from wswebserver import (
    WsWebHandler,
    runserver, abort,
    request,
    msg, debug, warn
)
from wswebserver.util import get_caller_name
# from wswebserver.util.litekv import ALiteKV

# if os.geteuid() == 0:

#     db_name = '/var/tmp/fronws.db'
# else:
#     db_name = 'fronws.db'
# tab_name = 'wsconnection'


# import httplib, urlparse
# def http_request(url, method='GET', payload='', headers={}):
#     """
#         Do an http request.
#         return an httplib.HTTPResponse instance.
#     """
#     url = urlparse.urlparse(url)
#     path = "%s?%s" % (url.path, url.query)
#     conn = httplib.HTTPConnection(url.hostname, url.port)
#     conn.request(method, path, payload, headers)
#     resp = conn.getresponse()
#     conn.close()
#     return resp

# def response_dumps(resp):
#     """
#         return a dumped string of httplib.HTTPResponse instance.
#     """
#     return """status %d, %s
# headers: %r
# --- content ---
# %s
# --- content ---""" % (
#         resp.status, resp.reason,
#         resp.getheaders(),
#         resp.read()
#         )



class App(WsWebHandler):
    pass


########################
# registered handlers
########################

# @App.finished
# def report_ws_end_lanzhou(req):
#     """
#         report end of websocket connection to main server.
#     """
#     # global db
#     db = ALiteKV(filename=db_name, table=tab_name)
#     data = """<DisconnectNovnc><ConnectTicket>%s</ConnectTicket></DisconnectNovnc>"""
#     # host_ip = req.client_address[0]
#     host_ip = 'localhost'
#     port = 80
#     # path = r'/RestService/Virtualmachine/GetVncIPPortPasswdForVM'
#     path = r'/RestService/DisconnectNovnc'
#     target_url = 'http://%s:%d%s' % (host_ip, port, path)
#     if req.ws_connection:
#         ticket = db.pop(req.token)  # read and delete
#         if ticket:
#             # ticket is only for fronware
#             data = data % ticket
#             resp = http_request(target_url, 'POST', data)
#             if resp.status != 200:
#                 loginfo = response_dumps(resp)
#                 req.log_error("\n%s\n%s", target_url, loginfo)
#             resp.close()


######################
#   urls
######################

# # must be prior to /vnc?uuid=xxx
# @App.route(r'^/fap\?uuid=(?P<uuid>.+)&connectTicket=(?P<connectTicket>.+)$')
# @App.route(r'^/vnc\?uuid=(?P<uuid>.+)&connectTicket=(?P<connectTicket>.+)$')
# def vnc_handler_lanzhou(uuid=None, connectTicket=None):
#     # global db
#     db = ALiteKV(filename=db_name, table=tab_name)
#     assert uuid is not None and connectTicket is not None

#     db.set(uuid, connectTicket)
#     return vnc_handler(uuid=uuid)


@App.route(r'^/vnc(\?uuid=(?P<uuid>.+))?$')
@App.route(r'^/fap(\?uuid=(?P<uuid>.+))?$')
def vnc_handler(uuid=None):
    """
        get vnc credential according to uuid
        put credential info into vnc_auto.html with template
        return templated vnc_auto.html
    """

    target_host_info = {
        'path': r'""', 
        'token': r'""', 
        'password': '""',
        'display': '""'
    }

    if uuid is None:
        abort(403, 'Require UUID')

    token = str(uuid)
    target_host_info['token'] = '"%s"' % token

    if request.targets is None:
        abort(400, 'Token file is not used.')

    if request.targets.get(token, None) is None:
        abort(403,  'UUID \"%s\" does not exist' % str(token))

    display = request.targets[token]
    if request.target_display:
        display = request.target_display.get(token, None) or display
    target_host_info['display'] = '"%s"' %display

    if request.target_credential:
        passwd = request.target_credential.get(token, None)
        if passwd is not None:
            target_host_info['password'] = '"%s"' % passwd


    try:
        # template is vnc_fronware.html at the root of web
        with open('vnc_fronware.html') as f:
            content = f.read()
            # safe_substitue -> ignore $id which is not present in keywords
            content = Template(content).safe_substitute(target_host_info) 
            return content
    except IOError, e:
        if e.errno == 2:
            abort(404, 'vnc_auto.html does not exist.')
        else:
            raise e


@App.route(r'^/spice/spice(\?uuid=(?P<uuid>.+))?$')
def spice_handler(uuid=None):
    """
        templated variables
    """

    target_host_info = {
        'path': r'', 
        'token': r'', 
        'password': '',
        'display': ''
    }

    if uuid is None:
        abort(403, 'Require UUID')

    token = "%s_%s" % (str(uuid), 'spice')
    target_host_info['token'] = token

    if request.targets is None:
        abort(400, 'Token file is not used.')

    if request.targets.get(token, None) is None:
        abort(403,  'UUID \"%s\" does not exist' % str(uuid))

    display = 'spice-%s' % request.targets[token]
    if request.target_display:
        display = request.target_display.get(token, None) or display
    target_host_info['display'] = display

    if request.target_credential is None:
        abort(400, 'Credential file is not used.')

    passwd = request.target_credential.get(token, None)
    if passwd is None:
        abort(403, 'no credential info for UUID \"%s\"' % str(uuid))
    target_host_info['password'] = passwd

    try:
        with open('spice/spice_auto_templated.html') as f:
            content = f.read()
            # safe_substitue 
            #   -> ignore template variable (start with '$') not present in template data.
            content = Template(content).safe_substitute(target_host_info) 
            return content
    except IOError, e:
        if e.errno == 2:
            abort(404, 'spice/spice_auto_templated.html does not exist.')
        else:
            raise e


# def update_token(new_rec, fn='/etc/websockify/tokens'):
#     """
#         update tokens file
#         input:
#             rec -> {
#                 'token': str,
#                 'ip': ip_str,
#                 'port': int
#             }
#     """
#     with open(fn, 'r') as f:
#         lines = f.readlines()
#         old_recs = filter(lambda l: l.startswith(new_rec['token']), lines)
#         if old_recs:
#             for rec in old_recs:
#                 lines.remove(rec)
#         lines.append('%s: %s:%s\n' % (new_rec['token'], new_rec['ip'], new_rec['port']))

#     with open(fn, 'w') as f:
#         f.writelines(lines)


# def update_credential(new_rec, fn='/etc/websockify/passwds'):
#     """
#         update passwds file
#         input:
#             rec -> {
#                 'token': str,
#                 'password': str
#             }
#     """
#     with open(fn, 'r') as f:
#         lines = f.readlines()
#         old_recs = filter(lambda l: l.startswith(new_rec['token']), lines)
#         if old_recs:
#             for rec in old_recs:
#                 lines.remove(rec)
#         lines.append('%s: %s\n' % (new_rec['token'], new_rec['password']))

#     with open(fn, 'w') as f:
#         f.writelines(lines)

# def update_display(new_rec, fn='/etc/websockify/display'):
#     """
#         update display info about vnc target.
#         input:
#             new_rec -> {
#                 'token': str,
#                 'display': str or unicode,
#             }
#     """
#     with open(fn, 'r') as f:
#         lines = f.readlines()
#         old_recs = filter(lambda l: l.startswith(new_rec['token']), lines)
#         if old_recs:
#             for rec in old_recs:
#                 lines.remove(rec)
#         lines.append('%s: %s\n' % (new_rec['token'], new_rec['display']))

# @App.route(r'^/config$', methods=['POST', "DELETE"])
@App.route(r'^/config(\?uuid=(?P<uuid>.+))?$', methods=['POST', "DELETE"])
def config(uuid=None):
    """
        update a token
    """
    if request.method == 'POST':
        token = request.data['uuid']
        ip = request.data.get('ip', None)
        port = request.data.get('port', None)
        password = request.data.get('password', None)
        display = request.data.get('display', None)

        if ip and port:
            request.targets[token] = '%s:%s' % (ip, port)

        if password:
            request.target_credential[token] = password

        if display:
            request.target_display[token] = display

        return 'ok'

    elif request.method == 'DELETE':
        if uuid is None:
            abort(404, "uuid is required.")
        if uuid in request.targets:
            del request.targets[uuid]

        if uuid in request.target_display:
            del request.target_display[uuid]

        if uuid in request.target_credential:
            del request.target_credential[uuid]

        return 'ok'

# ---------------- tests ---------------------
# below are just test
# @App.errorhandler(KeyError)
# def keyerror_handler(e):
#     print '---- KeyError handler ----'
#     return e.message, 400, {}


# @App.errorhandler(501)
# def err_501_handler(e):
#     return 'error handler 501'


@App.route(r'/test/.*', methods=['POST', 'GET'])
def test():
    # abort(501)
    # print 'test handler, registered method: GET, POST'
    # raise KeyError, "test KeyError message"
    # return 'just a test value.'
    print 'request'
    print 'request.command:', request.command
    print 'request.path:', request.path
    print 'request.request_version:', request.request_version
    print 'request.headers:', dict(request.headers)
    print 'request.protocol_version:', request.protocol_version
    print 'request.requestline:', request.requestline
    print 'request.server_version:', request.server_version
    print 'request.sys_version:', request.sys_version
    print 'request.client_address:', request.client_address
    print 'request.args:', request.args
    print 'request.token:', request.token
    print 'request.ws_connection:', request.ws_connection

    print '---- message body ----'
    print 'request.body:', repr(request.body)
    print 'request.content_length:', repr(request.content_length)
    print 'request.content_type:', repr(request.content_type)
    print 'request.data:', repr(request.data)
    print 'request.json:', repr(request.json)
    print 'request.request:', request.request

    print '---- all request attributes ----'
    print repr(dir(request._get_current_object()))

    return 'OK'


def run():
    runserver(App)

if __name__ == '__main__':
    run()
