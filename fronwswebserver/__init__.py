# -*- coding:utf-8 -*-
"""
    fronware websocket server logic.
"""

import os
from string import Template


from wswebserver import (
    WsWebHandler, runserver,
    runserver, abort,
    get_caller_name
)
from wswebserver.litekv import ALiteKV
import wswebserver


if os.geteuid() == 0:
    db_name = '/var/tmp/fronws.db'
else:
    db_name = 'fronws.db'
tab_name = 'wsconnection'

db = ALiteKV(filename=db_name, table=tab_name)


import httplib, urlparse
def http_request(url, method='GET', payload='', headers={}):
    """
        Do an http request.
        return an httplib.HTTPResponse instance.
    """
    url = urlparse.urlparse(url)
    path = "%s?%s" % (url.path, url.query)
    conn = httplib.HTTPConnection(url.hostname, url.port)
    conn.request(method, path, payload, headers)
    resp = conn.getresponse()
    conn.close()
    return resp

def response_dumps(resp):
    """
        return a dumped string of httplib.HTTPResponse instance.
    """
    return """status %d, %s
headers: %r
--- content ---
%s
--- content ---""" % (
        resp.status, resp.reason,
        resp.getheaders(),
        resp.read()
        )



class App(WsWebHandler):
    pass


########################
# registered handlers
########################

@App.finished
def report_ws_end(req):
    """
        report end of websocket connection to main server.
    """
    global db
    data = """<DisconnectNovnc><ConnectTicket>%s</ConnectTicket></DisconnectNovnc>"""
    # host_ip = req.client_address[0]
    host_ip = 'localhost'
    port = 80
    # path = r'/RestService/Virtualmachine/GetVncIPPortPasswdForVM'
    path = r'/RestService/DisconnectNovnc'
    target_url = 'http://%s:%d%s' % (host_ip, port, path)
    if req.ws_connection:
        ticket = db.pop(req.token)  # read and delete
        if ticket:
            # ticket is only for fronware
            data = data % ticket
            resp = http_request(target_url, 'POST', data)
            if resp.status != 200:
                loginfo = response_dumps(resp)
                req.log_error("\n%s\n%s", target_url, loginfo)
            resp.close()


######################
#   urls
######################

# must be prior to /vnc?uuid=xxx
@App.route(r'^/fap\?uuid=(?P<uuid>.+)&connectTicket=(?P<connectTicket>.+)$')
@App.route(r'^/vnc\?uuid=(?P<uuid>.+)&connectTicket=(?P<connectTicket>.+)$')
def vnc_handler_lanzhou(uuid=None, connectTicket=None):
    global db
    assert uuid is not None and connectTicket is not None

    db.set(uuid, connectTicket)
    return vnc_handler(uuid=uuid)


@App.route(r'^/vnc(\?uuid=(?P<uuid>.+))?$')
@App.route(r'^/fap(\?uuid=(?P<uuid>.+))?$')
def vnc_handler(uuid=None):
    """
        get vnc credential according to uuid
        put credential info into vnc_auto.html with template
        return templated vnc_auto.html
    """

    target_host_info = {'path': r'""', 'token': r'""', 'password': '""'}

    if uuid is None:
        abort(403, 'Require UUID')

    token = str(uuid)
    target_host_info['token'] = '"%s"' % token

    if wswebserver.tokens is None:
        abort(400, 'Token file is not used.')

    if wswebserver.tokens.lookup(token) is None:
        abort(403,  'UUID \"%s\" does not exist' % str(token))

    if wswebserver.credentials is not None:
        passwd = wswebserver.credentials.lookup(token)
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


# ---------------- tests ---------------------
# below are just test
# @App.errorhandler(KeyError)
# def keyerror_handler(e):
#     print '---- KeyError handler ----'
#     return e.message, 400, {}


# @App.errorhandler(501)
# def err_501_handler(e):
#     return 'error handler 501'


@App.route(r'/test/', methods=['POST', 'GET'])
def test():
    # abort(501)
    print 'test handler, registered method: GET, POST'
    #raise KeyError, "test KeyError message"
    # return 'just a test value.'
    return 'test data.'


def run():
    runserver(App)

if __name__ == '__main__':
    run()
