from string import Template

from wswebserver import (
    WsWebHandler, runserver,
    runserver, abort
)
import wswebserver

class App(WsWebHandler):
    pass

# ----- urls -----
@App.route(r'^/vnc(\?uuid=(?P<uuid>.+))?$')
@App.route(r'^/fap(\?uuid=(?P<uuid>.+))?$')
def vnc_handler(uuid=None):
    """
        get vnc credential according to uuid
        put credential info into vnc_auto.html with template
        return templated vnc_auto.html
    """

    # print '=============== vnc_handler'    # del line
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

    # print 'target host:', target_host_info

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

# below are just test
@App.errorhandler(KeyError)
def keyerror_handler(e):
    print '---- KeyError handler ----'
    return e.message, 400, {}


@App.errorhandler(501)
def err_501_handler(e):
    return 'error handler 501'


@App.route(r'/test/')
def test():
    # abort(501)
    raise KeyError, "test KeyError message"
    # return 'just a test value.'


def run():
    runserver(App)

if __name__ == '__main__':
    run()