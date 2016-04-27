from wswebserver import WsWebHandler, runserver, HTTPError


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
        raise HTTPError(403, 'Require UUID')

    token = str(uuid)
    target_host_info['token'] = '"%s"' % token

    if _token_plugin is None:
        raise HTTPError(400, 'Token file is not used.')

    if _token_plugin.lookup(token) is None:
        raise HTTPError(403, 
            'UUID \"%s\" does not exist' % str(token))

    if _credential_plugin is not None:
        passwd = _credential_plugin.lookup(token)
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
            raise HTTPError(404, 'vnc_auto.html does not exist.')
        else:
            raise e
 