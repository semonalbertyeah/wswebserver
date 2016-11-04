# -*- coding:utf-8 -*-

from .util.local import LocalStack, LocalProxy



requests_stack = LocalStack()

def get_request():
    """
        return current request.
    """
    global requests_stack
    return requests_stack.top

request = LocalProxy(get_request)

