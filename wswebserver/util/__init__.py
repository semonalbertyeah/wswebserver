# -*- coding:utf-8 -*-


from . import local
from . import litekv
from . import compat


__all__ = [
    'local', 'litekv', 'compat'
    'reraise_exception', 'get_caller_name'
]

import sys, inspect
from .compat import reraise

def reraise_exception(e):
    exc_type, exc_value, tb = sys.exc_info()
    reraise(exc_type, exc_value, tb)

def get_caller_name():
    return inspect.stack()[2][3]
