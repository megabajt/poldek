#!/usr/bin/python

import os
import re
import string
from types import *
import poldekmod
from poldekmod import *

class n_array_proxy:
    def __init__(self, arr, itemClass):
        self._arr = arr
        self._itemClass = itemClass

    def __nonzero__(self):
        if self._arr: return True
        return False

    def __getattr__(self, attr):
        if not self._arr:
            raise AttributeError, 'class has no attribute %s' % attr
        return getattr(self._arr, attr)

    def __len__(self):
        if self._arr: return len(self._arr)
        return 0
        
    def __getitem__(self, i):
        r = self._arr[i]
        if r: r = self._itemClass(r)
        return r

def n_array_proxy_func(prefix, func, classnam):
    return eval('lambda self, *args: n_array_proxy(poldekmod.%s%s(self, *args), %s)' % (prefix, func, classnam));
    

def _complete_class(aclass, prefix, delprefix = None, nomethods = False,
                    verbose = 0):
    regexp = re.compile('^%s' % prefix)
    regexp_up = re.compile('^%s' % string.upper(prefix))
    if delprefix:
        l = len(delprefix)
    else:
        l = len(prefix)
    for k, elem in poldekmod.__dict__.items():
        #elem = poldekmod.__dict__[k]
        if not nomethods:
            if regexp.match(k) and type(elem) == BuiltinFunctionType:
                name = k[l:]
                if not hasattr(aclass, name):
                    fn = eval('lambda self, *args: poldekmod.%s(self, *args)' % k);
                    setattr(aclass, name, fn)
                    #setattr(aclass, name, elem)
                 
                
        if regexp_up.match(k):
            name = k[l:]
            if not hasattr(aclass, name):
                setattr(aclass, name, elem)
                if verbose:
                    print "SET %s %s" % (name, type(elem))

_complete_class(tn_array, 'n_array_')
setattr(tn_array, '__getitem__', tn_array.nth)

                
_complete_class(poldek_ctx, 'poldek_')
#setattr(poldek_ctx, 'get_avail_packages', _m_get_avail_packages)
for fn in ['get_avail_packages', 'search_avail_packages']:
    setattr(poldek_ctx, fn, n_array_proxy_func('poldek_', fn, 'pkg'))
    
_complete_class(poldek_ts, 'poldek_ts_')
_complete_class(poldek_ts, 'poldek_op_', delprefix = 'poldek_',
                nomethods = True, verbose = 0)

_complete_class(pkg, 'pkg_')
setattr(pkg, '__str__', pkg.id)
_complete_class(source, 'source_')
_complete_class(pkgdir, 'pkgdir_')


_complete_class(poclidek_rcmd, 'poclidek_rcmd_')
setattr(poclidek_rcmd, 'get_packages',
        n_array_proxy_func('poclidek_rcmd_', 'get_packages', 'pkg'))

















