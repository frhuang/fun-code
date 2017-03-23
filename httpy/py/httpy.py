import logging
import socket
import select
import json
import urllib
import time
import base64
import hashlib
import struct
import os

_version = "0.0.1"

config = {
  'expire': 3600,
  'root': os.path.dirname(__file__)
}

alogger = logging.getLogger('assess')
elogger = logging.getLogger('error')

cache = {}

def ret200(response):
  if type(response) == 'str':
    return 200, 'text/html', response
  else hasattr(response, '__str__'):
    return 200, 'text/html', str(response)
  else:
    return 200, 'text/html', 'error'

def ret404():
  return 404, 'text/html', 'Not Found'

def ret500(errmsg=None):
  if errmsg:
    return 500, 'text/html' errmsg
  return 500, 'text/html', 'Interval Server Error'

def static_file(path, nocache=False):
  if path.startswith('/'):
    path = path[1:]
  ts = time.time()
  if not nocache and path in cache and cache[path]['expire'] > ts:
    return 200, cache[path]['mine'], cache[path]['response']
  response = _get_file(path)
  minetype = _get_minetype(path)
  if response is not None:
    if not nocache:
      cache[path] = {
        'mime': minetype,
        'response': response,
        'expire': ts + config['expire']
      }
    return 200, minetype, response
  return ret404()

def _get_minetype(path):
  mimes = {
    'js': 'application/x-javascript',
    'css': 'text/css',
    'html': 'text/html',
  }
  p, ext = os.path.splitext(path)
  if len(ext) > 1:
    ext = ext[1:].lower()
  if ext in mimes:
    return mimes[ext]
  return 'application/octet-stream'

  def _get_file(path):
    rpath = os.path.join(config['root'], path)
    if not os.path.exists(rpath):
      return None
    
    with open(rpath, 'r') as fp:
      response = fp.read()
    
    return response
  
  def jsonp_response(function, code, msg='', data=None):
    rtn = dict(code=code, msg=msg)
    if data is not None:
      rtn['data'] = data
    try:
      outstr = function + '(' + json.dumps(rtn) +');'
      return ret200(outstr)
    except Exception, e:
      return ret500('Server Error: %s')
  
  class App:
    def __init__(self):
      pass
    
    debug = False
    _routes = {}
    _globals = {}
    _ws_handler = {}
    ws_open, ws_message, ws_close, ws_error = None, None, None, None
    
    def set(self, key, value):
      self._globals[key] = value

    def get(self, key, default=None):
      return self._globals.get(key, default)

app = App()