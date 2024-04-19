#!/usr/bin/env python


"""
Birdwing's FCGI server.  Handles auth/put/camera requests

We handle all requests in a single FCGI server to minimize the number of
FCGI servers running on the machine.
"""

import datetime
import dbm
from flup.server.fcgi import WSGIServer
from flup.server.fcgi_base import BaseFCGIServer
from functools import reduce
from html import escape
import inspect
import json
import kaiten.jsonrpc
import kaiten.address
import kaiten.decorator
import os
import random
import select
import string
import struct
import sys
import threading
import time
import traceback
import urllib.parse

valid_response_types = ['code', 'token', 'answer', 'thingiverse_token']
valid_client_ids = ['MakerWare', 'host-driver']
valid_contexts = ['jsonrpc', 'put', 'camera']
codelen = 32

# Time in seconds in-between responses - We rate limit responses
# to avoid spiking CPU & affecting printing
response_interval = 1.5

class ParamError(Exception):
    def __init__(self, name, val=None, extra=False):
        self._name = name
        self._val = val
        self._extra = extra

    def __str__(self):
        if None is not self._val:
            return 'Invalid value: '+self._name+'='+self._val
        elif self._extra:
            return 'Invalid parameter: '+self._name
        else:
            return 'Missing parameter: '+self._name

def checkparams(func):
    """
    Raise a ParamError if the kwargs do not match what function expects.
    Annotataions, if present, must indicate a list of allowable values.
    The decorated function must not have a *args parameter.
    """
    params = inspect.signature(func).parameters
    def decorator(*args, **kwargs):
        arg_set = set(kwargs)
        for param in list(params)[len(args):]:
            if params[param].kind == inspect.Parameter.VAR_KEYWORD: break
            has_default = params[param].default != inspect.Parameter.empty
            if param not in arg_set and not has_default:
                raise ParamError(param)
            if param not in arg_set: continue
            has_annotation = params[param].annotation != inspect.Parameter.empty
            if has_annotation and kwargs[param] not in params[param].annotation:
                raise ParamError(param, kwargs[param])
            arg_set -= {param}
        else:
            for param in arg_set:
                raise ParamError(param, extra=True)
        return func(*args, **kwargs)
    return decorator

class AccessError(Exception):
    def __init__(self, name, val):
        self._name = name
        self._val = val

    def __str__(self):
        return 'Access denied: '+self._name+'='+self._val

def catch_fcgi_errors(func):
    """ Catch exceptions thrown in fcgi handlers and yield an error response """
    def decorator(*args, **kwargs):
        start_response = args[2]
        try:
            return (yield from func(*args, **kwargs))
        except ParamError as e:
            start_response('400 Bad Request', [('Content-Type',
                                                'application/json')])
            yield json.dumps({'status': 'error',
                              'message': str(e)})
        except AccessError as e:
            start_response('401 Access Denied', [('Content-Type',
                                                'application/json')])
            yield json.dumps({'status': 'error',
                              'message': str(e)})
        except Exception as e:
            start_response('500 Internal Server Error', [('Content-Type',
                                                          'application/json')])
            yield json.dumps({'status': 'error',
                              'message': traceback.format_exc()})
    return decorator

class TokenStore(object):
    def __init__(self):
       self._tokens = {}
       self._lock = threading.Lock()

    def add_token(self, token, context):
        with self._lock:
            self._tokens[token] = context

    def consume_token(self, token, context):
        with self._lock:
            if token in self._tokens and self._tokens[token] == context:
                self._tokens.pop(token)
            else:
                raise AccessError('token', token)

    def clear(self):
        with self._lock:
            self._tokens.clear()


class ResponseRateLimiter(object):
    """
    ResponseRateLimiter can be used as a global rate-limiter to limit the
    response rate between all FCGI threads.  This can be useful for limiting
    CPU usage.
    """
    def __init__(self, rate_in_seconds):
        self._lock = threading.Lock()
        self._last_block_timestamp = 0
        self._rate_in_seconds = rate_in_seconds

    def block_if_necessary(self):
        with self._lock:
            time_delta = time.time() - self._last_block_timestamp
            if time_delta < self._rate_in_seconds:
                time.sleep(self._rate_in_seconds - time_delta)
            self._last_block_timestamp = time.time()


def parse_qs(query):
    results = urllib.parse.parse_qs(query)
    for key in results:
        if len(results[key]) is 1:
            results[key] = results[key][0]

    return results


class JsonRpcThread(threading.Thread):
    """
    Handle all JSONRPC communication with kaiten
    """
    def __init__(self):
        threading.Thread.__init__(self)
        self._jsonrpc = None
        self._installers = []
        self._install_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self.__stop = False
        # Add a pipe to wake up the poll thread when we halt
        self._stop_read, self._stop_write = os.pipe()

    def _connect_jsonrpc(self):
        self._address_string = 'pipe:/tmp/kaiten.socket'
        self._address = kaiten.address.Address.address_factory(
            self._address_string)
        self._connection = self._address.connect()
        self._fileno = self._connection.fileno()
        self._poll = select.poll()
        self._poll.register(self._fileno, select.POLLIN)
        self._poll.register(self._stop_read, select.POLLIN)
        def run(generator):
            for dummy in generator:
                pass
        with self._install_lock:
            self._jsonrpc = kaiten.jsonrpc.JsonRpc(self._connection, run)
            for installer in self._installers:
                kaiten.jsonrpc.install(self._jsonrpc, installer)
        self._run_jsonrpc = self._jsonrpc.run()
        self._sync_jsonrpc_request('handshake', {})
        self._sync_jsonrpc_request('register_fcgi', {})

    def install(self, installer):
        with self._install_lock:
            self._installers.append(installer)
            if self._jsonrpc:
                kaiten.jsonrpc.install(self._jsonrpc, installer)

    def _check_jsonrpc_result(self, result):
        if 'error' in result:
            error = result['error']
            if 'data' not in error:
                error['data'] = None
            error = dict((k, error[k]) for k in ('code', 'message', 'data'))
            raise kaiten.jsonrpc.JsonRpcException(**error)
        return result.get('result')

    def jsonrpc_notify(self, method, params):
        with self._send_lock:
            for x in self._jsonrpc.notify(method, params): pass

    def async_jsonrpc_request(self, request, params, callback):
        with self._send_lock:
            for x in self._jsonrpc.request(request, params, callback): pass

    def _sync_jsonrpc_request(self, request, params):
        """ For internal use while the main listen loop is not running """
        result = None
        def done(res):
            nonlocal result
            result = res
        self.async_jsonrpc_request(request, params, done)
        while not self.__stop and result is None:
            self._response_wait()
        return self._check_jsonrpc_result(result)

    def sync_jsonrpc_request(self, request, params):
        """ For external use by other threads """
        result = None
        wait = threading.Semaphore(value=0)
        def done(res):
            nonlocal result
            result = res
            wait.release()
        self.async_jsonrpc_request(request, params, done)
        wait.acquire() # Block until done() is called
        return self._check_jsonrpc_result(result)

    def _response_wait(self):
        while True:
            events = [e for (f, e) in self._poll.poll() if f == self._fileno]
            if events: break
            if self.__stop: return
        event = reduce(lambda x,y: x | y, events)
        if event != select.POLLIN:
            raise Exception('Broken socket connection')
        next(self._run_jsonrpc)

    def run(self):
        count = 0
        while True:
            try:
                self._connect_jsonrpc()
            except Exception as e:
                if self.__stop: return
                # Retry forever, but don't spam the terminal forever
                if count < 5:
                    print('FCGI connection to jsonrpc failed, retrying')
                    count += 1
                time.sleep(1)
                continue
            try:
                while True:
                    if self.__stop: return
                    self._response_wait()
            except Exception as e:
                if self.__stop: return
                print('Exception in JsonRpcThread, restarting\n%s'%
                      traceback.format_exc())
                time.sleep(1)
                count = 3

    def stop(self):
        self.__stop = True
        # Make sure we wake up the polling thread
        os.write(self._stop_write, b'\n')
        try:
            self._connection.close()
        except:
            pass


class CameraHandler(object):

    def __init__(self, json_thread, token_store, rate_limiter):
        self._token_store = token_store
        self._rate_limiter = rate_limiter
        self._json_thread = json_thread
        json_thread.install(self)
        self._frame = None
        self._frame_wait = threading.Semaphore(value=0)

    @catch_fcgi_errors
    def run(self, environ, start_response):
        # Ensure enough time has elapsed in-between requests
        if self._rate_limiter is not None:
            self._rate_limiter.block_if_necessary()

        # Check if a valid token was supplied
        params = parse_qs(environ['QUERY_STRING'])
        self._check_auth(**params)

        if self._json_thread.sync_jsonrpc_request('request_camera_frame', {}):
            self._frame_wait.acquire()

        start_response('200 OK', [('Content-Type', 'application/octet-stream')])
        yield self._frame

    @checkparams
    def _check_auth(self, token):
        self._token_store.consume_token(token, 'camera')

    @kaiten.decorator.jsonrpc
    @kaiten.decorator.jsonrpc_immediate
    def camera_frame(self):
        def raw_handler():
            data = b''
            while len(data) < 4:
                data += yield
            length = struct.unpack('!I', data[:4])[0]
            while len(data) < length:
                data += yield
            self._frame = data[:length]
            self._frame_wait.release()
            if length > len(data): yield data[length:]
        self._json_thread._jsonrpc.set_raw_handler(raw_handler())

class PutHandler(object):

    def __init__(self, json_thread, token_store):
        self._json_thread = json_thread
        self._token_store = token_store

    def _progress(self, local_path, progress, done=False):
        params = {
            'local_path' : local_path,
            'progress' : progress,
            'done' : done,
        }
        self._json_thread.jsonrpc_notify('transfer_progress', params)

    @catch_fcgi_errors
    def run(self, environ, start_response):
        """
        Handles PUT requests.  We choose not to use the file iterator here,
        since it iterates on input lines, and we could potentially try to read
        in a huge amount of information and crash the python interrpreter.
        """
        size = int(environ['CONTENT_LENGTH'])
        # _progress cannot be called more frequently than every 32768 bytes,
        # so do not decrease the buffer size below this without altering how
        # often _progress is called.
        buffer_size = 32768
        # _progress also has to be called frequently enough to avoid timeouts
        progress_timeout = datetime.timedelta(0, 2)
        progress_time_next = datetime.datetime.now() + progress_timeout
        progress = 0
        (path, query_string) = urllib.parse.unquote(environ["REQUEST_URI"]).split('?')
        params = parse_qs(query_string)

        self._check_auth(**params)
        # Chroot the provided path to /home (DO NOT os.path.join this)
        full_path = os.path.normpath('/home' + os.path.abspath('/' + path))
        self._progress(full_path, 0)
        written = 0
        with open(bytes(full_path, "UTF-8"), "wb") as f:
            while True:
                read_data = environ["wsgi.input"].read(buffer_size)
                # If we read the empty string, we no longer have data to read
                if not read_data:
                    break
                f.write(read_data)
                written += len(read_data)
                new_progress = int((written * 100) / size)
                if new_progress != progress or \
                   datetime.datetime.now() > progress_time_next:
                    progress = new_progress
                    self._progress(full_path, progress)
                    progress_time_next = datetime.datetime.now() + progress_timeout
        # We now want to make sure we wrote the correct amount of bytes
        if size != os.stat(full_path).st_size:
            raise IOError
        self._progress(full_path, 100, done=True)
        start_response('200 OK', [('Content-Type', 'text/html')])
        yield "<h1>BirdWing FastCGI</h1>\n"
        yield "Successfully uploaded file %s" % (environ["REQUEST_URI"])

    @checkparams
    def _check_auth(self, token):
        self._token_store.consume_token(token, 'put')

class AuthHandler(object):

    def __init__(self, json_thread, token_store, rate_limiter):
        self._json_thread = json_thread
        json_thread.install(self)
        self._sysrand = random.SystemRandom()
        self._answers = {}
        self._token_store = token_store
        self._rate_limiter = rate_limiter
        print('FCGIServer rand test: %s'% self._randstring())

    def _sync_jsonrpc_request(self, request, params):
        return self._json_thread.sync_jsonrpc_request(request, params)

    def _async_jsonrpc_request(self, request, params, callback):
        self._json_thread.async_jsonrpc_request(request, params, callback)

    @catch_fcgi_errors
    def run(self, environ, start_response):
        """
        Handles the oauth authentication
        """

        # Ensure enough time has elapsed in-between requests
        if self._rate_limiter is not None:
            self._rate_limiter.block_if_necessary()

        params = parse_qs(environ['QUERY_STRING'])
        yield from self._dispatch(start_response, **params)

    @checkparams
    def _dispatch(self, start_response, response_type:valid_response_types,
                  client_id:valid_client_ids, **kwargs):
        kwargs['client_id'] = client_id
        if response_type == 'code':
            yield from self._handle_auth_code(start_response, **kwargs)
        elif response_type == 'token':
            yield from self._handle_access_token(start_response, **kwargs)
        elif response_type == 'answer':
            yield from self._handle_answer_check(start_response, **kwargs)
        elif response_type == 'thingiverse_token':
            yield from self._handle_thingiverse_token(start_response, **kwargs)

    @checkparams
    def _handle_auth_code(self, start_response, client_id, client_secret,
                          username='Anonymous', thingiverse_token=None,
                          do_chamber_blink=False):
        answer_code = self._randstring()
        self._answers[answer_code] = {'client_id': client_id,
                                'client_secret': client_secret,
                                'thingiverse_token': thingiverse_token,
                                'username': username,
                                'answer': 'pending'}
        if thingiverse_token:
            self._maybe_thingiverse_token_authorize(thingiverse_token,
                                                    username, answer_code,
                                                    do_chamber_blink)
        else:
            self._start_lcd_authorize(username, answer_code, do_chamber_blink)
        self._start_json(start_response)
        yield json.dumps({'status': 'ok',
                          'answer_code': answer_code,
                          'username': username,
                          'client_id': client_id})

    @checkparams
    def _handle_answer_check(self, start_response, answer_code,
                             client_id, client_secret):
        if answer_code not in self._answers:
            raise AccessError('answer_code', answer_code)
        answer = self._answers[answer_code]
        self._check_client(client_id, client_secret, answer)

        response = {'username': answer['username'],
                    'answer': answer['answer']}
        if answer['answer'] == 'accepted':
            self._answers.pop(answer_code)
            response['code'] = answer['code']

        self._start_json(start_response)
        yield json.dumps(response)

    @checkparams
    def _handle_access_token(self, start_response, auth_code,
                             context:valid_contexts, client_id, client_secret):
        params = {'local_secret': client_secret, 'local_code': auth_code}
        try:
            result = self._sync_jsonrpc_request('fcgi_reauthorize', params)
        except kaiten.jsonrpc.JsonRpcException:
            raise AccessError('auth_code', auth_code)
        one_time_token = result['one_time_token']
        username = result['username']

        # We have registered a token with kaiten for authentication, but
        # if the context is not jsonrpc this is not what we want, so we
        # unregister the token there and register it here instead.
        if context != 'jsonrpc':
            params = {'access_token': one_time_token}
            self._sync_jsonrpc_request('authenticate', params)
            self._token_store.add_token(one_time_token, context)

        self._start_json(start_response)
        yield json.dumps({'username': username,
                          'access_token': one_time_token,
                          'status': 'success'})

    @checkparams
    def _handle_thingiverse_token(self, start_response, auth_code, username,
                                  thingiverse_token, client_id, client_secret):
        # The username here is the makerbot account username, which does
        # not necessarily match the local auth username.  So we still
        # need to use fgci_reauthorize here.
        params = {'local_secret': client_secret, 'local_code': auth_code}
        try:
            result = self._sync_jsonrpc_request('fcgi_reauthorize', params)
        except kaiten.jsonrpc.JsonRpcException:
            raise AccessError('auth_code', auth_code)

        params = {'username': username, 'makerbot_token': thingiverse_token}
        self._sync_jsonrpc_request('add_makerbot_account', params)

        self._start_json(start_response)
        yield json.dumps({'status': 'success'})

    def _check_client(self, client_id, client_secret, record):
        """ Verify that the client info matches the given auth record """
        if client_id != record['client_id']:
            raise AccessError('client_id', client_id)
        if client_secret != record['client_secret']:
            raise AccessError('client_secret', client_secret)

    def _randstring(self):
        return ''.join(self._sysrand.choice(string.ascii_letters)
                       for x in range(codelen))

    def _start_json(self, start_response):
        start_response('200 OK', [('Content-Type', 'application/json')])

    def _pack_dbval(self, unpacked):
        return '&'.join([key+'='+val for key, val in unpacked.items()])

    def _unpack_dbval(self, packed):
        return dict([pair.split('=') for pair in packed.decode().split('&')])

    def _maybe_thingiverse_token_authorize(self, thingiverse_token,
                                           username, answer_code,
                                           do_chamber_blink):
        answer = self._answers[answer_code]
        def add_local_callback(result):
            local_code = result.get('result')
            if isinstance(local_code, str):
                answer['code'] = local_code
                answer['answer'] = 'accepted'
            else:
                answer['answer'] = 'error'
        def reauth_callback(result):
            # If thingiverse token wasn't found, fall back to authorizing
            # using the knob
            if not result.get('result'):
                self._start_lcd_authorize(
                    username, answer_code, do_chamber_blink)
                # The answer dict can stay pending
            else:
                local_secret = answer['client_secret']
                params = {'username': username, 'local_secret': local_secret}
                self._async_jsonrpc_request(
                    'add_local_auth', params, add_local_callback)
        params = {
            'username': username,
            'makerbot_token': thingiverse_token,
        }
        self._async_jsonrpc_request(
            'reauthorize', params, reauth_callback)

    def _start_lcd_authorize(self, username, answer_code, do_chamber_blink):
        answer = self._answers[answer_code]
        def callback(result):
            local_code = result.get('result', {}).get('local_code')
            error_code = result.get('error', {}).get('code')
            if isinstance(local_code, str):
                answer['code'] = local_code
                answer['answer'] = 'accepted'
            elif error_code == 25:
                answer['answer'] = 'rejected'
            elif error_code == 26:
                answer['answer'] = 'timedout'
            else:
                answer['answer'] = 'error'
        params = {
            'username': username,
            'makerbot_token': answer['thingiverse_token'],
            'local_secret': answer['client_secret'],
            'chamber_blink': do_chamber_blink,
        }
        self._async_jsonrpc_request('authorize', params, callback)

    @kaiten.decorator.jsonrpc
    def auth_count(self):
        """ Count the number of auth tokens stored """
        return len(self._sync_jsonrpc_request('get_authorized',{}))

    @kaiten.decorator.jsonrpc
    def reset_auth(self):
        """ Clear out all stored auth_codes and tokens """
        def done(res):
            # we don't really need to wait for the clear_authorized to finish
            # for some reason it occasionally causes a hang when called
            # with a sync request
            pass
        self._async_jsonrpc_request('clear_authorized', {}, done)
        self._token_store.clear()
        self._answers.clear()

class FCGIThread(threading.Thread):
    def __init__(self, handler, port):
        self.wsgi = WSGIServer(handler.run, bindAddress=('127.0.0.1', port))
        super(FCGIThread, self).__init__()

    def run(self):
        self.wsgi.run()

    def stop(self):
        self.wsgi.stop()


class SingleFCGIThread(threading.Thread):
    """
    SingleFCGIThread is similar to FCGIThread, except the WSGIServer server is
    started in non-multithreaded mode, so each new request does not spawn a new thread.
    Because all requests are processed in the same thread, it is possible to limit
    the rate of requests by sleeping the thread.

    This is often necessary to ensure CPU usage is kept low during a print.
    """
    def __init__(self, handler, port):
        self.wsgi = WSGIServer(handler.run, bindAddress=('127.0.0.1', port),
                               multithreaded=False, debug=False)
        super(SingleFCGIThread, self).__init__()

    def run(self):
        self.wsgi.run()

    def stop(self):
        self.wsgi.stop()


class Server(object):
    """
    Main server object that starts/stops/joins all necessary threads.
    Not a thread itself because that would be stupid
    """
    def __init__(self, *args, **kwargs):
        super(Server, self).__init__(*args, **kwargs)
        self._threads = []

        token_store = TokenStore()
        rate_limiter = ResponseRateLimiter(response_interval)
        json_thread = JsonRpcThread()
        self._threads.append(json_thread)

        camera_handler = CameraHandler(json_thread, token_store, rate_limiter)
        auth_handler = AuthHandler(json_thread, token_store, rate_limiter)
        put_handler = PutHandler(json_thread, token_store)

        self._threads.append(SingleFCGIThread(camera_handler, 4002))
        self._threads.append(SingleFCGIThread(auth_handler, 4001))
        self._threads.append(FCGIThread(put_handler, 4000))

    def start(self):
        for thread in self._threads: thread.start()

    def stop(self):
        for thread in self._threads: thread.stop()

    def join(self):
        for thread in self._threads: thread.join()

if __name__ == "__main__":
    s = Server()
    s.start()
    import signal
    def handler(signal, frame):
        s.stop()
    signal.signal(signal.SIGTERM, handler)
    try:
        s.join()
    except KeyboardInterrupt:
        s.stop()
    finally:
        s.join()
