import uuid, sys
import ssl, zlib, io
from json import *
from socket import *
from os.path import isfile
from urllib.parse import urlencode
from collections import OrderedDict
from select import epoll, EPOLLIN, EPOLLHUP
from time import time

URL_OAUTH_TOKEN = 'https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token'
URL_LOGIN = 'https://www.epicgames.com/id/api/login'
URL_2FA = 'https://www.epicgames.com/id/api/login/mfa'
URL_REDIRECT = 'https://www.epicgames.com/id/api/redirect'
URL_EXCHANGE = 'https://www.epicgames.com/id/api/exchange'
URL_GRANT_TOKEN = 'https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token' # TODO: redundant?
URL_ACCOUNT = 'https://account-public-service-prod03.ol.epicgames.com/account/api'
#URL_2FA = 'http://hvornum.se/id/api/login/mfa'
URL_CSRF = 'https://www.epicgames.com/id/api/csrf'
URL_SESSION_KILL = 'https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/sessions/kill'
URL_GET_EULA = 'https://eulatracking-public-service-prod-m.ol.epicgames.com/eulatracking/api/public/agreements/fn/account'
URL_ACCEPT_EULA = 'https://eulatracking-public-service-prod-m.ol.epicgames.com/eulatracking/api/public/agreements/fn/version'
URL_GRANT_ACCESS_TO_GAME = 'https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/grant_access'
URL_FRIENDS = 'https://friends-public-service-prod06.ol.epicgames.com/friends/api/public/friends'
URL_STATS = 'https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/stats/accountId/{accountId}/bulk/window/alltime'

class EpicError(Exception):
	def __init__(self, message, errors=None):
		super(EpicError, self).__init__(message)
		self.errors = errors

#	dumps(obj, cls=JSON_Typer)
class JSON_Typer(JSONEncoder):
	def _encode(self, obj, recursion):
		if isinstance(obj, dict):
			new_obj = {}
			def check_key(o):
				if type(o) == bytes:
					o = o.decode('UTF-8', errors='replace')
				elif type(o) == Cookie:
					o = o.__repr__()
				elif type(o) == set:
					o = loads(dumps(o, cls=JSON_Typer))
				return o
			
			for key, val in list(obj.items()):
				if isinstance(val, dict):
					val = loads(dumps(val, cls=JSON_Typer)) # This, is a EXTREMELY ugly hack..
															# But it's the only quick way I can think of to 
															# trigger a encoding of sub-dictionaries. (I'm also very tired, yolo!)
				else:
					val = check_key(val)
				#del(obj[key])
				new_obj[check_key(key)] = val
			return new_obj
		elif isinstance(obj, (datetime, date)):
			return obj.isoformat()
		elif isinstance(obj, Cookie):
			return o.__repr__()
		elif isinstance(obj, (list, set, tuple)):
			r = []
			for item in obj:
				r.append(loads(dumps(item, cls=JSON_Typer)))
			return r
		else:
			return obj

	def encode(self, obj, recursion=0):
		return super(JSON_Typer, self).encode(self._encode(obj, recursion=recursion))

class Cookie():
	def __init__(self, name, value, paramters):
		self.name = name
		self.value = value
		self.built = time()
		for parameter in paramters.split(';'):
			if '=' in parameter:
				key, val = parameter.split('=', 1)
				val = val.strip(' ;')
			else:
				key, val = parameter, True
			self.__dict__[key.strip(' ;')] = val

	def __repr__(self, *args, **kwargs):
		return self.value

	def validate_path(self, url):
		if not 'Path' in self.__dict__: return True
		if url[:len(self.__dict__['Path'])] == self.__dict__['Path']:
			#print(f'Cookie {self.name} is valid for {url[:len(self.__dict__["Path"])]}')
			return True
		return False

class HTTP():
	"""
	HTTP extension for Fortnite
	Essentially just gives Fortnite the ability to do Fortnite.POST and Fortnite.GET
	(Automatically handles cookies, redirects etc)
	"""
	def __init__(self, cookies={}, headers={}, *args, **kwargs):
		if not 'User-Agent' in headers: headers['User-Agent'] = 'EpicGamesLauncher/10.2.3-7092195+++Portal+Release-Live Windows/10.0.17134.1.768.64bit'
		#if not 'Authorization' in headers: headers['Authorization'] = f'basic {self.pick_auth_token(self.client_stage)}'
		if not 'Accept-Language' in headers: headers['Accept-Language'] = 'en-EN'
		if not 'Accept' in headers: headers['Accept'] = '*/*'
		if not 'Accept-Encoding' in headers: headers['Accept-Encoding'] = 'gzip, deflate'
		#'Content-Type' : 'application/x-www-form-urlencoded'
		#'Content-Length' 
		#'Host'

		self.headers = headers
		self.content_encoding = None
		self.cookies = {}

		## Migrate kwargs to self.key = val
		for key, val in kwargs.items():
			self.__dict__[key] = val

	def peak_headers(self, data):
		if b'\r\n\r\n' in data:
			headers, payload = data.split(b'\r\n\r\n', 1)
			for index, item in enumerate(headers.split(b'\r\n')):
				if index == 0:
					trash, code, message = item.split(b' ', 2)
					if code == b'204':
						return True
				if b':' in item:
					key, val = item.split(b':', 1)
					if key.strip().lower() == b'content-length':
						if int(val.strip().decode('UTF-8')) >= len(payload):
							return True
					elif key.strip().lower() == b'content-encoding':
						self.content_encoding = val.strip().decode('UTF-8')
					elif key.strip().lower() == b'transfer-encoding':
						if val.strip().lower() == b'chunked':
							ending = b'0\r\n\r\n'
							if payload[0-len(ending):] == ending:
								return True

	def unchunk(self, payload):
		clean = b''
		index = 0
		#print('Unchunking')
		while True:
			if b'\r\n' in payload[index:]:
				l, tmp = payload[index:].split(b'\r\n', 1)
				l = l.decode('UTF-8')
				chunk_len = int(l, 16)

				#print('Chunk:', clean[-20:], chunk_len, l, payload[index+len(l)+2:index+len(l)+2+chunk_len])
				if chunk_len != 0:
					clean += payload[index+len(l)+2:index+len(l)+2+chunk_len]
					index += len(l) + 2 + chunk_len + 2
					continue
				else:
					#print('Returning clean:')
					#print(clean[:120], clean[-120:])
					#print('Clean returned')
					return clean
		return None

	def parse_headers(self, headers, overwrite_cookies=True):
		clean = {}
		cookies = {}

		for index, item in enumerate(headers.split(b'\r\n')):
			if index == 0:
				trash, code, message = item.split(b' ', 2)
				clean['HTTP_STATUS'] = {'code' : int(code.strip().decode('UTF-8')), 'message' : message.decode('UTF-8')}
				continue

			if b':' in item:
				key, val = item.decode('UTF-8').split(':', 1)
				if key.strip().lower() == 'set-cookie':
					key, val = val.split('=',1)
					if ';' in val:
						val, params = val.split(';', 1)
					else:
						val, params = val, ''
					cookie = Cookie(key.strip(), val.strip(' ;'), params)
					#val = val.split(';')[0]
					cookies[key.strip()] = cookie# val.strip(" ;")
				else:
					clean[key.strip()] = val.strip(" ;")

		if overwrite_cookies:
			#dumps(obj, cls=JSON_Typer)
			self.cookies = {**self.cookies, **cookies}
		clean['COOKIES'] = cookies
		return clean

	def get_request_response(self, socket, overwrite_cookies=True):
		poller = epoll()
		poller.register(socket.fileno(), EPOLLIN | EPOLLHUP)
		response = b''
		alive = True
		self.content_encoding = None
		while alive:
			for fileno, event in poller.poll(0.25):
				data = socket.recv(8192)
				if len(data) <= 0:
					alive = False
					break

				response += data
				#print('Got data, peaking at headers again:', response[-200:])
				if self.peak_headers(response):
					alive = False
					break

		headers, payload = response.split(b'\r\n\r\n', 1)
		headers = self.parse_headers(headers, overwrite_cookies=overwrite_cookies)

		for header in headers:
			if header.lower() == 'transfer-encoding':
				if headers[header].lower() == 'chunked':
					payload = self.unchunk(payload)

		if self.content_encoding and self.content_encoding == 'gzip':
			payload = zlib.decompress(payload, 16+zlib.MAX_WBITS)

		#print('Response:')
		#print(dumps(headers, indent=4, sort_keys=True, cls=JSON_Typer))
		#print(payload[:400])
		#print('----')

		return headers, payload.decode('UTF-8')

	def HTTP_REQUEST(self, method, url, headers={}, cookies={}, payload=None, *args, **kwargs):
		if not 'INCLUDE_DEFAULT_HEADERS' in kwargs: kwargs['INCLUDE_DEFAULT_HEADERS'] = True
		if not 'FILTER_OUT_HEADERS' in kwargs: kwargs['FILTER_OUT_HEADERS'] = False
		if not 'CLOSE_AFTER_REQUEST' in kwargs: kwargs['CLOSE_AFTER_REQUEST'] = True
		if not 'OVERWRITE_COOKIES' in kwargs: kwargs['OVERWRITE_COOKIES'] = True

		if kwargs['INCLUDE_DEFAULT_HEADERS']:
			headers = {**self.headers, **headers}

		if kwargs['FILTER_OUT_HEADERS']:
			for key in kwargs['FILTER_OUT_HEADERS']:
				for hkey in list(headers.keys()):
					if hkey.lower() == key.lower():
						del(headers[hkey])

		if 'https://' in url[:8]:
			tls, port = True, 443
			host, url = url[8:].split('/', 1)
		elif 'http://' in url[:7]:
			tls, port = False, 80
			host, url = url[7:].split('/', 1)
		else:
			raise EpicError('Not a valid URL endpoint:', url)
		url = f'/{url}'

		# Add POST/GET specific headers
		if payload:
			if 'Content-Type' not in headers or headers['Content-Type'] != 'application/json':
				payload = urlencode(payload)
				headers['Content-Type'] = 'application/x-www-form-urlencoded'
			else:
				payload = dumps(payload)
			if not 'Content-Length' in headers:
				headers['Content-Length'] = len(payload)
		if not 'Host' in headers:
			headers['Host'] = host

		self.socket = socket()
		request = f'{method} {url} HTTP/1.1\r\n'
		for key, val in headers.items():
			request += f'{key}: {val}\r\n'

		if len(self.cookies):
			cookie_string = ''
			if len(cookies): # Add only filtered cookies
				for cookie in cookies:
					if cookie in self.cookies and self.cookies[cookie].validate_path(url):
						cookie_string += f'{cookie}={self.cookies[cookie]}; '
			else:
				for cookie in self.cookies:
					if self.cookies[cookie].validate_path(url):
						cookie_string += f'{cookie}={self.cookies[cookie]}; '
			request += f'Cookie: {cookie_string[:-2]}; samesite=strict\r\n'
		request += '\r\n'
		if payload:
			request += payload

		#print('\nSending request:')
		#print(request)

		self.socket.connect((host, port))
		if tls:
			context = ssl.create_default_context()
			self.socket = context.wrap_socket(self.socket, server_hostname=host)

		self.socket.send(bytes(request, 'UTF-8'))
		headers, payload = self.get_request_response(self.socket, kwargs['OVERWRITE_COOKIES'])

		if kwargs['CLOSE_AFTER_REQUEST']:
			self.socket.close()

		if 'Content-Type' in headers:
			if headers['Content-Type'] == 'application/json':
				try:
					payload = loads(payload)
				except Exception as e:
					print(' * * * Could not load JSON:')
					print(payload[:200], payload[-200:])
					print(' * * * ')


		return socket, headers, payload


	def DELETE(self, url, headers={}, cookies={}, *args, **kwargs):
		socket, headers, payload = self.HTTP_REQUEST('DELETE', url, headers, cookies, *args, **kwargs)
		return headers, payload

	def GET(self, url, headers={}, cookies={}, *args, **kwargs):
		socket, headers, payload = self.HTTP_REQUEST('GET', url, headers, cookies, *args, **kwargs)
		return headers, payload

	def POST(self, url, payload={}, headers={}, cookies={}, *args, **kwargs):
		socket, headers, payload = self.HTTP_REQUEST('POST', url, headers, cookies, payload=payload, *args, **kwargs)

		return headers, payload

class Fortnite(HTTP):
	def __init__(self, email, password, *args, **kwargs):
		self.email = email
		self.password = password

		if not 'platform' in kwargs: kwargs['platform'] = 'WIN'
		if not 'net_cl' in kwargs: kwargs['net_cl'] = '8371706'
		if not 'party_build_id' in kwargs: kwargs['party_build_id'] = '1:1:{net_cl}'.format(**kwargs)
		if not 'default_party_config' in kwargs: kwargs['default_party_config'] = {}
		if not 'build' in kwargs: kwargs['build'] = '++Fortnite+Release-10.31-CL-8723043'
		if not 'engine_build' in kwargs: kwargs['engine_build'] = '4.23.0-8723043+++Fortnite+Release-10.31'
		if not 'launcher_token' in kwargs: kwargs['launcher_token'] = 'MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE='
		if not 'fortnite_token' in kwargs: kwargs['fortnite_token'] = 'ZWM2ODRiOGM2ODdmNDc5ZmFkZWEzY2IyYWQ4M2Y1YzY6ZTFmMzFjMjExZjI4NDEzMTg2MjYyZDM3YTEzZmM4NGQ='
		if not 'device_id' in kwargs: kwargs['device_id'] = uuid.uuid4().hex
		#if not 'two_factor_code' in kwargs: kwargs['two_factor_code'] = None
		if not 'client_stage' in kwargs: kwargs['client_stage'] = 'LAUNCHER' # Will migrate to FORTNITE after successful login etc.

		if not 'EULA_ACCEPTED' in kwargs: kwargs['EULA_ACCEPTED'] = False

		## Migrate kwargs to self.key = val
		for key, val in kwargs.items():
			self.__dict__[key] = val

		self.kill_other_sessions = True
		self.accept_eula = True

		self.launcher_information = None
		self.profiles = {}
		self.logged_in_as = None

		# Fire up the old web engine after the configuration is set.
		HTTP.__init__(self)

		if self.login():
			self.logged_in_as = self.launcher_information['account_id']
			response = self.get_profile(self.logged_in_as, cache_profile=True)

			if self.kill_other_sessions:
				self.DELETE(URL_SESSION_KILL+'?killType=OTHERS_ACCOUNT_CLIENT_SERVICE',
									headers={
										'Authorization' : f'bearer {self.launcher_information["access_token"]}'
									})

			if not kwargs['EULA_ACCEPTED']:
				if self.agree_on_eula(self.logged_in_as):
					#print('EULA accepted!')
					if self.grant_access(self.logged_in_as):
						#print('You can now play Fortnite.')
						return True

	def agree_on_eula(self, account_id):
		version, accepted = self.get_eula_version(account_id)
		if version and version != 0 and not accepted:
			#print('Accepting it:', version)
			return self.accept_eula_version(version, account_id)
		elif accepted:
			#print('EULA already accepted')
			return True
		return False

	def accept_eula_version(self, account_id, version):
		headers, data = self.POST(f'{URL_ACCEPT_EULA}/{version}/account/{account_id}/accept?locale=en',
										headers={
											'Authorization' : f'bearer {self.launcher_information["access_token"]}'
										})
		#print('Accepted EULA:', headers)
		if headers['HTTP_STATUS']['code'] == 200:
			return True

	def grant_access(self, account_id):
		headers, data = self.POST(f'{URL_GRANT_ACCESS_TO_GAME}/{account_id}',
									headers={
										'Authorization' : f'bearer {self.launcher_information["access_token"]}'
									})

		#print('Granted access to game:', headers, data[:299])
		if headers['HTTP_STATUS']['code'] in (200, 204):
			return True

	def get_eula_version(self, account_id):
		headers, data = self.GET(f'{URL_GET_EULA}/{account_id}',
										headers={
											'Authorization' : f'bearer {self.launcher_information["access_token"]}'
										})

		#print('Getting EULA version:', headers)
		if headers['HTTP_STATUS']['code'] == 200:
			version = data['version'] if 'version' in data else 0
			was_declined = data['wasDeclined'] if 'wasDeclined' in data else False
			return version, False if was_declined else True

	def get_csrf_token(self, *args, **kwargs):
		headers, data = self.GET(URL_CSRF)

		if 'XSRF-TOKEN' in headers['COOKIES']:
			self.headers['x-xsrf-token'] = headers['COOKIES']['XSRF-TOKEN']
			return headers['COOKIES']['XSRF-TOKEN']

		raise EpicError("Could not get XSRF token (Required to pass forgery checks), aborting!")

	def authenticate_2fa(self, code, method):
		headers, data = self.POST(URL_2FA,
									payload={
										'code': code,
										'method': method,
										'rememberDevice': 'False'
									},
									header_order=['Host', 'x-xsrf-token', 'User-Agent', 'Accept-Language', 'Accept', 'Accept-Encoding', 'Content-Length', 'Content-Type'])
		if headers['HTTP_STATUS']['code'] == 200:
			return True

	def redirect(self):
		#print('Redirecting')
		
		headers, data = self.GET(URL_REDIRECT,
									headers={
										'referer' : 'https://www.epicgames.com/id/login',
									})

		# {"redirectUrl":"https://epicgames.com/account/personal","sid":"ed775bfa65724793b1b39f07cbb4bf9b"}
		if headers['HTTP_STATUS']['code'] == 200:
			return True

	def exchange(self):
		#print('Exchange')

		headers, data = self.GET(URL_EXCHANGE)
		response = loads(data)
		return response['code']
		#except HTTPError as event:
		#	print(event.getcode())
		#	print(event.read().decode())

	def grant_token(self, ticket):
		#print('Granting token')
		headers, data = self.POST(URL_GRANT_TOKEN,
										payload={
											'grant_type': 'exchange_code',
											'exchange_code': ticket,
											'token_type': 'eg1',
										},
										headers={
											'authorization' : f'basic {self.launcher_token}'
										})

		if headers['HTTP_STATUS']['code'] == 200:
			return data
		return False

	def login(self):
		self.get_csrf_token()
		headers, data = self.POST(URL_LOGIN,
										cookies = {
											'EPIC_SSO_SESSION',
											'XSRF-TOKEN'
										},
										payload={
											'email': self.email,
											'password': self.password,
											'rememberMe': 'False'
										})

		response = loads(data)
		if headers['HTTP_STATUS']['code'] == 431:
			two_factor_code = input(f'{response["message"]}: ')

			self.get_csrf_token() # Refresh it before 2FA because it will belong to the new auth process.
			if not self.authenticate_2fa(two_factor_code, 'authenticator'):# response['metadata']['twoFactorMethod']):
				return False

		if self.redirect():
			ticket = self.exchange()
			if ticket:
				self.launcher_information = self.grant_token(ticket)

				return True

	def get_profile(self, account_id, cache_profile=True):
		headers, data = self.GET(f'{URL_ACCOUNT}/public/account/{account_id}',
									headers={
										'Authorization' : f'bearer {self.launcher_information["access_token"]}'
									})

		if headers['HTTP_STATUS']['code'] == 200:
			self.profiles[account_id] = data
			return data
		return False

	def get_friends(self, include_pending=False, cache_profiles=True):
		headers, data = self.GET(f'{URL_FRIENDS}/{self.logged_in_as}?includePending={include_pending}',
									headers={
										'Authorization' : f'bearer {self.launcher_information["access_token"]}'
									})

		if headers['HTTP_STATUS']['code'] == 200:
			if cache_profiles:
				print('Caching friends profiles (might take a while, unless you have no friends)')
				for friend in data:
					self.get_profile(friend['accountId'], cache_profile=True)
			return data
		
		return None

	def get_stats(self, account_id):
		headers, data = self.GET(
            'https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/' \
            'statsv2/account/{0}{1}'.format(account_id, ''),
            headers={
				'Authorization' : f'bearer {self.launcher_information["access_token"]}'
			})

		print('--- Stats:')
		print(data)

	def get_public_stats(self, account_id):
		URL_STATS
		headers, data = self.GET(URL_STATS.format(accountId=account_id),
					            headers={
									'Authorization' : f'bearer {self.launcher_information["access_token"]}'
								})
		print('PubStats:', data)