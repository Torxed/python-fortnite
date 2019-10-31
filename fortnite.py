import uuid
import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen, build_opener, install_opener, HTTPCookieProcessor, BaseHandler
from urllib.error import HTTPError
import http.cookiejar

URL_OAUTH_TOKEN = 'https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token'
URL_LOGIN = 'https://www.epicgames.com/id/api/login'
URL_2FA = 'https://www.epicgames.com/id/api/login/mfa'
URL_REDIRECT = 'https://www.epicgames.com/id/api/redirect'
URL_EXCHANGE = 'https://www.epicgames.com/id/api/exchange'
URL_GRANT_TOKEN = 'https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token'
#URL_2FA = 'https://hvornum.se/token.php'
URL_CSRF = 'https://www.epicgames.com/id/api/csrf'

class EpicError(Exception):
	def __init__(self, message, errors=None):
		super(EpicError, self).__init__(message)
		self.errors = errors

class HeaderFilter(BaseHandler):
	"""
	Filters headers based on what's given in {headers} to keep,
	and if the kept header is in {kwargs} it overwrites the default ones.
	"""
	def __init__(self, headers, *args, **kwargs):
		BaseHandler.__init__(self)
		self.headers = headers
		self.args = args
		for item in list(kwargs.keys()): kwargs[item.lower()] = kwargs[item]
		self.kwargs = kwargs

	def http_request(self, request):
		for header, val in request.header_items():
			if header.lower() not in self.headers:
				request.remove_header(header)
			elif header.lower() in self.headers and header.lower() in self.kwargs:
				request.remove_header(header)
				request.add_header(header, self.kwargs[header.lower()])
		for header in self.headers:
			if header in self.kwargs:
				request.add_header(header, self.kwargs[header])

		return request
	https_request = http_request

class HTTP():
	"""
	HTTP extension for Fortnite
	Essentially just gives Fortnite the ability to do Fortnite.POST and Fortnite.GET
	(Automatically handles cookies, redirects etc)
	"""
	def __init__(self, cookies={}, headers={}, *args, **kwargs):
		if not 'User-Agent' in headers: headers['User-Agent'] = 'EpicGamesLauncher/10.2.3-7092195+++Portal+Release-Live Windows/10.0.17134.1.768.64bit'
		if not 'Authorization' in headers: headers['Authorization'] = f'basic {self.pick_auth_token(self.client_stage)}'
		if not 'Accept-Language' in headers: headers['Accept-Language'] = 'en-EN'

		self.headers = headers
		self.cookies = http.cookiejar.CookieJar()
		opener = build_opener(HTTPCookieProcessor(self.cookies))
		install_opener(opener)

		## Migrate kwargs to self.key = val
		for key, val in kwargs.items():
			self.__dict__[key] = val

	def pick_auth_token(self, client):
		if client.upper() == 'FORTNITE':
			return self.fortnite_token
		elif client.upper() == 'LAUNCHER':
			return self.launcher_token
		return client


	def GET(self, url, headers={}, delete_headers={}, include_default_headers=True):
		if include_default_headers: headers = {**self.headers, **headers}
		for key in delete_headers: del(headers[key])

		print('(GET) Url:', url)
		print('Headers:', json.dumps(headers, indent=4))

		request = Request(url, headers=headers)
		response = urlopen(request)

		response_headers = response.info()
		response_data = response.read().decode()

		return response_data, response_headers, response

	def POST(self, url, payload, headers={}, delete_headers={}, include_default_headers=True, *args, **kwargs):
		if include_default_headers:
			headers = {**self.headers, **headers}
		for key in delete_headers: del(headers[key])

		request = Request(url, urlencode(payload).encode())
		opener = build_opener(HeaderFilter(headers, **kwargs))

		print('(POST) Url:', url)
		print('Payload:', json.dumps(payload, indent=4))
		print('Formatted payload:', urlencode(payload).encode())
		response = opener.open(request)

		response_headers = response.info()
		response_data = response.read().decode()
		
		return response_data, response_headers, response

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

		## Migrate kwargs to self.key = val
		for key, val in kwargs.items():
			self.__dict__[key] = val

		self.kill_other_sessions = True
		self.accept_eula = True

		# Fire up the old web engine after the configuration is set.
		HTTP.__init__(self)

	def get_csrf_token(self, *args, **kwargs):
		data, headers, raw_response = self.GET(URL_CSRF, delete_headers={'Authorization'})

		for cookie in self.cookies:
			if cookie.name == 'XSRF-TOKEN':
				self.headers['x-xsrf-token'] = cookie.value
				return cookie.value

		raise EpicError("Could not get XSRF token (Required to pass forgery checks), aborting!")

	def authenticate_2fa(self, code, method):
		try:
			data, headers, raw_response = self.POST(URL_2FA,
															payload={
																'code': code,
																'method': method,
																'rememberDevice': 'False'
															},
															headers={
																'content-type',
																'content-length',
																'accept-encoding',
																'accept',
																'accept-language',
																'user-agent',
																'x-xsrf-token',
																'host'
															},
															**self.headers,
															include_default_headers=False)
		except HTTPError as event:
			code = event.getcode()
			response = json.loads(event.read().decode())
			print(response['message'])

	def redirect(self):
		print('Redirecting')
		try:
			data, headers, raw_response = self.GET(URL_REDIRECT,
														headers={
															'accept-encoding',
															'accept',
															'accept-language',
															'user-agent',
															'x-xsrf-token',
															'referer',
															'host'
														},
														**self.headers,
														referer = 'https://www.epicgames.com/id/login',
														include_default_headers=False)
			print(data)
		except HTTPError as event:
			print(event.getcode())
			print(event.read().decode())

	def exchange(self):
		print('Exchange')
		try:
			data, headers, raw_response = self.GET(URL_EXCHANGE,
														headers={
															'accept-encoding',
															'accept',
															'accept-language',
															'user-agent',
															'x-xsrf-token',
															'host'
														},
														**self.headers,
														include_default_headers=False)
			response = json.loads(data)
			return response['code']
		except HTTPError as event:
			print(event.getcode())
			print(event.read().decode())

	def grant_token(self, ticket):
		try:
			data, headers, raw_response = self.POST(URL_GRANT_TOKEN,
														payload={
															'grant_type': 'exchange_code',
															'exchange_code': ticket,
															'token_type': 'eg1',
														},
														headers={
															'content-type',
															'content-length',
															'accept-encoding',
															'accept',
															'accept-language',
															'user-agent',
															'x-xsrf-token',
															'host',
															'authorization'
														},
														**self.headers)
		except HTTPError as event:
			code = event.getcode()
			if code != 431:
				print('Unknown error:', code, event, event.read())
				exit(1)
			data = event.read().decode()


	def login(self):
		client.get_csrf_token()
		try:
			data, headers, raw_response = self.POST(URL_LOGIN,
														payload={
															'email': self.email,
															'password': self.password,
															'rememberMe': 'False'
														},
														headers={
															'content-type',
															'content-length',
															'accept-encoding',
															'accept',
															'accept-language',
															'user-agent',
															'x-xsrf-token',
															'host'
														},
														**self.headers,
														include_default_headers=False)
		except HTTPError as event:
			code = event.getcode()
			if code != 431:
				print('Unknown error:', code, event, event.read())
				exit(1)
			data = event.read().decode()

		response = json.loads(data)
		two_factor_code = input(f'{response["message"]}: ')

		client.get_csrf_token() # Refresh it before 2FA because it will belong to the new auth process.
		self.authenticate_2fa(two_factor_code, 'authenticator')
		self.redirect()
		ticket = self.exchange()
		if ticket:
			self.grant_token(ticket)

	def get_oauth_token(self, *args, **kwargs):
		headers = {
			'X-Epic-Device-ID': self.device_id
		}
		payload = {
			'grant_type': 'password',
			'username': self.email,
			'password': self.password
		}
		
		self.POST(URL_OAUTH_TOKEN, headers=headers, payload=payload)

client = Fortnite('eric@fnite.se', 'Lx0e1utY!')
client.login()
