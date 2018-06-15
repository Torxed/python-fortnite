import ssl, json, re
from time import sleep
from socket import *
from select import select
from urllib.parse import urlparse
from base64 import *
from io import BytesIO
from gzip import decompress
from bs4 import BeautifulSoup


config = {
	'launcher_key' : b'34a02cf8f4414e29b15921876da36f9a:daafbccc737745039dffe53d94fc76cf', # Can be found by stringing the Game Launcher binary (or via HTTPS requests from the game launcher)
	'game_key' : b'',
	'username' : 'anton.feeds@gmail.com',
	'password' : '-----',
	'device_id' : 'a03c4960470f8fb19aa12a938ae76749' # Taken from /waitingroom/api/waitingroom GET request. Probably don't need to configure this here since it will be fetched.
}

# Some constants for different game modes
# and platforms when fetching stats etc.
_SOLO = "_p2"
_DUO = "_p10"
_SQUAD = "_p9"
_PC = "pc"
_PS4 = "ps4"
_XBOX = "xb1"

# Some identified URL's that could be useful.
URLs = {
	"init" : "https://account-public-service-prod03.ol.epicgames.com",
	"OAUTH_TOKEN": "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token",
	"WAITING_ROOM" : "https://launcherwaitingroom-public-service-prod06.ol.epicgames.com/waitingroom/api/waitingroom",
	"LOGIN_PAGE" : "https://launcher-website-prod07.ol.epicgames.com//epic-login",
	"LOGIN_FORM" : "https://accounts.launcher-website-prod07.ol.epicgames.com/login/doLauncherLogin?client_id={client_id}",
	"TWO-FACTOR" : "https://accounts.launcher-website-prod07.ol.epicgames.com/login/doTwoFactor",
    "OAUTH_EXCHANGE": "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/exchange",
    "OAUTH_VERIFY": "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/verify?includePerms=true",
    "FortnitePVEInfo": "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/world/info",
    "FortniteStore": "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/storefront/v2/catalog",
    "FortniteStatus": "https://lightswitch-public-service-prod06.ol.epicgames.com/lightswitch/api/service/bulk/status?serviceId=Fortnite",
    "FortniteNews": "https://fortnitecontent-website-prod07.ol.epicgames.com/content/api/pages/fortnite-game",
    "username": "https://persona-public-service-prod06.ol.epicgames.com/persona/api/public/account/lookup?q={username}",
    "accountId": "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/stats/accountId/{accountId}/bulk/window/alltime",
    "accountId": "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/profile/{accountId}/client/QueryProfile?profileId=collection_book_schematics0&rvn=-1",
    "token": "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/sessions/kill/{token}",
    "leaderBoardScore": "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/leaderboards/type/global/stat/br_placetop1_{plat}_m0{groupType}/window/weekly?ownertype=1&itemsPerPage=50",
    "displayNameFromIds": "https://account-public-service-prod03.ol.epicgames.com/account/api/public/account?accountId={id}&accountId={id2}"
}

# Some session data to keep track of,
# some are access_token, refresh_token etc.
session = {}

class connection():
	def __init__(self, url):
		self.socket = None
		self.url = url
		tmp = urlparse(self.url)
		self.hostname = tmp.netloc
		self.path = tmp.path
		if len(tmp.query):
			self.path += '?'+tmp.query
		self.scheme = tmp.scheme
		self.reconnect()

	def reconnect(self):
		if self.socket: self.socket.close()

		self.socket = socket()
		self.socket = ssl.wrap_socket(self.socket, server_side=False, ssl_version=ssl.PROTOCOL_TLS, do_handshake_on_connect=True, suppress_ragged_eofs=True)
		self.socket.settimeout(10)
		self.socket.connect((self.hostname, 443))
		#print('Connected to {}'.format(self.hostname))
		#self.socket.setblocking(0)
		
	def recv(self, buffer=8192, timeout=0):
		#start = time()
		#while time() - start <= timeout:
		try:
			data = self.socket.recv(buffer)
		except BlockingIOError:
			data = None
		return data

	def send(self, data):
		#print('Sent {} characters of data.'.format(len(data)))
		self.socket.send(data)

	def close(self):
		self.socket.close()

class HTTP():
	def __init__(self, data):
		#if type(data) == bytes: data = data.decode('UTF-8') # TODO: Dangerous assumption
		self.data = data
		self.headers = {}
		self.cookies = {}
		self.payload = b''
		self.parse()

	def parse(self):
		if b'\r\n\r\n' in self.data:
			headers, data = self.data.split(b'\r\n\r\n', 1)
			headers = headers.decode('UTF-8') # TODO: dangerous, but should be a valid assumption.
			for index, item in enumerate(headers.split('\r\n')):
				if index == 0 and 'HTTP/1' in item:
					self.headers[':status'] = int(item.split(' ')[1])
					continue

				if ':' in item:
					key, val = item.split(':', 1)
					if key.lower() == 'set-cookie':
						cookie, cookie_val = val.strip(), True
						if '=' in cookie:
							cookie, cookie_val = cookie.split('=',1)

						if type(cookie_val) == str and ';' in cookie_val: cookie_val = cookie_val.split(';',1)[0]
						#print('[Got Cookie] {} = {}'.format(cookie, cookie_val))
						self.cookies[cookie] = cookie_val
					else:
						self.headers[key.strip().lower()] = val.strip()

			if 'content-encoding' in self.headers:
				if self.headers['content-encoding'] == 'gzip':
					# decompressed_data=zlib.decompress(f.read(), 16+zlib.MAX_WBITS)
					data = decompress(BytesIO(data).read())

			if type(data) == bytes:
				data = data.decode('UTF-8') ## Again, dangerous assumption, check headers for content type first.

			if 'content-type' in self.headers and self.headers['content-type'].lower()[:len('application/json')] == 'application/json':
				try:
					self.payload = json.loads(data)
				except:
					print([data])
					data = data[data.find('{'):] # Some random shadow 23ab thing comes in all the time.
					self.payload = json.loads(data)
			else:
				self.payload = data
		else:
			print('Incomplete data.')

	def __repr__(self, *args, **kwargs):
		s = '[HTTP {0:>3} Response]\n'.format(self.headers[':status'])
		s += '-------------------\n'
		if type(self.payload) == dict:
			s += '    Payload: {}\n'.format(json.dumps(self.payload, indent=8, sort_keys=True))
		else:
			s += '    Payload: {}\n'.format(self.payload[:400])
		s += '    headers: {}\n'.format(json.dumps(self.headers, indent=8, sort_keys=True))
		s += '    Cookies: {}'.format(json.dumps(self.cookies, indent=8, sort_keys=True))
		return s

class HTTP_SEND():
	def __init__(self, _type, url, headers, payload=b'', cookies={}):
		self._type = _type
		self.headers = headers
		if type(payload) == bytes:
			payload = payload
		elif type(payload) == dict:
			payload_str = ''
			for key, val in payload.items():
				payload_str += '{}={}&'.format(key, val)
			payload = bytes(payload_str[:-1], 'UTF-8')
		else:
			payload = b''
		self.payload = payload

		if len(payload) and ('Content-Length' not in headers or int(headers['Content-Length']) != len(payload)):
			headers['Content-Length'] = len(payload)

		self.url = url
		self.cookies = cookies

		self.frame = b''
		self.frame += bytes('{} {} HTTP/1.1\r\n'.format(_type, url), 'UTF-8')
		for key, val in headers.items():
			self.frame += bytes('{}: {}\r\n'.format(key, val), 'UTF-8')
		cookie_str = ''
		for key, val in cookies.items():
			if len(cookie_str) <= 0: cookie_str += 'Cookie: '
			cookie_str += '{}={}; '.format(key, val)
		if len(cookie_str):
			self.frame += bytes(cookie_str[:-2]+'\r\n', 'UTF-8')
		self.frame += b'\r\n'
		self.frame += payload

	def __repr__(self, *args, **kwargs):
		s = '[HTTP {0:>3} Request]\n'.format(self._type)
		s += '---------------------\n'
		s += '        URL: {}\n'.format(self.url)
		s += '    Payload: {}\n'.format(self.payload.decode('UTF-8'))
		s += '    headers: {}\n'.format(json.dumps(self.headers, indent=8, sort_keys=True))
		s += '    Cookies: {}'.format(json.dumps(self.cookies, indent=8, sort_keys=True))
		return s

def fake_launcher(cookies={}):
	## == Act as if we've started the launcher.
	##    The next step is to start a game and get a game-token.
	if not 'launcher' in session: session['launcher'] = {}

	con = connection(URLs['OAUTH_TOKEN'])
	request = HTTP_SEND('POST', URLs['OAUTH_TOKEN'], {
			'Host': con.hostname,
			'Accept': '*/*',
			'Content-Type': 'application/x-www-form-urlencoded',
			'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
			'Authorization': 'basic {}'.format(b64encode(config['launcher_key']).decode('UTF-8'))
		}, payload={'grant_type' : 'client_credentials', 'token_type' : 'eg1'}, cookies=cookies)
	
	con.send(request.frame)
	print(request)
	
	response = HTTP(con.recv(8192*3))
	con.close()

	print(response)

	session['access_token'] = response.payload['access_token']
	session['client_id'] = response.payload['client_id']

	con = connection(URLs['OAUTH_TOKEN'])
	request = HTTP_SEND('POST', URLs['OAUTH_TOKEN'], {
			'Host': con.hostname,
			'Accept': '*/*',
			'Content-Type': 'application/x-www-form-urlencoded',
			'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
			'Authorization': 'basic {}'.format(b64encode(config['launcher_key']).decode('UTF-8'))
		}, payload=b'grant_type=client_credentials&token_type=eg1', cookies=cookies)
	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192*3))
	con.close()
	print(response)

	if type(response.payload) == dict:
		if 'access_token' in response.payload:
			print('[Notification] Successfully logged in.')

			if 'x-epic-correlation-id' in response.headers:
				session['launcher']['x-epic-correlation-id'] = response.headers['x-epic-correlation-id']
			for key, val in response.payload.items():
				session['launcher'][key] = val

			print('    Access Token: {}'.format(session['launcher']['access_token']))

	# == Maybe not needed since we're getting a eg1 token later.
	# con = connection(URLs['OAUTH_EXCHANGE'])
	# request = HTTP_SEND('GET', URLs['OAUTH_EXCHANGE'], {
	# 		'Host': con.hostname,
	# 		'Accept': '*/*',
	# 		'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
	# 		'Authorization': 'bearer {}'.format(session['launcher']['access_token'])
	# 	}, cookies=response.cookies)
	# con.send(request.frame)
	# print(request)

	# response = HTTP(con.recv(8192*3))
	# con.close()
	# print(response)

	return response

def enter_waitingRoom(cookies={}):
	con = connection(URLs['WAITING_ROOM'])
	request = HTTP_SEND('GET', URLs['WAITING_ROOM'], {
		'Host': con.hostname,
		'Accept': '*/*',
		'X-Epic-Correlation-ID': 'UE4-{device_id}-14F5DBFB40E3D4C0FC0F2CB72E25F1FB-D0488D2E4D24020CFED4638C30668DB6'.format(**config),
		'User-Agent': 'game=EpicGamesLauncher, engine=UE4, version=4.18.0-4118508+++Portal+Release-Live, platform=Windows, osver=10.0.17134.1.256.64bit'
	}, cookies=cookies)

	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192*3))
	con.close()

	print(response)
	return response

def get_login_form(cookies={}):
	print('[Notice] Fetching login form: {}'.format(URLs['LOGIN_PAGE']))

	last_url = URLs['LOGIN_PAGE']
	con = connection(URLs['LOGIN_PAGE'])
	request = HTTP_SEND('GET', URLs['LOGIN_PAGE'], {
		'Host': con.hostname,
		'Connection': 'keep-alive',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
		'Accept-Language': 'en-US',
		'Upgrade-Insecure-Requests': 1,
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
		'Accept-Encoding': 'gzip, deflate'
	}, cookies=cookies)

	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192*3))
	con.close()

	print(response)

	while response.headers[':status'] == 302:
		for field in urlparse(response.headers['location']).query.split('&'):
			if '=' in field:
				key, val = field.split('=',1)
				if key.lower() == 'client_id':
					print('[Notice] Found our own Client ID: {}'.format(val))
					session['client_id'] = val.strip()
					
		print('[HTTP Following redirect]\n    => {}'.format(response.headers['location']))
		last_url = response.headers['location'] #TODO: Dangerous assumption, check for https:// previous to the redirect.

		con = connection(response.headers['location'])
		request = HTTP_SEND('GET', response.headers['location'], {
			'Host': con.hostname,
			'Connection': 'keep-alive',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
			'Accept-Language': 'en-US',
			'Upgrade-Insecure-Requests': 1,
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
			'Accept-Encoding': 'gzip, deflate'
		}, cookies=response.cookies)
		con.send(request.frame)
		print(request)

		response = HTTP(con.recv(8192*3))
		con.close()
		print(response)

	con = connection(URLs['LOGIN_FORM'])
	request = HTTP_SEND('GET', URLs['LOGIN_FORM'].format(**session), {
		'Host': con.hostname,
		'Connection': 'keep-alive',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
		'Accept-Language': 'en-US',
		'Upgrade-Insecure-Requests': 1,
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
		'Referer' : last_url,
		'Accept-Encoding': 'gzip, deflate',
		'Cookie': 'EPIC_DEVICE={device_id}'.format(**config)
	}, cookies=response.cookies)

	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192*3))
	con.close()

	print(response)

	# while response.headers[':status'] == 302:
	# 	print('[HTTP Following redirect]\n    => {}'.format(response.headers['location']))

	# 	con = connection(response.headers['location'])
	# 	request = HTTP_SEND('GET', response.headers['location'], {
	# 		'Host': con.hostname,
	# 		'Connection': 'keep-alive',
	# 		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
	# 		'Accept-Language': 'en-US',
	# 		'Upgrade-Insecure-Requests': 1,
	# 		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
	# 		'Accept-Encoding': 'gzip, deflate'
	# 	}, cookies=response.cookies)
	# 	#	'Cookie': 'EPIC_DEVICE={device_id}'.format(**config)
	# 	#}, cookies=response.cookies)
	# 	con.send(request.frame)
	# 	#print(request)

	# 	response = HTTP(con.recv(8192*3))
	# 	con.close()

	html = BeautifulSoup(response.payload, "html.parser")

	loginForm = html.find("form", {"id": "loginForm"})
	if not loginForm:
		print('[HTTP.formError] Could not locate login form.')
		exit(1)

	inputs = loginForm.find_all('input')
	if not inputs:
		print('[HTTP.formError] Could analyze login form.')
		exit(1)

	fields = {}
	for field in inputs:
		field_name = field.get('name')
		if field_name:
			fields[field_name] = field.get('value')

	print(response)
	print('[Notice] Found login-data:')
	print(json.dumps(fields, indent=8, sort_keys=True))

	fields['epic_username'] = config['username']
	fields['password'] = config['password']
	if 'client_id' in fields:
		print('[Notice] Reliably updating client ID to: {}'.format(fields['client_id']))
		session['client_id'] = fields['client_id']

	con = connection(URLs['LOGIN_FORM'])
	request = HTTP_SEND('POST', URLs['LOGIN_FORM'].format(**session), {
		'Host': con.hostname,
		'Connection': 'keep-alive',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
		'Accept-Language': 'en-US',
		'Origin' : 'https://accounts.launcher-website-prod07.ol.epicgames.com',
		'Referer' : URLs['LOGIN_FORM'].format(**session),
		'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Upgrade-Insecure-Requests': 1,
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
		'Accept-Encoding': 'gzip, deflate'
	}, cookies=response.cookies, payload=fields)

	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192*3))
	con.close()

	print(response)
	html = BeautifulSoup(response.payload, "html.parser")

	TwoFactForm = html.find("form", {"id": "twoFactorForm"})
	if not TwoFactForm:
		print('[HTTP.formError] Could not locate 2FA form.')
		exit(1)

	inputs = TwoFactForm.find_all('input')
	if not inputs:
		print('[HTTP.formError] Could analyze 2FA form.')
		exit(1)

	fields = {}
	for field in inputs:
		field_name = field.get('name')
		if field_name:
			fields[field_name] = field.get('value')

	fields['client_id'] = session['client_id']
	fields['twoFactorCode'] = input('[IMPORTANT] Enter your Two-Factor-Auth code (check your mail): ')
	fields['epic_username'] = config['username']
	fields['redirectUrl'] = 'https://accounts.launcher-website-prod07.ol.epicgames.com/login/showPleaseWait?client_id={}&rememberEmail=false'.format(session['client_id'])
	print(json.dumps(fields, indent=8, sort_keys=True))
	#fields['password'] = config['password']

	con = connection(URLs['TWO-FACTOR'])
	request = HTTP_SEND('POST', URLs['TWO-FACTOR'], {
		'Host': con.hostname,
		'Connection': 'keep-alive',
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
		'Accept-Language': 'en-US',
		'Origin' : 'https://accounts.launcher-website-prod07.ol.epicgames.com',
		'Referer' : 'https://accounts.launcher-website-prod07.ol.epicgames.com/login/launcher',
		'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Upgrade-Insecure-Requests': 1,
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
		'Accept-Encoding': 'gzip, deflate'
	}, cookies=response.cookies, payload=fields)

	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192*3))
	con.close()

	print(response)

	if response.headers[':status'] != 200:
		print('[Fail] Could not log on.')
		exit(1)

		# with open('html_login.html', 'w') as fh:
		# 	fh.write(response.payload)

		# while response.headers[':status'] == 302:
		# 	for key, val in response.header.items():
		# 		elif key.lower()[0] == 'x':
		# 			session[key.lower()] = val.strip()
						
		# 	print('[HTTP Following redirect]\n    => {}'.format(response.headers['location']))
		# 	last_url = response.headers['location'] #TODO: Dangerous assumption, check for https:// previous to the redirect.

		# 	con = connection(response.headers['location'])
		# 	request = HTTP_SEND('GET', response.headers['location'], {
		# 		'Host': con.hostname,
		# 		'Connection': 'keep-alive',
		# 		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
		# 		'Accept-Language': 'en-US',
		# 		'Upgrade-Insecure-Requests': 1,
		# 		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
		# 		'Accept-Encoding': 'gzip, deflate'
		# 	}, cookies=response.cookies)
		# 	#	'Cookie': 'EPIC_DEVICE={device_id}'.format(**config)
		# 	#}, cookies=response.cookies)
		# 	con.send(request.frame)
		# 	#print(request)

		# 	response = HTTP(con.recv(8192*3))
		# 	con.close()

	if type(response.payload) == dict:
		if 'redirectURL' in response.payload:

			con = connection(response.payload['redirectURL'])
			request = HTTP_SEND('GET', response.payload['redirectURL'], {
				'Host': con.hostname,
				'Connection': 'keep-alive',
				'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
				'Accept-Language': 'en-US',
				'Referer' : 'https://accounts.launcher-website-prod07.ol.epicgames.com/login/launcher',
				'Upgrade-Insecure-Requests': 1,
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',
				'Accept-Encoding': 'gzip, deflate'
			}, cookies=response.cookies, payload=fields)

			con.send(request.frame)
			print(request)

			response = HTTP(con.recv(8192*3))
			con.close()

			print(response)

	return response

response = fake_launcher()
if 'access_token' in session['launcher']:
	print('[Notice] Launcher successfully "started".')

response = enter_waitingRoom(cookies=response.cookies)
if response.headers[':status'] == 204:
	print('Successfully entered waiting room.')

response = get_login_form(cookies={**response.cookies, 'EPIC_DEVICE' : '{device_id}'.format(**config)})

cookies = response.cookies
if 'ExchangeCode' in response.payload:
	print('[Notice] Extracting ExchangeCode...')
	code = re.findall("ExchangeCode\('[a-zA-Z0-9]+',", response.payload)[0]
	code = code[code.find("('")+2:-2]
	print()
	print()
	print()
	print()
	print('[Notice] ExchangeCode: {}'.format(code))
	session['ExchangeCode'] = code

con = connection(URLs['OAUTH_TOKEN'])
request = HTTP_SEND('POST', URLs['OAUTH_TOKEN'], {
	'Host': con.hostname,
	'Accept': '*/*',
	'Content-Type': 'application/x-www-form-urlencoded',
	'Content-Length': '104',
	'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
	'Authorization': 'basic {}'.format(b64encode(config['launcher_key']).decode('UTF-8'))
}, payload={
	'grant_type' : 'exchange_code',
	'exchange_code' : session['ExchangeCode'],
	'includePerms' : 'true',
	'token_type' : 'eg1'
})

con.send(request.frame)
print(request)

response = HTTP(con.recv(8192*3))
con.close()

print(response)

if 'refresh_token' in response.payload:
	print('[Notice] Successfully gained access!')
#	session['refresh_token'] = response.payload['refresh_token']
#if 'account_id' in response.payload:
#	session['account_id'] = response.payload['account_id']
for key, val in response.payload.items():
	session[key] = val



url = 'https://account-public-service-prod03.ol.epicgames.com/account/api/public/account/{account_id}'.format(**session)
con = connection(url)
request = HTTP_SEND('GET', url, {
	'Host': con.hostname,
	'Connection': 'keep-alive',
	'Accept': '*/*',
	'Content-Type': 'application/json',
	'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
	'Content-Length': '0',
	'Authorization': 'bearer {}'.format(session['access_token']),
})

con.send(request.frame)
print(request)
response = HTTP(con.recv(8192*3))
con.close()
print(response)

con = connection(URLs['username'].format(username='hvornum'))
request = HTTP_SEND('GET', URLs['username'].format(username='hvornum'), {
	'Host': con.hostname,
	'Connection': 'keep-alive',
	'Accept': '*/*',
	'Content-Type': 'application/json',
	'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
	'Content-Length': '0',
	'Authorization': 'bearer {}'.format(session['access_token']),
})
#	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) EpicGamesLauncher/7.11.0-4118508+++Portal+Release-Live UnrealEngine/4.18.0-4118508+++Portal+Release-Live Safari/537.36',

con.send(request.frame)
print(request)

response = HTTP(con.recv(8192*3))
con.close()

print(response)