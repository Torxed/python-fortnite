import ssl, json, re
from time import sleep
from socket import *
from select import select
from urllib.parse import urlparse
from base64 import *
from io import BytesIO
from gzip import decompress
from bs4 import BeautifulSoup

## == Both are "old" API's which, might work..
#     But getting a hold of the game client token now days are hard.
#     Epic has beefed up the securatey, hard locked the client to a Symantec Cert.
#     Pulling out the network traffic appears to be harder than i'd imagine.
# https://github.com/nicolaskenner/python-fortnite-api-wrapper
# https://github.com/qlaffont/fortnite-api

config = {
	'launcher_key' : b'34a02cf8f4414e29b15921876da36f9a:daafbccc737745039dffe53d94fc76cf',
	'game_key' : b'',
	'username' : 'anton.feeds@gmail.com',
	'password' : 'Lx0e1utY',
	'device_id' : 'a03c4960470f8fb19aa12a938ae76749' # Taken from /waitingroom/api/waitingroom GET request.
}

_SOLO = "_p2"
_DUO = "_p10"
_SQUAD = "_p9"
_PC = "pc"
_PS4 = "ps4"
_XBOX = "xb1"

URLs = {
	"init" : "https://account-public-service-prod03.ol.epicgames.com",
	"OAUTH_TOKEN": "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token", # b'HTTP/1.1 200 OK\r\nDate: Wed, 13 Jun 2018 20:03:48 GMT\r\nContent-Type: application/json\r\nContent-Length: 1117\r\nConnection: keep-alive\r\nCache-Control: no-cache, no-store, no-transform\r\nX-Epic-Correlation-ID: c192b044-c4a0-4a0e-b0e2-d22315cc1993\r\n\r\n{\n  "access_token" : "eg1~eyJraWQiOiJ0RkMyVUloRnBUTV9FYTNxY09kX01xUVQxY0JCbTlrRkxTRGZlSmhzUkc4IiwiYWxnIjoiUFMyNTYifQ.eyJwIjoiZU5xVmtjRnF3ekFRUlBcL0g1RkE3cmhzditGUkNMcjMyQTliUzJoR3NWa1lycCszZlZ6RXVGR0pxZXBKWXpjeStRWXl6bUN0RnNPRkRPS0NGQXM2VE14ZjBwR1wvclkxY2QrdG14ZFRJRVdHNGV4UTJrQ1hDYXNtT1o1Vk1UcGxsMzVPOFNDZmtzb3hQNjJRQ01QVEVVMmNvYlJGdVdMUDMwT1U1SjFRWEpxbU9OVDVVWlRrTmRselZWYlY4K3QxVjVlbWtzSHB1aHhhNzhrK3VoOWc3VWdcLzQxU0NKSldXNHdJWWNSOUlxUjdKTHdyODFyMGk4QUV5emxLUEpUdXBkZGcrOFQ4bDE3MEdBY01pUkNyeUNhTGMwR003c2I3Y0lVVzdVTmg5bHFDaEZIQXYzU1JINFJLTVdiTStRa1wvN3dZMnJGMDFUZitsK1FZIiwiY2xzdmMiOiJsYXVuY2hlciIsInQiOiJzIiwiY2xpZCI6IjM0YTAyY2Y4ZjQ0MTRlMjliMTU5MjE4NzZkYTM2ZjlhIiwiaWMiOnRydWUsImV4cCI6MTUyODkzNDYyOCwiYW0iOiJjbGllbnRfY3JlZGVudGlhbHMiLCJpYXQiOjE1Mjg5MjAyMjgsImp0aSI6IjQ0MGNjY2MzZDMyYTRiZmE5MWVjYzBkZGFiZmNmMDNhIn0.AAhgcLYNKxepBJV-kNajtUObD5bLKbNwbdwePngDJFBBILfOIJrL4F1hoNNeV3j1bD1tmbbM6Kux2LRaKUHhXuYg",\n  "expires_in" : 14400,\n  "expires_at" : "2018-06-14T00:03:48.611Z",\n  "token_type" : "bearer",\n  "client_id" : "34a02cf8f4414e29b15921876da36f9a",\n  "internal_client" : true,\n  "client_service" : "launcher"\n}'
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

def generate_OTP():
	pass
	# https://accounts.epicgames.com/account/doRequestOneTimePassword

	# POST /account/doRequestOneTimePassword HTTP/1.1
	# Host: accounts.epicgames.com
	# Connection: keep-alive
	# Content-Length: 165
	# Accept: */*
	# Origin: https://accounts.epicgames.com
	# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36
	# Content-Type: application/x-www-form-urlencoded; charset=UTF-8
	# Referer: https://accounts.epicgames.com/account/oneTimePassword
	# Accept-Encoding: gzip, deflate, br
	# Accept-Language: en-US,en;q=0.9,sv;q=0.8
	# Cookie: _ga=GA1.2.1822577829.1518348679; EPIC_DEVICE=0afba94f-81b8-4680-820d-ad55324fbb9a; epicCountry=SE; _epicSID=d1b00bdd3a9b42e6aba3e948906e689d; euCookieAccepted=true; AWSELB=B13F99EF083A44C5754AEDFCC362C318ED4A6401A216A4BB96A03AA60E914CEFA16A1BB76FDA42363FFF75A23B4B4BE37ED83EA79E3B93AF3798454B5A4B1E41F71E6AF911; EPIC_SSO=9uwpfq1c59cqsjr65hqxpdov; EPIC_SSO_RM=9uwpfq1c59cqsjr65hqxpdov; EPIC_BEARER_TOKEN=c03738976c2c48b1af00f6693b5406f8; EPIC_STAY_SIGNED_IN=true; EPIC_SSO_SESSION=9uwpfq1c59cqsjr65hqxpdov; EPIC_SSO_SESSION_INSTANCE=eNoBgAJ//QpYU6skBZhPjH8vhoLmA9p8MzRi4DVb86zW9lV+M2ZCG1IkNQ6JXFG60Be1wyVkl78xYUHhWFmG/yYzErRjKOdh94WNKAcalLvAlCMRbEXytOglmshJya+ofeSmmqCCl0dR9aD1+pmlfjZSaHBNA18EstNWAkTLCkF5Rc26y/tWWG5VZxyqkdpubKXnxalpXCoaMk/VHxe8q60zxbW2IPITBgP0wlXytC7OOeeMPtczRdyyU9CB9bwvsLXLTgZXdUuXhq5KQ0SEZ9iJ/19uuAsDyy1kYc2f+fBlQqzphCjHS96PNft2FDiNWXJS9fVevnSAgoM22Kxlu/btQ9ObNz50Su2szum/3h01Je87uIte+TptUka9BBIkmP8mCVVUFGKMtyOrit2hRz1lhcC8zyRcv7PCM3T+X2BClp0NWTbGbmVQCtlnC97WYvPOsG/kIaCccm7QvXZVfnm79yveazcroK4zypMZjO5ifxLzeqeOetL/GYXYqXfzt+AHCKHItMTEY0nGV/1ixWR2isXkndUzekinN3nQXvuA7aO8on+ArTUYgYAel19nN2p9fyLo6kKHUowqargka9DJFwa0/ABwECuKaNAdiZ8o68Fyc2pAxmw1pSFgOsw+0PWmLqx6eJzBQTLL7157O47E+JGmYeMXbonDhCx3R2aJI4PuO5XyWmh9HBjZ+1JaLBKWdJ0IjVCB/kgfriDD4WpZkvytCmgIU8qe0nRhv45XJh9s5USZx7IK83H7xesnqkgzn0WBmzXbTtVtTbuThbJpq16blgbqVnyJY4HdJDVk5PVEpbDNj7TaTgdUI6s1d8S+znQVi/ORe9LeEtfrIYv1E4TE1g2JiEHA

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
	print(request.frame)
	
	response = HTTP(con.recv(8192))
	con.close()

	print(response)

	session['access_token'] = response.payload['access_token']
	session['client_id'] = response.payload['client_id']

	url = 'https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/public/assets/v2/platform/Windows/launcher?label=Live-Belica&clientVersion=7.11.0-4118508%2B%2B%2BPortal%2BRelease-Live-Windows&machineId=a03c4960470f8fb19aa12a938ae76749'
	con = connection(url)
	request = HTTP_SEND('GET', url, {
			'Host': con.hostname,
			'Accept': '*/*',
			'Content-Type': 'application/json',
			'X-Epic-Correlation-ID': 'UE4-{device_id}-781BD437424E897104848D98B063BE14-CA83104841917E41C1AD96A01156F69B'.format(**config),
			'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
			'Content-Length': '0',
			'Authorization': 'bearer {}'.format(session['access_token'])
		}, payload={'grant_type' : 'client_credentials', 'token_type' : 'eg1'}, cookies=cookies)
	
	con.send(request.frame)
	print(request)
	
	response = HTTP(con.recv(8192*2))
	con.close()

	print(response)

	return response

def exchange_token():
	print(session['access_token'])
	con = connection(URLs['OAUTH_TOKEN'])
	request = HTTP_SEND('POST', URLs['OAUTH_TOKEN'], {
			'Host': con.hostname,
			'Accept': '*/*',
			'Content-Type': 'application/x-www-form-urlencoded',
			'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
			'Authorization': 'basic {}'.format(b64encode(config['launcher_key']).decode('UTF-8'))
		}, payload={'grant_type' : 'refresh_token',
					'refresh_token' : session['access_token'],
					'includePerms' : 'true',
					'token_type' : 'eg1'})

	con.send(request.frame)
	print(request)

	response = HTTP(con.recv(8192))
	con.close()

	print(response)
	return response

# def exchange_token():
# 	con = connection(URLs['OAUTH_EXCHANGE'])
# 	request = HTTP_SEND('GET', URLs['OAUTH_EXCHANGE'], {
# 			'Host': con.hostname,
# 			'Accept': '*/*',
# 			'Content-Type': 'application/json',
# 			'Content-Length' : '0',
# 			'User-Agent': 'game=UELauncher, engine=UE4, build=7.11.0-4118508+++Portal+Release-Live',
# 			'Authorization': 'bearer {}'.format(session['access_token'])
# 		})
	
# 	con.send(request.frame)
# 	print(request)
	
# 	response = HTTP(con.recv(8192))
# 	con.close()

# 	print(response)
# 	return response

response = fake_launcher()
if 'access_token' in session:
	print('[Notice] Launcher successfully "started".')

response = exchange_token()