import oauth2 as oauth
import time
import urllib

class OAuthEntity:
	def __init__(self, app, consumer_key, consumer_secret, \
				request_token_url, access_token_url, \
				authorize_url, short_post_url):
		self.app = app
		self.consumer_key = consumer_key
		self.consumer_secret = consumer_secret
		self.request_token_url = request_token_url
		self.access_token_url = access_token_url
		self.authorize_url = authorize_url
		self.short_post_url = short_post_url
		self.consumer = oauth.Consumer(consumer_key, consumer_secret)

	def short_post(self, post, user_access):
		url = self.short_post_url
		if self.app == 'TWITTER':
			if len(post) > 140:
				return {'success': False, 'reason': 'Message too long'}
			body = {'status': post}
		elif self.app == 'TUMBLR':
			tumblr_base = user_access.user.get_profile().tumblr_base
			if not tumblr_base:
				return {'success': False, 'reason': 'No tumblr url configured'}
			body = {'type': 'text', 'body': post}
			url = url.replace('{tumblr_base}', tumblr_base)
		elif self.app =='FACEBOOK':
			facebook_id = user_access.user.get_profile().facebook_id
			if not facebook_id:
				return {'success': False, 'reason': 'No facebook id configured'}
			body = {'message': post, 'access_token': user_access.oauth_token}
			url = url.replace('{facebook_id}', facebook_id)
		token = oauth.Token(key=user_access.oauth_token, secret=user_access.oauth_secret)
		client = oauth.Client(self.consumer, token)
		resp, content = client.request(url, method="POST", body=urllib.urlencode(body))
		if resp['status'] == '201' or resp['status'] == '200':
			return {'success': True}
		else:
			return {'success': False, 'reason': 'Response ' + resp}

	