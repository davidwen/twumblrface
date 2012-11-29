from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.template import Context, RequestContext, loader
from django.shortcuts import redirect, render_to_response
from django.http import HttpResponse

from forms import CreateUserForm
from models import UserAccess, UserProfile
from oauth_entities import OAuthEntity

import cgi
import oauth2 as oauth
import urlparse
import urllib
import urllib2

# Override these variables in oauth_settings.py
twitter_key = 'twitter_key'
twitter_secret = 'twitter_secret'
tumblr_key = 'tumblr_key'
tumblr_secret = 'tumblr_secret'
facebook_key = 'facebook_key'
facebook_secret = 'facebook_secret'
base_url = 'http://twumblrface.example'

try:
	from oauth_settings import *
except ImportError:
	pass

twitter = OAuthEntity( \
	app='TWITTER', \
	consumer_key=twitter_key, \
	consumer_secret=twitter_secret, \
	request_token_url='http://twitter.com/oauth/request_token', \
	access_token_url='http://twitter.com/oauth/access_token', \
	authorize_url='http://twitter.com/oauth/authorize', \
	short_post_url='https://api.twitter.com/1/statuses/update.json')

tumblr = OAuthEntity( \
	app='TUMBLR', \
	consumer_key=tumblr_key, \
	consumer_secret=tumblr_secret, \
	request_token_url='http://www.tumblr.com/oauth/request_token', \
	access_token_url='http://www.tumblr.com/oauth/access_token', \
	authorize_url='http://www.tumblr.com/oauth/authorize', \
	short_post_url='http://api.tumblr.com/v2/blog/{tumblr_base}/post')

facebook = OAuthEntity( \
	app='FACEBOOK', \
	consumer_key=facebook_key, \
	consumer_secret=facebook_secret, \
	request_token_url='https://www.facebook.com/dialog/oauth/', \
	access_token_url='https://graph.facebook.com/oauth/access_token', \
	authorize_url='', \
	short_post_url='https://graph.facebook.com/{facebook_id}/feed')

entities = {'TWITTER': twitter, 'TUMBLR': tumblr, 'FACEBOOK': facebook}

def index(request):
	t = loader.get_template('home/index.html')
	c = Context({})
	return HttpResponse(t.render(c))

@login_required
def dashboard(request, success='', errors=''):
	# Initialize access map
	access_map = {}
	for app in entities.keys():
		access_map[app] = False

	user_accesses = UserAccess.objects.filter(user=request.user)	
	for access in user_accesses:
		access_map[access.app] = True

	return render_to_response( \
		'home/dashboard.html', \
		{
			'profile': request.user.get_profile(), \
			'twitter_linked': access_map['TWITTER'], \
			'tumblr_linked': access_map['TUMBLR'], \
			'facebook_linked': access_map['FACEBOOK'], \
			'success': success, \
			'errors': errors \
		}, \
		context_instance=RequestContext(request))

def link(request, app):
	app = app.upper()
	if app in entities.keys():
		entity = entities[app]
		method = "GET"
		if (entity.app == 'FACEBOOK'):
			params = {
				'scope': 'publish_stream',
				'client_id': entity.consumer_key,
				'redirect_uri': facebook_redirect,
				'response_type': 'code'
			}
			url = "%s?%s" % (entity.request_token_url, urllib.urlencode(params))
			return redirect(url)
		elif (entity.app == 'TUMBLR'):
			method = "POST"
		client = oauth.Client(entity.consumer)
		resp, content = client.request(entity.request_token_url, method)
		if resp['status'] != '200':
			raise Exception("Invalid response %s." % resp['status'])	
		request.session['request_token'] = dict(cgi.parse_qsl(content))
		url = "%s?oauth_token=%s" % (entity.authorize_url, request.session['request_token']['oauth_token'])
		return redirect(url)

@login_required
def unlink(request, app):
	app = app.upper()
	try:
		user_access = UserAccess.objects.get(user=request.user, app=app)
	except UserAccess.DoesNotExist:
		return dashboard(request, success=app.capitalize() + ' unlinked.')
	user_access.delete()
	return dashboard(request, success=app.capitalize() + ' unlinked.')

def authenticate_entity(request, app):
	user = request.user
	app = app.upper()
	success = ''
	if app == 'FACEBOOK':
		entity = facebook
		params = { 
			'client_id': entity.consumer_key,
			'client_secret': entity.consumer_secret,
			'redirect_uri': facebook_redirect,
			'code': request.GET['code']
		}
		client = oauth.Client(entity.consumer)
		url = "%s?%s" % (entity.access_token_url, urllib.urlencode(params))
		resp, content = client.request(url, "GET")
		if resp['status'] != '200':
			raise Exception("Invalid response.")

		access_token = dict(cgi.parse_qsl(content))
		
		if (user.is_anonymous()):
			try:
				user_access = UserAccess.objects.get( \
					oauth_token=access_token['access_token'], app=entity.app)
				# Case where there exists an entry for the attempted 
				# authentication already. Log in as this user.
				user = authenticate(username=user_access.user.username, password=' ')
				login(request, user)
			except UserAccess.DoesNotExist:
				# Case where no entry exists. Create a new user for this entry,
				# create a new entry, and log in as user.
				user_id = User.objects.order_by('-id')[0].id + 1
				user = User.objects.create_user(str(user_id), '', ' ')
				user.save()
				user = authenticate(username=user.username, password=' ')
				login(request, user)
				user_access = UserAccess()
				user_access.user = user
				user_access.app = entity.app
				success = 'Welcome! ' + entity.app.capitalize() + ' linked.'
			user_access.oauth_token = exchangeFacebookToken(access_token['access_token'])
			user_access.save()
		else:
			try:
				# Case where user already has this entry. Update token.
				user_access = UserAccess.objects.get(user=user, app=entity.app)
				user_access.oauth_token = exchangeFacebookToken(access_token['access_token'])
				user_access.save()
			except UserAccess.DoesNotExist:
				try: 
					user_access = UserAccess.objects.get( \
						oauth_token=access_token['access_token'], app=entity.app)
					# Case where user accessed an entry assigned to another user.
					# Merge these two accounts.
					mergeUsers(user, user_access.user)
					success = 'Account merged.'
				except UserAccess.DoesNotExist:
					# Case where user is linking to new entry.
					user_access = UserAccess()
					user_access.user = user
					user_access.app = entity.app
					user_access.oauth_token = exchangeFacebookToken(access_token['access_token'])
					user_access.save()
					success = entity.app.capitalize() + ' linked.'
	elif app == 'TWITTER' or app == 'TUMBLR':
		entity = entities[app]
		method = "POST"
		token = oauth.Token(request.session['request_token']['oauth_token'], request.session['request_token']['oauth_token_secret'])
		client = oauth.Client(entity.consumer, token)
		query = 'oauth_verifier=' + request.GET['oauth_verifier']
		resp, content = client.request(entity.access_token_url, method, query)
		if resp['status'] != '200':
			raise Exception("Invalid response %s." % resp['status'])

		access_token = dict(cgi.parse_qsl(content))

		if (user.is_anonymous()):
			try:
				user_access = UserAccess.objects.get( \
					oauth_token=access_token['oauth_token'], app=entity.app)
				# Case where there exists an entry for the attempted 
				# authentication already. Log in as this user.
				user = authenticate(username=user_access.user.username, password=' ')
				login(request, user)
			except UserAccess.DoesNotExist:
				# Case where no entry exists. Create a new user for this entry,
				# create a new entry, and log in as user.
				user_id = User.objects.order_by('-id')[0].id + 1
				user = User.objects.create_user(str(user_id), '', ' ')
				user.save()
				user = authenticate(username=user.username, password=' ')
				login(request, user)
				user_access = UserAccess()
				user_access.user = user
				user_access.app = entity.app
				success = 'Welcome! ' + entity.app.capitalize() + ' linked.'
			user_access.oauth_token = access_token['oauth_token']
			user_access.oauth_secret = access_token['oauth_token_secret']
			user_access.save()
		else:
			try:
				# Case where user already has this entry. Update token.
				user_access = UserAccess.objects.get(user=user, app=entity.app)
				user_access.oauth_token = access_token['oauth_token']
				user_access.oauth_secret = access_token['oauth_token_secret']
				user_access.save()
			except UserAccess.DoesNotExist:
				try: 
					user_access = UserAccess.objects.get( \
						oauth_token=access_token['oauth_token'], app=entity.app)
					# Case where user accessed an entry assigned to another user.
					# Merge these two accounts.
					mergeUsers(user, user_access.user)
					success = 'Accounts merged.'
				except UserAccess.DoesNotExist:
					# Case where user is linking to new entry.
					user_access = UserAccess()
					user_access.user = user
					user_access.app = entity.app
					user_access.oauth_token = access_token['oauth_token']
					user_access.oauth_secret = access_token['oauth_token_secret']
					user_access.save()
					success = entity.app.capitalize() + ' linked.'
	return dashboard(request, success=success)

@login_required
def post(request):
	if request.method == 'POST':
		postTo = request.POST.getlist('postTo')
		user_accesses = UserAccess.objects.filter(user=request.user).filter(app__in=postTo)
		if len(user_accesses) == 0:
			return dashboard(request, errors="No linked sites to post to.")
		if not request.POST.has_key('post') or not request.POST['post']:
			return dashboard(request, errors="No message to post.")
		success = ''
		errors = ''
		successful_apps = []
		failed_apps = []
		for user_access in user_accesses:
			result = entities[user_access.app].short_post(request.POST['post'], user_access)
			if (result['success']):
				successful_apps.append(user_access.app.capitalize())
			else:
				failed_apps.append(user_access.app.capitalize() + ' (' + result.reason + ')')
		if len(successful_apps) > 0:
			success = 'Posted to ' + ', '.join(successful_apps) + '.'
		if len(failed_apps) > 0:
			errors = 'Unable to post to ' + ', '.join(failed_apps) + '.'
		return dashboard(request, success=success, errors=errors)

@login_required
def account(request):
	return render_to_response( \
		'home/account.html', \
		{'profile': request.user.get_profile()}, \
		context_instance=RequestContext(request))

@login_required
def save_profile(request):
	tumblr_base = ''  
	facebook_id = ''
	if request.POST.has_key('tumblr_base'):
		tumblr_base = request.POST['tumblr_base']
	if request.POST.has_key('facebook_id'):
		facebook_id = request.POST['facebook_id']

	# Strip http:// and similar
	if tumblr_base and tumblr_base.find('://') >= 0:
		tumblr_base = tumblr_base[tumblr_base.find('://') + 3:]
	
	# Strip trailing slash
	if tumblr_base and tumblr_base.find('/') >= 0:
		tumblr_base = tumblr_base[:tumblr_base.find('/')]
			
	profile = request.user.get_profile()
	profile.tumblr_base = tumblr_base
	profile.facebook_id = facebook_id
	profile.save()
	return render_to_response( \
		'home/account.html', \
		{ \
			'profile': request.user.get_profile(), \
			'success': 'Profile saved.' \
		}, \
		context_instance=RequestContext(request))

def mergeUsers(userA, userB):
	a_accesses = UserAccess.objects.filter(user=userA)
	b_accesses = UserAccess.objects.filter(user=userB)
	merge_accesses = {}
	for b_access in b_accesses:
		merge_accesses[b_access.app] = b_access
	for a_access in a_accesses:
		merge_accesses[a_access.app] = a_access
	UserAccess.objects.filter(Q(user=userA) | Q(user=userB)).delete()
	for access in merge_accesses.values():
		access.user = userA
		access.save()

	a_profile = UserProfile.objects.get(user=userA)
	b_profile = UserProfile.objects.get(user=userB)
	a_profile.tumblr_base = a_profile.tumblr_base or b_profile.tumblr_base
	a_profile.facebook_id = a_profile.facebook_id or b_profile.facebook_id
	a_profile.save()

	b_profile.delete()
	userB.delete()

def exchangeFacebookToken(old_token):
	params = { \
		'client_id': facebook.consumer_key, \
		'client_secret': facebook.consumer_secret, \
		'grant_type': 'fb_exchange_token', \
		'fb_exchange_token': old_token \
	}
	url = "%s?%s" % (facebook.access_token_url, urllib.urlencode(params))
	resp = dict(urllib2.urlparse.parse_qsl(url))
	try:
		result = resp['access_token']
	except KeyError:
		result = old_token
	return result

facebook_redirect = base_url + reverse('home.views.authenticate_entity', args=['facebook'])