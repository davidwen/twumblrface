from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save

class UserProfile(models.Model):
	user = models.OneToOneField(User)
	tumblr_base = models.CharField(max_length=100)
	facebook_id = models.CharField(max_length=30)

	def __str__(self):
		return "%s's profile" % self.user

def create_user_profile(sender, instance, created, **kwargs):
	if created:
		UserProfile.objects.create(user=instance)
	
post_save.connect(create_user_profile, sender=User)

class UserAccess(models.Model):
	user = models.ForeignKey(User)
	app = models.CharField(max_length=30)
	oauth_token = models.CharField(max_length=200)
	oauth_secret = models.CharField(max_length=200)