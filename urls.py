from django.conf.urls.defaults import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
	url(r'^$', 'home.views.dashboard'),
	url(r'^login/$', 'home.views.index'),
	url(r'^logout/$', 'django.contrib.auth.views.logout', {'template_name': 'home/index.html'}),
	url(r'^dashboard/$', 'home.views.dashboard'),
	url(r'^link/(\w+)/$', 'home.views.link'),
	url(r'^unlink/(\w+)/$', 'home.views.unlink'),
	url(r'^authenticate/(\w+)/$', 'home.views.authenticate_entity'),
	url(r'^dashboard/post/$', 'home.views.post'),
	url(r'^account/$', 'home.views.account'),
	url(r'^account/save/$', 'home.views.save_profile'),
	url(r'^admin/', include(admin.site.urls)),
)