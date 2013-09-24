from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from django.views.generic.base import TemplateView
from Core.Backend.PrivilegeManagement import site
from Client.Ikea.Users.models import Market
import sys
admin.autodiscover()
#site.cutomer_autodiscover();
#from app.api import CabinetResource
#cabinet_resource = CabinetResource()
#from Core.Countries.models import WorldCountries
#from UserManagement.api import UsersList,GroupsList
#from UserManagement.usersapi import READGroup,GroupsPermission,BookCategories,CRUDGroup,CRUDUser
#from Assets.api import GalleryPresetDetail,GalleryPresetList,GalleryList,GalleryDetail,CreateGallery
#from Uploader.api import FilesList,FileDetail

#from tastypie.api import Api
#v1_api = Api(api_name='v1')
##v1_api.register(UsersList())
##v1_api.register(GroupsList())
#v1_api.register(GroupsPermission())
#v1_api.register(BookCategories())
#v1_api.register(CRUDGroup())
#v1_api.register(CRUDUser())
#v1_api.register(READGroup())



#v1_api.register(GalleryPresetDetail())
#v1_api.register(GalleryPresetList())
#v1_api.register(GalleryList())
#v1_api.register(GalleryDetail())
#v1_api.register(CreateGallery())
#v1_api.register(FilesList())
#v1_api.register(FileDetail())


from Core.UserManagement.views import homepage
urlpatterns = patterns('',    url(r'^$', homepage, name='home'),)
urlpatterns += patterns('',
    # url(r'^catalog/', include('catalog.foo.urls')),
    
    url(r'^editor/', include(admin.site.urls)),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^home/', include(site.usersite.urls)),
    #url(r'^api/', include(v1_api.urls)),
    #url(r'^gallery/upload/', include('Uploader.urls')),
)
from django.db.models import Q
#for country in WorldCountries.objects.filter(~Q(pk=1000)):
for market in Market.objects.all():
    pattern = r'^ikea/'+market.country.iso_code+'/'
    #print >> sys.stdout,pattern 
    urlpatterns += patterns(market.country.iso_code,
        url(r'^ikea/%s/' % (market.country.iso_code),include(site.usersite.geturls(app_name=market.country.iso_code,name=market.country.iso_code)))
    )

#print >> sys.stdout,admin.site.urls 
"""
for country in WorldCountries.objects.all():
    pattern = r'^'+country.iso_code+'/'
    #print >> sys.stdout,pattern 
    urlpatterns += patterns(country.iso_code,
        url(r'^%s/' % (country.iso_code),include(site.usersite.urls,app_name=country.iso_code))
    )
"""

import os
urlpatterns += patterns('',
        (r'^upload/(.*)$', 'django.views.static.serve', {'document_root': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'upload')}),
)
urlpatterns += patterns('',
        (r'^static/(.*)$', 'django.views.static.serve', {'document_root': os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')}),
)



