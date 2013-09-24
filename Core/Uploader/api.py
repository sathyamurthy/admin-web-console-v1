import copy
import urlparse
import sys
import json as simplejson

from tastypie.resources import ModelResource
from tastypie import fields
from tastypie.http import HttpResponse
from tastypie.exceptions import Unauthorized,BadRequest
from tastypie.serializers import Serializer
from tastypie.serializers import Serializer

from django.core.serializers import json
from django.template import loader, Context
from django.db import IntegrityError

from Uploader.models import Files
#from SiteManagement.log import StormLog,ACCESS_TOKEN,PROJECT_ID
from UserManagement import get_user
from UserManagement.authendication import CheckForAuthentication,CheckForAuthorization


def RenderHTML(image_properies,ID,edit):
    # ...
    #print >> sys.stdout,jsonform
    t = loader.get_template('base_templates/Extended/Images.html')
    
    c = Context({
        'edit':edit,
        'id':ID,
        'list': (image_properies),
    })
    return t.render(c)


class PrettyJSONSerializer(Serializer):
    json_indent = 2

    def to_json(self, data, options=None):
        options = options or {}
        data = self.to_simple(data, options)
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder,
                sort_keys=True, ensure_ascii=False, indent=self.json_indent)


class FilesList(ModelResource):
    class Meta:
        queryset = Files.objects.all()
        #excludes = ['id']
        resource_name = 'files/list'
        include_resource_uri = False
        #max_limit = None
        #excludes = ['all']
        fields = ['limited_properties','id','relative_path','name','extension']
        #serializer = Serializer(formats=['json', 'jsonp', 'xml', 'yaml', 'html', 'plist'])
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()

    def dehydrate(self, bundle):
        bundle.data['properties'] = simplejson.loads(bundle.data['limited_properties'].replace('u\'','"').replace('\'','"'))
        #bundle.data['limited_properties'] = RenderHTML(bundle.data['properties'],bundle.data['id'],self.Meta.authorization.is_authorized(bundle.request,'Extended.Edit'))
        bundle.data['limited_properties'] = None
        return bundle


    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Extended.Create'):
            return super(FilesList, self).get_object_list(request).filter(gallery=request.GET['gid'])
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                #del(data_dict['meta'])
                # Rename the objects.
                data_dict['files'] = copy.copy(data_dict['objects'])
                data_dict['edit'] = self.Meta.authorization.is_authorized(request,'Extended.Edit')
                
                del(data_dict['objects'])
        return data_dict

class FileDetail(ModelResource):
    #print >> sys.stdout, category
    class Meta:
        queryset = Files.objects.all()
        #excludes = ['id']
        resource_name = 'files/detail'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()

    def dehydrate(self, bundle):
        bundle.data['properties'] = simplejson.loads(bundle.data['properties'].replace('u\'','"').replace('\'','"'))
        return bundle

    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Extended.Create'):
            return super(FilesDetail, self).get_object_list(request).filter(countries=User.country).filter(pk=request.GET['gid'])
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['file'] = copy.copy(data_dict['objects'])
                data_dict['edit'] = self.Meta.authorization.is_authorized(request,'Extended.Create')
                del(data_dict['objects'])
        return data_dict

