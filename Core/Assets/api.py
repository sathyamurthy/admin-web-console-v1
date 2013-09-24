import copy
import sys
import json as simplejson
import urlparse

from django.db import IntegrityError
from django.core.serializers import json
from django.template import loader, Context

from tastypie.resources import ModelResource
from tastypie import fields
from tastypie.http import HttpResponse
from tastypie.serializers import Serializer
from tastypie.exceptions import BadRequest,Unauthorized
from tastypie.serializers import Serializer

from Assets.models import ExtendedContent,Properties,GalleryPreset
#from SiteManagement.log import StormLog,ACCESS_TOKEN,PROJECT_ID
from UserManagement import get_user
from UserManagement.authendication import CheckForAuthentication,CheckForAuthorization
from Countries.models import WorldCountries

#log = StormLog(ACCESS_TOKEN,PROJECT_ID)
def RenderHTML(jsonform):
    # ...
    #print >> sys.stdout,jsonform
    t = loader.get_template('base_templates/Extended/Gallery_form.html')
    
    c = Context({
        'sample':'oiuiuu',
    
        'form': (jsonform),
    })
    return t.render(c)

class PrettyJSONSerializer(Serializer):
    json_indent = 2

    def to_json(self, data, options=None):
        options = options or {}
        data = self.to_simple(data, options)
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder,
                sort_keys=True, ensure_ascii=False, indent=self.json_indent)


class Countries(ModelResource):
    #parent = fields.ForeignKey('self', 'parent', null=True)

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['countries'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict


    class Meta:
        queryset = WorldCountries.objects.all()
        include_resource_uri = True
        #fields = ['category_name','id','parent']

    def get_object_list(self, request):
        return super(Countries, self).get_object_list(request)

class Properties(ModelResource):
    #parent = fields.ForeignKey('self', 'parent', null=True)

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['properties'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict


    class Meta:
        queryset = Properties.objects.all()
        include_resource_uri = False
        #fields = ['category_name','id','parent']

    def get_object_list(self, request):
        user_inputs = simplejson.dumps(super(Properties, self).get_object_list(request))
        return user_inputs
        #return super(Properties, self).get_object_list(request)


class GalleryPresetDetail(ModelResource):

    properties = fields.ManyToManyField('Assets.api.Properties', 'properties',related_name='properties', full=True,null=True, blank=True)

    class Meta:
        queryset = GalleryPreset.objects.all()
        #excludes = ['id']
        resource_name = 'gallerypreset/detail'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()


    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Extended.Edit'):
            user_inputs = (super(GalleryPresetDetail, self).get_object_list(request).filter(pk=request.GET['gid']))
            return user_inputs
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        
    def dehydrate(self, bundle):
        #print >> sys.stdout,simplejson.dumps(bundle.data['properties'])
        Properties = {'properties':[]}
        for p in bundle.data['properties']:
            Properties['properties'].append((p.data))
            #print >> sys.stdout,simplejson.dumps(p.data)
        #print >> sys.stdout,simplejson.dumps(Properties)
        for p in Properties['properties']:
            try:
                p['value'] = simplejson.loads(p['value'].replace('u\'','"').replace('\'','"'))
                #print >> sys.stdout,p['value'].replace('u','').replace('\'','"')
            except:
                pass
        bundle.data['properties_html'] = RenderHTML(Properties)
        #bundle.data['items'] = simplejson.dumps(bundle.data['items'])
        return bundle

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                #print >> sys.stdout, RenderHTML(copy.copy(data_dict['objects']))
                data_dict['gallery'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict

class GalleryPresetList(ModelResource):
    #print >> sys.stdout, category
    class Meta:
        queryset = GalleryPreset.objects.all()
        #excludes = ['id']
        resource_name = 'gallerypreset/list'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()


    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Extended.Create'):
            return super(GalleryPresetList, self).get_object_list(request)
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['gallery_preset'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict

class GalleryPreset(ModelResource):
    #parent = fields.ForeignKey('self', 'parent', null=True)

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                print >> sys.stdout,data_dict
                # Rename the objects.
                data_dict['preset'] = copy.copy(data_dict['objects'])
                
                del(data_dict['objects'])
        return data_dict

    class Meta:
        queryset = GalleryPreset.objects.all()
        include_resource_uri = True
        #fields = ['category_name','id','parent']

    def get_object_list(self, request):
        return super(GalleryPreset, self).get_object_list(request)

class urlencodeSerializer(Serializer):
    formats = ['json', 'jsonp', 'xml', 'yaml', 'html', 'plist', 'urlencode']
    content_types = {
        'json': 'application/json',
        'jsonp': 'text/javascript',
        'xml': 'application/xml',
        'yaml': 'text/yaml',
        'html': 'text/html',
        'plist': 'application/x-plist',
        'urlencode': 'application/x-www-form-urlencoded',
        }
    def from_urlencode(self, data,options=None):
        """ handles basic formencoded url posts """
        qs = dict((k, v if len(v)>1 else v[0] )
            for k, v in urlparse.parse_qs(data).iteritems())
        return qs

    def to_urlencode(self,content): 
        pass
class CreateGallery(ModelResource):
    countries = fields.ManyToManyField('Assets.api.Countries', 'countries',related_name='countries', full=True,null=True, blank=True)

    class Meta:
        object_class = ExtendedContent
        queryset = ExtendedContent.objects.all()
        excludes = ['created']
        allowed_methods = ['post','put']
        include_resource_uri = False
        serializer = urlencodeSerializer()
        resource_name = 'extended/create'
        always_return_data = True
        authorization = CheckForAuthorization()


    def hydrate_m2m(self,bundle):
        User = get_user(bundle.request)
        #print >> sys.stdout,bundle.obj.countries
        try :
            country = WorldCountries.objects.get(country_name=User.country)
            bundle.obj.countries.add(country)
            #bundle.data.countries.add(country)
        except:
            pass
        


    def dehydrate(self, bundle):
        bundle.data['properties'] = simplejson.dumps(bundle.data['properties'])
        bundle.data['items'] = simplejson.dumps(bundle.data['items'])
        return bundle

    def obj_update(self, bundle,  **kwargs):
        #print >> sys.stdout, bundle.request
        request = bundle.request
        if self.Meta.authorization.is_authorized(request,'Extended.Edit'):
            try:
                try:
                   
                    bundle.data['properties'].replace('u','')
                    bundle.data['items'].replace('u','')

                    bundle = super(CreateGallery, self).obj_update(bundle, **kwargs)
                    bundle.obj.save()
                    
                except AttributeError:
                    pass
                """
                try:
                    log.send('Gallery Edited',sourcetype='syslog', host='addmin')
                except:
                    pass
                """
            except IntegrityError:
                raise BadRequest('Gallery id already exists')
            return bundle

        else:
            raise Unauthorized("Permission denied")

    def obj_create(self, bundle,  **kwargs):
        request = bundle.request
        if self.Meta.authorization.is_authorized(request,'Extended.Create'):
            try:
                try:
                    bundle.data['properties'].replace('u','')
                    bundle.data['items'].replace('u','')
                    #print >> sys.stdout, bundle.obj
                    bundle = super(CreateGallery, self).obj_create(bundle, **kwargs)
                    bundle.obj.save()
                    
                except AttributeError:
                    pass
                
            except IntegrityError:
                raise BadRequest('Gallery id already exists')
                #raise
            

        else:
            raise Unauthorized("Permission denied")
        return bundle
        
    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                print >> sys.stdout, data_dict['objects']
                data_dict['extended_create'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict
        

class GalleryList(ModelResource):
    #print >> sys.stdout, category
    gallery_preset = fields.ManyToManyField('Assets.api.GalleryPresetList', 'gallery_preset',related_name='gallery_preset', full=True,null=True, blank=True)
    class Meta:
        queryset = ExtendedContent.objects.all()
        #excludes = ['id']
        resource_name = 'extended/list'
        include_resource_uri = False
        excludes = ['properties','items']
        #serializer = Serializer(formats=['json', 'jsonp', 'xml', 'yaml', 'html', 'plist'])
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()

    def dehydrate(self, bundle):
        #bundle.data['properties'] = simplejson.dumps(bundle.data['properties'])
        #bundle.data['items'] = simplejson.dumps(bundle.data['items'])
        #bundle.data['gallery_presets'] = GalleryPreset.objects.all()
        return bundle


    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Extended.Create'):
            return super(GalleryList, self).get_object_list(request).filter(countries=User.country)
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['extended_content'] = copy.copy(data_dict['objects'])
                data_dict['edit'] = self.Meta.authorization.is_authorized(request,'Extended.Edit')
                
                del(data_dict['objects'])
        return data_dict

class GalleryDetail(ModelResource):
    #print >> sys.stdout, category
    class Meta:
        queryset = ExtendedContent.objects.all()
        #excludes = ['id']
        resource_name = 'extended/detail'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()

    def dehydrate(self, bundle):
        bundle.data['properties'] = simplejson.loads(bundle.data['properties'].replace('u\'','"').replace('\'','"'))
        bundle.data['items'] = simplejson.dumps(bundle.data['items'])
        
        #bundle['body'] = simplejson.loads(bundle.data['body'])
        #print >> sys.stdout,bundle
        #print >> sys.stdout,bundle.data['properties'].replace('u','')
        return bundle

    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Extended.Create'):
            return super(GalleryDetail, self).get_object_list(request).filter(countries=User.country).filter(pk=request.GET['gid'])
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['extended_content'] = copy.copy(data_dict['objects'])
                data_dict['edit'] = self.Meta.authorization.is_authorized(request,'Extended.Create')
                del(data_dict['objects'])
        return data_dict

