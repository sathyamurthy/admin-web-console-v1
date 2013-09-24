import copy
import sys
import json as simplejson

from django.core.serializers import json

from tastypie.resources import ModelResource
from tastypie import fields
from tastypie.exceptions import Unauthorized
from tastypie.serializers import Serializer

from UserManagement.models import User,UserGroups
from Categories.models import Categories
from UserManagement import get_user
from UserManagement.authendication import CheckForAuthentication,CheckForAuthorization
from Components.models import UserPrivilleges

class PrettyJSONSerializer(Serializer):
    json_indent = 2

    def to_json(self, data, options=None):
        options = options or {}
        data = self.to_simple(data, options)
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder,
                sort_keys=True, ensure_ascii=False, indent=self.json_indent)


class Permissions(ModelResource):
    #parent = fields.ForeignKey('self', 'parent', null=True)

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['permissions'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict


    class Meta:
        queryset = UserPrivilleges.objects.all()
        excludes = ['show_as_link']
        include_resource_uri = False
        #fields = ['category_name','id','parent']

    def get_object_list(self, request):
        return super(Permissions, self).get_object_list(request)

class CategoriesInformation(ModelResource):
    #parent = fields.ForeignKey('self', 'parent', null=True)

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['categories'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict


    class Meta:
        serializer = PrettyJSONSerializer()
        queryset = Categories.objects.all()
        include_resource_uri = False
        #fields = ['category_name','id','parent']

    def get_object_list(self, request):
        User = get_user(request)
        return super(CategoriesInformation, self).get_object_list(request).filter(countries=User.country)

 

class GroupsList(ModelResource):
    category = fields.ManyToManyField('UserManagement.api.CategoriesInformation', 'category',related_name='category', full=True,null=True, blank=True)
    modules = fields.ManyToManyField('UserManagement.api.Permissions', 'modules',related_name='modules', full=True,null=True, blank=True)
    #print >> sys.stdout, category
    class Meta:
        queryset = UserGroups.objects.all()
        #excludes = ['id']
        resource_name = 'groups/list'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()


    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Groups.Create'):
            gid = None
            try:
                gid = request.GET['gid']
            except:
                pass
            if gid is not None:
                return super(GroupsList, self).get_object_list(request).filter(countries=User.country).filter(pk=gid)
            else:
                return super(GroupsList, self).get_object_list(request).filter(countries=User.country)
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['groups'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict

class UsersList(ModelResource):
    class Meta:
        queryset = User.objects.all()
        excludes = ['id', 'password', 'is_superuser']
        resource_name = 'users/list'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()

    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized(request,'Users.Create'):
            gid = None
            try:
                gid = request.GET['gid']
            except:
                pass
            if gid is not None:
                return super(UsersList, self).get_object_list(request).filter(country=User.country).filter(groups=gid)
            else:
                return super(UsersList, self).get_object_list(request).filter(country=User.country)
            
        else:
            raise Unauthorized("Permission denied")    
        #print >> sys.stdout,self.Meta.authorization.is_authorized(request,'Users.List')
        

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                #del(data_dict['meta'])
                # Rename the objects.
                data_dict['users'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict    


