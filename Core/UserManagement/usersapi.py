import copy
import sys
import json as simplejson

from django.core.serializers import json
from django.db import IntegrityError

from tastypie.resources import ModelResource
from tastypie import fields
from tastypie.exceptions import BadRequest,Unauthorized,TastypieError
from tastypie.serializers import Serializer

from django.conf import settings

from UserManagement.models import User,UserGroups
from Categories.models import Categories
from UserManagement import get_user
from UserManagement.authendication import CheckForAuthentication,CheckForAuthorization
from Components.models import UserPrivileges,ModulesGroup,UserModules
from Countries.models import WorldCountries
from Assets.api import urlencodeSerializer
from Loggers.models import Logging
from django.http import HttpResponse
from django import http



def handle_errors(options):
    Logging().log(request=options['R'],log_entry=options['A'],User=options['U'],log_type=options['L_T'],comments=options['E'],process_code=options['C'])
    raise BadRequest(options['E'])

def handle_errors_only_log(options):
    Logging().log(request=options['R'],log_entry=options['A'],User=options['U'],log_type=options['L_T'],comments=options['E'],process_code=options['C'])
 
class PrettyJSONSerializer(Serializer):
    json_indent = 2

    def to_json(self, data, options=None):
        options = options or {}
        data = self.to_simple(data, options)
        return simplejson.dumps(data, cls=json.DjangoJSONEncoder,
                sort_keys=True, ensure_ascii=False, indent=self.json_indent)


class Permissions(ModelResource):
    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['modules'] = []
                for module in UserModules.objects.filter(is_active=True):
                    data_dict['modules'].append({'name':module,'id':module.id})
                data_dict['permissions'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict

    def dehydrate(self, bundle):
        bundle.data['module'] = UserPrivileges.objects.get(privilege_id = bundle.data['privilege_id']).module.id
        return bundle
    class Meta:
        queryset = UserPrivileges.objects.all()
        resource_name = 'permission/list'
        include_resource_uri = False
        excludes = ['show_as_link']
        serializer = Serializer(formats=['json', 'jsonp', 'xml', 'yaml', 'html', 'plist'])
        authorization = CheckForAuthorization()

    def get_object_list(self, request):
        if self.Meta.authorization.is_authorized(request,'Groups.Create'):
            return super(Permissions, self).get_object_list(request)
        else:
            errors = {'error':['Permission denied']}
            options = {
                'R':request,
                'A':"/Users/Permission/list/Permission denied/",
                'U':get_user(request),
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)
            #raise Unauthorized("Permission denied")    




class BookCategories(ModelResource):
    parent = fields.ForeignKey('self', 'parent', null=True)
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
        resource_name = 'categories/category'
        queryset = Categories.objects.all()
        include_resource_uri = False
        serializer = urlencodeSerializer()
        allowed_methods = ['get','post','patch']
        fields = ['category_name']
        serializer = urlencodeSerializer()
        always_return_data = True
        authorization = CheckForAuthorization()
        #fields = ['category_name','id','parent']

    def hydrate_m2m(self,bundle):
        return bundle

    def hydrate(self, bundle):
        return bundle
    

    def obj_create(self, bundle,  **kwargs):
        request = bundle.request
        User = get_user(bundle.request)
        action = str(User.pk)+"/" + bundle.request.POST['category_name']
        if User.is_superuser:
        #if self.Meta.authorization.is_authorized(request,'Groups.Create'):
            try:
                try:
                    newCategory = Categories(category_name =bundle.request.POST['category_name'])
                    #newCategory.children.add(Categories.objects.get(pk=bundle.request.POST['parent']))
                    Categories.objects.get(pk=bundle.request.POST['parent']).children.add(newCategory)
                    country = WorldCountries.objects.get(country_name=User.country)
                    newCategory.countries.add(country)
                    newCategory.owner = country.pk
                    newCategory.is_system_folder = False
                    newCategory.save()
                    bundle.obj = newCategory
                    bundle.obj.id = newCategory.pk
                    #bundle = super(BookCategories, self).obj_create(bundle, **kwargs)
                except AttributeError, e:
                    errors = {'error':[str(e)]}
                    options = {
                        'R':bundle.request,
                        'A':"/Categories/Category/Update/Application error(attribute)/" +action,
                        'U':User,
                        'L_T':'app',
                        'E':errors,
                        'C':500,
                    }
                    handle_errors_only_log(options)                    
            except IntegrityError, e1:
                errors = {'error':[str(e1)]}
                options = {
                    'R':bundle.request,
                    'A':"/Categories/Category/Create/Application error(integrity)/" +action,
                    'U':User,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)                    
        else:
            #raise Unauthorized("Permission denied")
            errors = {'error':['Permission denied']}
            options = {
                'R':bundle.request,
                'A':"/Categories/Category/Update/Permission denied(Not a super admin user)/" +action,
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)
            
        try:
            #action = str(User.pk)+"/" +str(bundle.obj.id)+"/" + bundle.request.POST['category_name']
            #Logging().log_200(request=bundle.request,User=User,case_id=1000,log_type="app",action=action)
            action = "/Categories/category/Create/Success/" + action
            Logging().log(request=bundle.request,log_entry=action,User=User,log_type="app",comments="Created successfully",process_code=200)
            
        except:
            pass

        return bundle        

    def obj_update(self, bundle,  **kwargs):
        request = bundle.request
        User = get_user(bundle.request)
        action = str(User.pk)+"/" +str(bundle.obj.id)+"/" + bundle.request.POST['category_name']
        if not bundle.obj.owner==User.country.pk:
            if bundle.obj.is_system_folder:
                errors = {'error':['Permission denied to modify system folder']}
                options = {
                    'R':bundle.request,
                    'A':"/Categories/Category/Update/Permission denied(system folder)/" +action,
                    'U':User,
                    'L_T':'app',
                    'E':errors,
                    'C':401,
                }
                handle_errors(options)

                #raise Unauthorized("Permission denied to modify other user folders")
            else:
                errors = {'error':['Permission denied to modify other market folders']}
                options = {
                    'R':bundle.request,
                    'A':"/Categories/Category/Update/Access violation(modifying other market folders)/" +action,
                    'U':User,
                    'L_T':'app',
                    'E':errors,
                    'C':401,
                }
                handle_errors(options)

                #raise Unauthorized("Permission denied to modify other user folders")

        if User.is_superuser:
            if bundle.obj.is_system_folder:
                errors = {'error':['Permission denied to modify system folder']}
                options = {
                    'R':bundle.request,
                    'A':"/Categories/Category/Update/Permission denied(system folder)/" +action,
                    'U':User,
                    'L_T':'app',
                    'E':errors,
                    'C':401,
                }
                handle_errors(options)
            else:
                try:
                    try:
                        bundle = super(BookCategories, self).obj_update(bundle, **kwargs)
                        bundle.obj.save()
                    except AttributeError, e:
                        errors = {'error':[str(e)]}
                        options = {
                            'R':bundle.request,
                            'A':"/Categories/Category/Update/Application error(attribute)/" +action,
                            'U':User,
                            'L_T':'app',
                            'E':errors,
                            'C':500,
                        }
                        handle_errors(options)                    
                except IntegrityError, e1:
                    errors = {'error':[str(e1)]}
                    options = {
                        'R':bundle.request,
                        'A':"/Categories/Category/Update/Application error(integrity)/" +action,
                        'U':User,
                        'L_T':'app',
                        'E':errors,
                        'C':500,
                    }
                    handle_errors(options)                    

        else:
            errors = {'error':['Permission denied']}
            options = {
                'R':bundle.request,
                'A':"/Categories/Category/Update/Permission denied/" +action,
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)
        try:
            #action = str(User.pk)+"/" +str(bundle.obj.id)+"/" + bundle.request.POST['category_name']
            #Logging().log_201(request=bundle.request,User=User,case_id=1000,log_type="app",action=action)
            action = "/Categories/category/Edit/Success/" + str(User.pk)+"/" +str(bundle.obj.id)+"/" + bundle.request.POST['category_name']
            Logging().log(request=bundle.request,log_entry=action,User=User,log_type="app",comments="Updated successfully",process_code=201)
            
        except:
            pass
        return bundle        

    def get_child_data(self, obj):
        data =  {
            'id': obj.id,
            'category_name': obj.category_name,
        }
        if not obj.is_leaf_node():
            data['children'] = [self.get_child_data(child) \
                                for child in obj.get_children()]
        return data

    def get_list(self, request, **kwargs):

        base_bundle = self.build_bundle(request=request)
        objects = self.obj_get_list(bundle=base_bundle, **self.remove_api_resource_names(kwargs))
        sorted_objects = self.apply_sorting(objects, options=request.GET)

        paginator = self._meta.paginator_class(
            request.GET, sorted_objects, 
            resource_uri=self.get_resource_uri(), limit=self._meta.limit, 
            max_limit=self._meta.max_limit, 
            collection_name=self._meta.collection_name
        )
        to_be_serialized = paginator.page()

        from mptt.templatetags.mptt_tags import cache_tree_children
        objects = cache_tree_children(objects)

        bundles = []

        for obj in objects:
            data = self.get_child_data(obj)
            bundle = self.build_bundle(data=data, obj=obj, request=request)
            bundles.append(self.full_dehydrate(bundle))

        to_be_serialized[self._meta.collection_name] = bundles
        to_be_serialized = self.alter_list_data_to_serialize(request, 
                                                            to_be_serialized)
        return self.create_response(request, to_be_serialized)
    
    def get_object_list(self, request):
        User = get_user(request)
        return super(BookCategories, self).get_object_list(request).filter(countries=User.country)


class CategoriesInformation(ModelResource):
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
        fields = ['category_name','id']
        #fields = ['category_name','id','parent']

    def get_object_list(self, request):
        User = get_user(request)
        return super(CategoriesInformation, self).get_object_list(request).filter(countries=User.country)
 

class READGroup(ModelResource):
    class Meta:
        queryset = UserGroups.objects.all()
        #excludes = ['id']
        resource_name = 'groups/limit'
        include_resource_uri = False
        serializer = urlencodeSerializer()
        allowed_methods = ['get']
        fields = ['group_name','id']
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['groups'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict
    
    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized_collection(request=request,permission=['Groups.Create','Groups.Edit','Groups.List'],atleast_one=True):
            return super(READGroup, self).get_object_list(request).filter(countries=User.country)
        else:
            #raise Unauthorized("Permission denied")    
            errors = {'error':['Permission denied']}
            options = {
                'R':request,
                'A':"/Users/Groups/Permission list/Access violation/",
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)                    

        #if self.Meta.authorization.is_authorized(request,'Groups.Create') or self.Meta.authorization.is_authorized(request,'Groups.List'):
        #    return super(READGroup, self).get_object_list(request).filter(countries=User.country)
        #else:
        #    raise Unauthorized("Permission denied")      
class CRUDGroup(ModelResource):
    category = fields.ManyToManyField('UserManagement.usersapi.CategoriesInformation', 'category',related_name='category', full=True,null=True, blank=True)
    modules = fields.ManyToManyField('UserManagement.usersapi.Permissions', 'modules',related_name='modules', full=True,null=True, blank=True)
    countries = fields.ManyToManyField('Assets.api.Countries', 'countries',related_name='countries', full=True,null=True, blank=True)

    #print >> sys.stdout, category
    class Meta:
        queryset = UserGroups.objects.all()
        #excludes = ['id']
        resource_name = 'groups/group'
        include_resource_uri = False
        serializer = urlencodeSerializer()
        allowed_methods = ['post','patch','get','put']
        excludes = ['owner',]
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()
        always_return_data = True

    def hydrate_m2m(self,bundle):
        User = get_user(bundle.request)
        try :
            country = WorldCountries.objects.get(country_name=User.country)
            bundle.obj.countries.add(country)
            bundle.obj.owner = country.pk
        except:
            pass
        try:

            
            Groups ={}
            if User.is_superuser:
                Groups  = UserGroups.objects.get(pk=1)
            else:
                Groups  = UserGroups.objects.get(pk=User.groups.pk)
            selected_module = bundle.request.POST['modules'].split(',')

            for mod in UserPrivileges.objects.all():
                bundle.obj.modules.remove(mod)

            for mod in Groups.modules.all():
                try:
                    if str(mod.privilege_id) in selected_module:
                        bundle.obj.modules.add(mod)
                        #bundle.obj.modules.add(mod)
                except:
                    pass
                
        except:
            pass

        try:

            for mod in Categories.objects.all():
                bundle.obj.category.remove(mod)
            for mod in bundle.request.POST['categories'].split(','):
                try:
                    # need to add country specifyc category check
                    bundle.obj.category.add(Categories.objects.get(pk=mod))
                except:
                    pass
        except:
            pass

    def get_object_list(self, request):
        User = get_user(request)
        if self.Meta.authorization.is_authorized_collection(request=request,permission=['Groups.Create','Groups.Edit'],atleast_one=True):
            return super(CRUDGroup, self).get_object_list(request).filter(countries=User.country)
        else:
            #raise Unauthorized("Permission denied")    
            errors = {'error':['Permission denied']}
            options = {
                'R':request,
                'A':"/Users/Groups/Permission/Access violation/",
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)                    

        #if self.Meta.authorization.is_authorized(request,'Groups.Create'):
        #    return super(CRUDGroup, self).get_object_list(request).filter(countries=User.country)
        #else:
        #    raise Unauthorized("Permission denied")    


    def obj_update(self, bundle,  **kwargs):
        request = bundle.request
        #print >> sys.stdout,self.Meta.authorization.is_authorized_collection(request=request,permission=['Groups.Edit','Groups.Create','Groups.Send','Groups.List','Groups.Delete'],atleast_one=True)
        User = get_user(request)
        action = str(User.pk)+"/" +str(bundle.request.POST['id'])+"/" + bundle.request.POST['group_name']
        country = WorldCountries.objects.get(country_name=User.country)
        G = UserGroups.objects.get(pk=bundle.request.POST['id'])
        bundle.obj.owner,bundle.obj.is_system_group = G.owner,G.is_system_group

        if int(bundle.request.POST['id']) == User.groups.id:
            errors = {'error':['Permission denied to modify  your own group']}
            options = {
                'R':bundle.request,
                'A':"/Users/Groups/Update/Permissin denied/" +action,
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)

        if bundle.obj.is_system_group or not bundle.obj.owner==country.pk:
            errors = {'error':['Permission denied to modify other groups']}
            options = {
                'R':bundle.request,
                'A':"/Users/Groups/Update/Permissin denied/" +action,
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)

        if self.Meta.authorization.is_authorized(request,'Groups.Edit'):
            try:
                try:
                    bundle.obj.is_system_group= False
                    bundle.obj.owner = country.pk
                    bundle = super(CRUDGroup, self).obj_update(bundle,**kwargs)
                    bundle.obj.save()

                except AttributeError, e:
                    errors = {'error':[str(e)]}
                    options = {
                        'R':bundle.request,
                        'A':"/Users/Groups/Update/Application error(attribute)/" +action,
                        'U':User,
                        'L_T':'app',
                        'E':errors,
                        'C':500,
                    }
                    handle_errors_only_log(options)                    

            except IntegrityError, e1:
                errors = {'error':[str(e1)]}
                options = {
                    'R':bundle.request,
                    'A':"/Users/Groups/Update/Application error(integrity)/" +action,
                    'U':User,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)                    

            try:
                action = "/Users/Groups/Update/Success/" + action
                Logging().log(request=bundle.request,log_entry=action,User=User,log_type="app",comments="Updated successfully",process_code=201)
            except:
                pass
            
            return bundle
        else:
            errors = {'error':['Permission denied']}
            options = {
                'R':bundle.request,
                'A':"/Users/Groups/Update/Permission denied/" +action,
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)             

            #raise Unauthorized("Permission denied")

    def obj_create(self, bundle,  **kwargs):

        request = bundle.request
        User = get_user(request)
        action = str(User.pk)+"/" + bundle.request.POST['group_name']
        if self.Meta.authorization.is_authorized(request,'Groups.Create'):
            try:
                try:
                    #for category in Categories.objects.all():
                    #    print >> sys.stdout,category
                    country = WorldCountries.objects.get(country_name=User.country)
                    #bundle.obj.owner = country.pk
                    bundle = super(CRUDGroup, self).obj_create(bundle, owner=country.pk)
                    #print >> sys.stdout,bundle.obj.id
                    bundle.obj.save()
                    
                except AttributeError, e:
                    errors = {'error':[str(e)]}
                    options = {
                        'R':bundle.request,
                        'A':"/Users/Groups/Create/Application error(attribute)/" +action,
                        'U':User,
                        'L_T':'app',
                        'E':errors,
                        'C':500,
                    }
                    handle_errors_only_log(options)                    

            except IntegrityError, e1:
                errors = {'error':[str(e1)]}
                options = {
                    'R':bundle.request,
                    'A':"/Users/Groups/Create/Application error(integrity)/" +action,
                    'U':User,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)                    
        else:
            errors = {'error':['Permission denied']}
            options = {
                'R':bundle.request,
                'A':"/Users/Groups/Create/Permission denied/" +action,
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)             
        try:
            action = "/Users/Groups/Create/Success/" + action
            Logging().log(request=bundle.request,log_entry=action,User=User,log_type="app",comments="Created successfully",process_code=200)
            
        except:
            pass

        return bundle        
        
    def alter_detail_data_to_serialize(self, request, data):
        data.data['all_permission'] = {'modules':[]}
        User = get_user(request)
        Groups ={}
        if User.is_superuser:
            Groups  = UserGroups.objects.get(pk=1)
        else:
            Groups  = UserGroups.objects.get(pk=User.groups.pk)
        for module in Groups.modules.all():
            data.data['all_permission']['modules'].append({'name':module,'privilege_id':module.privilege_id,'module':module.module.pk,'friendly_name':module.friendly_name}) 
        data.data['all_modules'] = []
        for module in UserModules.objects.filter(is_active=True):
            data.data['all_modules'].append({'name':module,'id':module.id})

        return data

    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['modules'] = []
                for module in UserModules.objects.filter(is_active=True):
                    data_dict['modules'].append({'name':module,'id':module.id})
                data_dict['groups'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict


class GroupsPermission(ModelResource):
    modules = fields.ManyToManyField('UserManagement.usersapi.Permissions', 'modules',related_name='modules', full=True,null=True, blank=True)

    class Meta:
        queryset = UserGroups.objects.all()
        #excludes = ['id']
        resource_name = 'groups/permission'
        include_resource_uri = False
        allowed_methods = ['get']
        fields = ['modules']
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()


    def get_object_list(self, request):
        User = get_user(request)
        #print >> sys.stdout,self.Meta.authorization.is_authorized_collection(request=request,permission=['Groups.Create','Groups.Edit'],atleast_one=True)
        if self.Meta.authorization.is_authorized_collection(request=request,permission=['Groups.Create','Groups.Edit'],atleast_one=True):
            if User.is_superuser:
                return super(GroupsPermission, self).get_object_list(request).filter(pk=1)
            else:
                return super(GroupsPermission, self).get_object_list(request).filter(pk=User.groups.pk)
        else:
            #raise Unauthorized("Permission denied")    
            errors = {'error':['Permission denied']}
            options = {
                'R':request,
                'A':"/Users/Groups/Permission List/Access violation(user list)/",
                'U':User,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)                    


    def alter_list_data_to_serialize(self, request, data_dict):
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                del(data_dict['meta'])
                # Rename the objects.
                data_dict['modules'] = []
                for module in UserModules.objects.filter(is_active=True):
                    data_dict['modules'].append({'name':module,'id':module.id})
                data_dict['permission'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict

class CRUDUser(ModelResource):
    country = fields.ForeignKey('Assets.api.Countries', 'country', null=True)
    
    groups = fields.ForeignKey('UserManagement.usersapi.READGroup', 'groups', null=True)
    class Meta:
        queryset = User.objects.all()
        excludes = ['password','country']
        resource_name = 'users/user'
        include_resource_uri = False
        #authentication = CheckForAuthentication()
        authorization = CheckForAuthorization()
        serializer = urlencodeSerializer()
        allowed_methods = ['post','patch','get','put']
        always_return_data = True
    def get_object_list(self, request):
        #if self.Meta.authorization.is_authorized(request,'Users.Create') or  self.Meta.authorization.is_authorized(request,'Users.List'):
        LUSER = get_user(request)
        if self.Meta.authorization.is_authorized_collection(request=request,permission=['Users.Create','Users.List','Users.Edit'],atleast_one=True):
            
            from django.db.models import Q
            try:
                if not LUSER.is_superuser:
                    return super(CRUDUser, self).get_object_list(request).filter(country=LUSER.country).filter(groups=request.GET['gid']).filter(is_active=True).filter(~Q(pk=LUSER.id)).filter(~Q(groups=1))
                else:
                    return super(CRUDUser, self).get_object_list(request).filter(country=LUSER.country).filter(groups=request.GET['gid']).filter(~Q(pk=LUSER.id)).filter(~Q(groups=1))
            except:
                if not LUSER.is_superuser:
                    return super(CRUDUser, self).get_object_list(request).filter(country=LUSER.country).filter(is_active=True).filter(~Q(pk=LUSER.id)).filter(~Q(groups=1))
                else:
                    return super(CRUDUser, self).get_object_list(request).filter(country=LUSER.country).filter(~Q(pk=LUSER.id)).filter(~Q(groups=1))

                
                
        else:
            #raise Unauthorized("Permission denied")    
            errors = {'error':['Permission denied']}
            options = {
                'R':request,
                'A':"/Users/User/Update/Access violation(user list)/",
                'U':LUSER,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)                    

    def dehydrate(self, bundle): 
        bundle = super(CRUDUser,self).dehydrate(bundle)
        LUSER = get_user(bundle.request)
        if not LUSER.is_superuser: 
            del bundle.data['is_superuser']
            del bundle.data['is_active']
        bundle.data['groups'] = bundle.data['groups'].replace('/api/v1/groups/limit/','').replace('/','')
        del bundle.data['country']
        return bundle 

    def obj_update(self, bundle,  **kwargs):
        request = bundle.request
        LUSER = get_user(request)
        
        
        G = User.objects.get(pk=bundle.request.POST['id'])
        action =  str(LUSER.pk)+"/" +str(bundle.request.POST['id'])+"/" + bundle.request.POST['username']
        if int(bundle.request.POST['id']) == LUSER.id:
            errors = {'error':['Update your information using account info']}
            options = {
                'R':bundle.request,
                'A':"/Users/User/Update/Access violation(self user update)/" +action,
                'U':LUSER,
                'L_T':'app',
                'E':errors,
                'C':500,
            }
            handle_errors(options)                    
        if not G.country.pk == LUSER.country.pk or G.groups.is_system_group:
            if G.groups.is_system_group:
                errors = {'error':['Permission denied to modify system user!!']}
                options = {
                    'R':bundle.request,
                    'A':"/Users/User/Update/Access violation(system user update)/" +action,
                    'U':LUSER,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)                    
            else:
                errors = {'error':['Permission denied to modify other system user!!']}
                options = {
                    'R':bundle.request,
                    'A':"/Users/User/Update/Access violation/" +action,
                    'U':LUSER,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)                    
        
        if self.Meta.authorization.is_authorized(request,'Users.Edit'):
            try:
                try:
                    
                    from UserManagement.forms import UserCreationFormAPI
                    UserCreationFormAPI.country = LUSER.country
                    UserCreationFormAPI.isUpdate  = True
                    CreatedUser = User.objects.get(pk=bundle.request.POST['id'])
                    UserCreationFormAPI.oldName = CreatedUser.username
                    
                    form = UserCreationFormAPI(bundle.request.POST)
                    if form.is_valid():
                        bundle = super(CRUDUser, self).obj_update(bundle,**kwargs)
                        bundle.obj.save()
                        if LUSER.is_superuser:
                            CreatedUser = User.objects.get(pk=bundle.obj.id)
                            try:
                               CreatedUser.is_active = (bundle.request.PUT['is_active'] == "true")
                            except:
                                pass
                            try:
                               CreatedUser.is_superuser =  (bundle.request.PUT['is_superuser'] == "true")
                            except:
                                pass
                            CreatedUser.save()

                            try:
                                action = "/Users/User/Update/Success/" + action
                                Logging().log(request=bundle.request,log_entry=action,User=LUSER,log_type="app",comments="Updated successfully",process_code=201)
                                
                            except:
                                pass
                    else:
                        errors = {'error':{}}
                        for  k, v in form.errors.items():
                            errors['error'][k] = v

                        options = {
                            'R':bundle.request,
                            'A':"/Users/User/Update/Form validation error/" +action,
                            'U':LUSER,
                            'L_T':'app',
                            'E':errors['error'],
                            'C':500,
                        }
                        handle_errors(options)                    
                    
                except AttributeError, e:
                    errors = {'error':[str(e)]}
                    options = {
                        'R':bundle.request,
                        'A':"/Users/User/Update/Application error(attribute)/" +action,
                       'U':LUSER,
                        'L_T':'app',
                        'E':errors,
                        'C':500,
                    }
                    handle_errors(options)                    
            except IntegrityError, e1:
                errors = {'error':[str(e1)]}
                options = {
                    'R':bundle.request,
                    'A':"/Users/User/Update/Application error(integrity)/" +action,
                    'U':LUSER,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)                    
        else:
            
            errors = {'error':['Permission denied']}
            options = {
                'R':bundle.request,
                'A':"/Users/User/Update/Permission denied/" +action,
                'U':LUSER,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)             
            
           
            
            #raise Unauthorized("Permission denied")
        return bundle        

    def handle_errors(self, options):
        print >> sys.stdout,"error"
        """
        if options['APP']:
            Logging().log_500(request=options['R'],User=options['U'],description=options['E'],case_id=options['C'],log_type="app",action=options['A'])
            raise BadRequest(options['E'])
        else:
            Logging().log_500(request=options['R'],User=options['U'],description=options['E'],case_id=options['C'],log_type="sys",action=options['A'])
            raise BadRequest(exception)        
        #return super(CRUDUser, self)._handle_500(request, exception)
        """
        Logging().log(request=options['R'],log_entry=options['A'],User=options['U'],log_type=options['L_T'],comments=options['E'],process_code=options['C'])
        raise BadRequest(options['E'])

    def handle_500(self, options):
        """
        if options['APP']:
            Logging().log_500(request=options['R'],User=options['U'],description=options['E'],case_id=options['C'],log_type="app",action=options['A'])
            raise BadRequest(options['E'])
        else:
            Logging().log_500(request=options['R'],User=options['U'],description=options['E'],case_id=options['C'],log_type="sys",action=options['A'])
            raise BadRequest(exception)        
        #return super(CRUDUser, self)._handle_500(request, exception)
        """
        Logging().log(request=options['R'],log_entry=options['A'],User=options['U'],log_type=options['L_T'],comments=options['E'],process_code=500)


    def obj_create(self, bundle,  **kwargs):
        request = bundle.request
        LUSER = get_user(request)
        action = str(LUSER.pk)+"/" + bundle.request.POST['username']
        try:
            UserGroups.objects.get(pk=bundle.request.POST['groups'].replace('/api/v1/groups/group/','').replace('/',''),countries=LUSER.country)
        except UserGroups.DoesNotExist:
            errors = {'error':['Permission denied - Trying to register invalid group!!']}
            options = {
            'R':bundle.request,
                'A':"/Users/User/Update/Access violation(Trying to register in different group)/" +action,
                'U':LUSER,
                'L_T':'app',
                'E':errors,
                'C':500,
            }
            handle_errors(options)  
            #raise Unauthorized("Permission denied - Trying to register invalid group")

        if self.Meta.authorization.is_authorized(request,'Users.Create'):
            try:
                try:
                    from UserManagement.forms import UserCreationFormAPI
                    UserCreationFormAPI.country = LUSER.country
                    form = UserCreationFormAPI(bundle.request.POST)
                    
                    if form.is_valid():
                        superuser=False
                        if LUSER.is_superuser:
                            try:
                               superuser = (bundle.request.POST['is_superuser'] == "true")
                            except:
                                pass
                        bundle = super(CRUDUser, self).obj_create(bundle, country=LUSER.country,first_name=bundle.obj.username,is_superuser=superuser)
                        bundle.obj.save()
                        
                        from django.template import loader
                        from django.contrib.auth.tokens import default_token_generator
                        from django.contrib.sites.models import get_current_site
                        from django.utils.http import int_to_base36

                        current_site = get_current_site(request)
                        site_name = current_site.name
                        domain = current_site.domain
                        
                        CreatedUser = User.objects.get(pk=bundle.obj.id)
                        CreatedUser.first_name = bundle.obj.username;
                        CreatedUser.set_password('IkEA4102!')
                        CreatedUser.is_superuser=superuser
                        CreatedUser.save()

                        
                        use_https = False
                        c = {
                            'email': CreatedUser.email,
                            'domain': domain,
                            'site_name': site_name,
                            'uid': int_to_base36(CreatedUser.id),
                            'user': CreatedUser,
                            'token': default_token_generator.make_token(CreatedUser),
                            'protocol': use_https and 'https' or 'http',
                            'home_url': '/%s/' % CreatedUser.country.iso_code,
                        }
                        subject = loader.render_to_string('base_templates/registration/welcome_email_subject.txt', c)
                        # Email subject *must not* contain newlines
                        subject = ''.join(subject.splitlines())
                        email = loader.render_to_string('base_templates/registration/welcome_email.html', c)
                        
                        CreatedUser.email_user(subject,email,'no-reply@ec.is')
                        try:
                            action = "/Users/User/Create/Success/" + action
                            Logging().log(request=bundle.request,log_entry=action,User=LUSER,log_type="app",comments="Created successfully",process_code=200)
                            
                        except:
                            pass
                        
                    else:
                        errors = {'error':{}}
                        for  k, v in form.errors.items():
                            errors['error'][k] = v

                        options = {
                            'R':bundle.request,
                            'A':"/Users/User/Create/Form validation error/" +action,
                            'U':LUSER,
                            'L_T':'app',
                            'E':errors['error'],
                            'C':500,
                        }
                        handle_errors(options)                    

                except AttributeError, e:
                    errors = {'error':[str(e)]}
                    options = {
                        'R':bundle.request,
                        'A':"/Users/User/Create/Application error(attribute)/" +action,
                       'U':LUSER,
                        'L_T':'app',
                        'E':errors,
                        'C':500,
                    }
                    handle_errors(options)                    
            except IntegrityError, e:
                errors = {'error':[str(e)]}
                options = {
                    'R':bundle.request,
                    'A':"/Users/User/Create/Application error(integrity)/" +action,
                    'U':LUSER,
                    'L_T':'app',
                    'E':errors,
                    'C':500,
                }
                handle_errors(options)
        else:
            errors = {'error':['Permission denied']}
            options = {
                'R':bundle.request,
                'A':"/Users/User/Create/Permission denied/" +action,
                'U':LUSER,
                'L_T':'app',
                'E':errors,
                'C':401,
            }
            handle_errors(options)             
        return bundle        
    def alter_list_data_to_serialize(self, request, data_dict):
        LUSER = get_user(request)
        if isinstance(data_dict, dict):
            if 'meta' in data_dict:
                # Get rid of the "meta".
                #del(data_dict['meta'])

                data_dict['fld'] = {}
                data_dict['fields'] = []
                data_dict['models'] = []


                friendly_field_name = User().list_view_display_fields()
                for field in friendly_field_name:
                    data_dict['fld'][field] = field

                #del data_dict['fld']['groups']
                #del data_dict['fld']['id']
                #del data_dict['fld']['country']
                if not LUSER.is_superuser:
                    del data_dict['fld']['is_superuser']
                    del data_dict['fld']['is_active']
                
                #print >> sys.stdout,friendly_field_name
                for field in data_dict['fld']:
                    data_dict['fields'].append(field)
                    data_dict['models'].append({"title": friendly_field_name[field],"property": field, "sortable": "true"})
                del data_dict['fld']

                #for field in data_dict['fields']:
                #    data_dict['models'].append({'name':field,'index':field,'width':80})


                    
                # Rename the objects.
                data_dict['users'] = copy.copy(data_dict['objects'])
                del(data_dict['objects'])
        return data_dict    



