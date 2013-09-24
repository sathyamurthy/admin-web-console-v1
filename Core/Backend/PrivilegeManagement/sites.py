from functools import update_wrapper
from django.http import Http404,HttpResponseForbidden, HttpResponseRedirect
from django.contrib.admin import ModelAdmin, actions
from django.contrib.contenttypes import views as contenttype_views
from django.views.decorators.csrf import csrf_protect
from django.db.models.base import ModelBase
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse, NoReverseMatch
from django.template.response import TemplateResponse
from django.utils.safestring import mark_safe
from django.utils.text import capfirst
from django.utils.translation import ugettext as _
from django.views.decorators.cache import never_cache
from django.conf import settings
from django.contrib import admin
from django.core.urlresolvers import reverse
from tastypie.exceptions import Unauthorized

from Core.UserManagement.forms import AuthenticationForm
from Core.UserManagement import REDIRECT_FIELD_NAME,get_user


import sys

LOGIN_FORM_KEY = 'this_is_the_login_form'

class AlreadyRegistered(Exception):
    pass

class NotRegistered(Exception):
    pass

"""
def get_top_menu(request,sel_mod='',sel_action=''):
    return modules
"""       
def get_country_from_url( PATH):
    try:
        return PATH.split('/')[1]
    except:
        pass
    return ""

def error_template(error_id,request,context,label):
    return TemplateResponse(request, 'base_templates/%s.html'%(error_id), context = context, current_app=label)

    
def get_accessble_modules(request,sel_mod='',sel_action=''):
    #print >> sys.stdout,sel_mod
    user = get_user(request)
    country = user.country.iso_code
    modules = {'mod':[],'selected':[],'menus':[]}
    from Core.Backend.Components.models import UserModules,UserPrivileges,UserActions
    for s in user.get_all_permissions():
        modules['perm_'+s.replace('.','_').lower()]={'opt':['true']}
    for module in UserModules.objects.all():
        app_label = module.module_name
        permission_set = user.get_all_permissions()
        has_module_perms = user.has_module_perms(app_label)
        
        if has_module_perms:

            groups = ''
            if module.groups.title().lower() == "none":
                groups = ''
            else:
                groups = '%s/' % module.groups.title()

            selected = False
            if sel_mod.lower() == app_label.lower():
                modules['mod'].append({'name':app_label,'url':'/%s/%s%s/' % (country,groups,app_label),'sel':'active'})
                selected = True
                modules['selected'].append({'name':app_label,'url':'/%s/%s%s/' % (country,groups,app_label),'options':[]})
            else:
                modules['mod'].append({'name':app_label,'url':'/%s/%s%s/' % (country,groups,app_label),'sel':''})

            perms = module.get_model_perms(module=module.pk)
            for prm in perms:
                if UserPrivileges.objects.filter(module=module).filter(action=UserActions.objects.filter(action_name=prm))[0].show_as_link:
                    if "%s.%s" % (app_label,prm) in permission_set:
                        modules[app_label.lower()]={'opt':[]}
                        modules[app_label.lower()+'_'+prm.lower()]={'opt':[]}
                        modules[app_label.lower()]['opt'].append('/%s/%s%s/' % (country,groups,app_label))
                        modules[app_label.lower()+'_'+prm.lower()]['opt'].append('/%s/%s%s/%s' % (country,groups,app_label,prm))
                        if selected:
                            #print >> sys.stdout,prm
                            if prm.lower() == sel_action.lower():
                                modules['selected'][0]['options'].append({'name':prm,'url':'/%s/%s%s/%s' % (country,groups,app_label,prm),'sel':'active'})
                            else:
                                modules['selected'][0]['options'].append({'name':prm,'url':'/%s/%s%s/%s' % (country,groups,app_label,prm),'sel':''})

    #print >> sys.stdout,modules
    return modules

class CustomerView(object):
    """
    An AdminSite object encapsulates an instance of the Django admin application, ready
    to be hooked in to your URLconf. Models are registered with the AdminSite using the
    register() method, and the get_urls() method can then be used to access Django view
    functions that present a full admin interface for the collection of registered
    models.
    """
    login_form = None
    index_template = None
    app_index_template = None
    login_template = None
    logout_template = None
    password_reset = None
    password_change_template = None
    password_change_done_template = None

    def __init__(self, name='customer_admin', app_name='customer_admin'):
        self._registry = {} # model_class class -> admin_class instance
        self.name = name
        self.app_name = app_name
        self._actions = {'delete_selected': actions.delete_selected}
        self._global_actions = self._actions.copy()

    def register(self, model_or_iterable, admin_class=None, **options):
        """
        Registers the given model(s) with the given admin class.

        The model(s) should be Model classes, not instances.

        If an admin class isn't given, it will use ModelAdmin (the default
        admin options). If keyword arguments are given -- e.g., list_display --
        they'll be applied as options to the admin class.

        If a model is already registered, this will raise AlreadyRegistered.

        If a model is abstract, this will raise ImproperlyConfigured.
        """
        if not admin_class:
            admin_class = ModelAdmin

        # Don't import the humongous validation code unless required
        if admin_class and settings.DEBUG:
            from django.contrib.admin.validation import validate
        else:
            validate = lambda model, adminclass: None

        if isinstance(model_or_iterable, ModelBase):
            model_or_iterable = [model_or_iterable]
        for model in model_or_iterable:
            if model._meta.abstract:
                raise ImproperlyConfigured('The model %s is abstract, so it '
                      'cannot be registered with admin.' % model.__name__)

            if model in self._registry:
                raise AlreadyRegistered('The model %s is already registered' % model.__name__)

            # If we got **options then dynamically construct a subclass of
            # admin_class with those **options.
            if options:
                # For reasons I don't quite understand, without a __module__
                # the created class appears to "live" in the wrong place,
                # which causes issues later on.
                options['__module__'] = __name__
                admin_class = type("%sAdmin" % model.__name__, (admin_class,), options)

            # Validate (which might be a no-op)
            validate(admin_class, model)

            # Instantiate the admin class to save in the registry
            self._registry[model] = admin_class(model, self)

    def unregister(self, model_or_iterable):
        """
        Unregisters the given model(s).

        If a model isn't already registered, this will raise NotRegistered.
        """
        if isinstance(model_or_iterable, ModelBase):
            model_or_iterable = [model_or_iterable]
        for model in model_or_iterable:
            if model not in self._registry:
                raise NotRegistered('The model %s is not registered' % model.__name__)
            del self._registry[model]

    def add_action(self, action, name=None):
        """
        Register an action to be available globally.
        """
        name = name or action.__name__
        self._actions[name] = action
        self._global_actions[name] = action

    def disable_action(self, name):
        """
        Disable a globally-registered action. Raises KeyError for invalid names.
        """
        del self._actions[name]

    def get_action(self, name):
        """
        Explicitally get a registered global action wheather it's enabled or
        not. Raises KeyError for invalid names.
        """
        return self._global_actions[name]

    @property
    def actions(self):
        """
        Get all the enabled actions as an iterable of (name, func).
        """
        return self._actions.iteritems()

    def has_permission(self, request):
        """
        Returns True if the given HttpRequest has permission to view
        *at least one* page in the admin site.
        """
        user = get_user(request);
        return user.is_active 

    def check_dependencies(self):
        """
        Check that all things needed to run the admin have been correctly installed.

        The default implementation checks that LogEntry, ContentType and the
        auth context processor are installed.
        """
        from django.contrib.admin.models import LogEntry
        from django.contrib.contenttypes.models import ContentType

        if not LogEntry._meta.installed:
            raise ImproperlyConfigured("Put 'django.contrib.admin' in your "
                "INSTALLED_APPS setting in order to use the admin application.")
        if not ContentType._meta.installed:
            raise ImproperlyConfigured("Put 'django.contrib.contenttypes' in "
                "your INSTALLED_APPS setting in order to use the admin application.")
        if not ('django.contrib.auth.context_processors.auth' in settings.TEMPLATE_CONTEXT_PROCESSORS or
            'django.core.context_processors.auth' in settings.TEMPLATE_CONTEXT_PROCESSORS):
            raise ImproperlyConfigured("Put 'django.contrib.auth.context_processors.auth' "
                "in your TEMPLATE_CONTEXT_PROCESSORS setting in order to use the admin application.")

    def admin_view(self, view, cacheable=False):
        """
        Decorator to create an admin view attached to this ``AdminSite``. This
        wraps the view and provides permission checking by calling
        ``self.has_permission``.

        You'll want to use this from within ``AdminSite.get_urls()``:

            class MyAdminSite(AdminSite):

                def get_urls(self):
                    from django.conf.urls import patterns, url

                    urls = super(MyAdminSite, self).get_urls()
                    urls += patterns('',
                        url(r'^my_view/$', self.admin_view(some_view))
                    )
                    return urls

        By default, admin_views are marked non-cacheable using the
        ``never_cache`` decorator. If the view can be safely cached, set
        cacheable=True.
        """
        def inner(request, *args, **kwargs):
            if not self.has_permission(request):
                country = get_country_from_url(request.get_full_path())
                if request.path == reverse(country+':logout',current_app=self.name):
                    index_path = reverse(country+':index', current_app=self.name)
                    return HttpResponseRedirect(index_path)

                if not "/password/" in request.path:
                    return self.login(request)
                else:
                    if "/password/reset/done/" in request.path:
                        return self.pwd_reset_done(request)
                    elif "/password/reset/confirm/complete/" in request.path:
                        return self.pwd_reset_confirm_complete(request)
                    elif "/password/reset/confirm/" in request.path:
                        return self.pwd_reset_confirm(request)
                    else:
                        return self.pwd_reset(request)
            return view(request, *args, **kwargs)
        if not cacheable:
            inner = never_cache(inner)
        # We add csrf_protect here so this function can be used as a utility
        # function for any view, without having to repeat 'csrf_protect'.
        if not getattr(view, 'csrf_exempt', False):
            inner = csrf_protect(inner)
        return update_wrapper(inner, view)

    def get_urls(self):
        from django.conf.urls import patterns, url, include

        if settings.DEBUG:
            self.check_dependencies()

        def wrap(view,app_label=None,action=None,cacheable=False):
            def wrapper(*args, **kwargs):
                if app_label is not None:
                    kwargs['app_label'] = app_label

                if action is not None:
                    kwargs['action'] = action
                    """
                    try :
                        kwargs['action'] = app_label.split('.')[1]
                    except :
                        pass
                    """
                #if action is not None:
                    

                return self.admin_view(view, cacheable)(*args, **kwargs)
            return update_wrapper(wrapper, view)

        # Admin-site-wide views.
        urlpatterns = patterns('',
            url(r'^$',
                wrap(self.index),
                name='index'),
            url(r'^signout/$',
                wrap(self.logout),
                name='logout'),
            url(r'^password_change/$',
                wrap(self.password_change, cacheable=False),
                name='password_change'),
            url(r'^Users/my_account/$',
                wrap(self.my_account, cacheable=False),
                name='my_accout'),
            url(r'^password/reset/$',
                wrap(self.pwd_reset, cacheable=False),
                name='pwd_reset'),
            url(r'^password/reset/done/$',
                wrap(self.pwd_reset_done, cacheable=False),
                name='pwd_reset_done'),
            url(r'^password/reset/confirm/$',
                wrap(self.pwd_reset_confirm, cacheable=False),
                name='pwd_reset_confirm'),
            url(r'^password/reset/confirm/complete/$',
                wrap(self.pwd_reset_confirm_complete, cacheable=False),
                name='pwd_reset_confirm_complete'),
            url(r'^password_change/done/$',
                wrap(self.password_change_done, cacheable=False),
                name='password_change_done'),
            url(r'^jsi18n/$',
                wrap(self.i18n_javascript, cacheable=False),
                name='jsi18n'),
            
            #url(r'^r/(?P<content_type_id>\d+)/(?P<object_id>.+)/$',wrap(contenttype_views.shortcut)),
            # url(r'^(?P<app_label>\w+)/$',wrap(self.app_index),name='app_list')
            
        )

        # Add in each model's views.
        

        from Core.Backend.Components.models import UserModules
        for module in UserModules.objects.all():
            
            if module.groups.title().lower() == "none":
                urlpatterns += patterns('',
                    url(r'^%s/$' %(module.title()),
                        wrap(self.app_index,app_label= module.title()),
                        name=module.title()
                        #name='app_list'
                        )
                )
            else:
                urlpatterns += patterns('',
                    url(r'^%s/%s/$' %(module.groups.title(),module.title()),
                        wrap(self.app_index,app_label= module.title()),
                        name=module.title()
                        #name='app_list'
                        )
                )
            
              
        from Core.Backend.Components.models import UserPrivileges
        for privilege in UserPrivileges.objects.all():
            if privilege.module.groups.title().lower() == "none":
                urlpatterns += patterns('',
                    url(r'^%s/%s/$' % (privilege.module.title(), privilege.action.title()),
                        wrap(self.app_mod_index,app_label= privilege.module.title(),action=privilege.action.title()),
                        name=privilege.module.title()+"_"+privilege.action.title(),
                        ),
                )
                urlpatterns += patterns('',
                    url(r'^%s/%s/(?P<object_id>.+)/$' % (privilege.module.title(), privilege.action.title()),
                        wrap(self.app_mod_index,app_label= privilege.module.title(),action=privilege.action.title()),
                        name=privilege.module.title()+"_"+privilege.action.title(),
                        ),
                )
            else:
                urlpatterns += patterns('',
                    url(r'^%s/%s/%s/$' % (privilege.module.groups.title(),privilege.module.title(), privilege.action.title()),
                        wrap(self.app_mod_index,app_label= privilege.module.title(),action=privilege.action.title()),
                        name=privilege.module.title()+"_"+privilege.action.title(),
                        ),
                )
                urlpatterns += patterns('',
                    url(r'^%s/%s/%s/(?P<object_id>.+)/$' % (privilege.module.groups.title(),privilege.module.title(), privilege.action.title()),
                        wrap(self.app_mod_index,app_label= privilege.module.title(),action=privilege.action.title()),
                        name=privilege.module.title()+"_"+privilege.action.title(),
                        ),
                )

        #print >> sys.stdout,r'^%s/%s/' % (privillege.module.title(), privillege.action.title())
        """
        for model, model_admin in self._registry.iteritems():
            #print >> sys.stdout,model_admin.urls
            print >> sys.stdout,model_admin
            urlpatterns += patterns('',
                url(r'^%s/%s/' % (model._meta.app_label, model._meta.module_name),
                    include(model_admin.urls))
            )
        """
        #print >> sys.stdout,urlpatterns
        return urlpatterns

    @property
    def urls(self):
        #print >> sys.stdout, self.app_name, self.name
        return self.get_urls(), self.app_name, self.name

    def geturls(self,app_name,name):
        #print >> sys.stdout, self.app_name, self.name
        return self.get_urls(), app_name, name

    def password_change(self, request):
        """
        Handles the "change password" task -- both form display and validation.
        """
        from Core.UserManagement.views import password_change
        user = get_user(request)
        country = get_country_from_url(request.get_full_path())
        url = '/%s/' % (country)
        extra_context = {
            'country' : '%s' % (country),
            'home_url' : url
        }
        extra_context['profile'] = user.get_profile();
        extra_context['modules'] = get_accessble_modules(request,sel_mod='Users',sel_action='')
        
        defaults = {
            'current_app': self.name,
            'extra_context' : extra_context,
            'post_change_redirect': url + 'password_change/done/'
        }
        #import pdb
        #pdb.set_trace()

        if self.password_change_template is not None:
            defaults['template_name'] = self.password_change_template
        return password_change(request, **defaults)

    def password_change_done(self, request, extra_context=None):
        """
        Displays the "success" page after a password change.
        """
        from Core.UserManagement.views import password_change_done
        user = get_user(request)
        extra_context = {
            'home_url' : '/%s/' % ( get_country_from_url(request.get_full_path())),
        }
        extra_context['profile'] = user.get_profile();
        extra_context['modules'] = get_accessble_modules(request,sel_mod='Users',sel_action='')

        defaults = {
            'current_app': self.name,
            'extra_context': extra_context or {},
        }
        if self.password_change_done_template is not None:
            defaults['template_name'] = self.password_change_done_template
        return password_change_done(request, **defaults)


    def pwd_reset_done(self, request):
        """
        Handles the "change password" task -- both form display and validation.
        """


        from Core.UserManagement.views import password_reset_done
        url = '/%s/' % ( get_country_from_url(request.get_full_path()))
        extra_context = {
            'country' : '%s' % ( get_country_from_url(request.get_full_path())),
            'home_url' : url
        }
        defaults = {
            'current_app': self.name,
            'extra_context' : extra_context,
        }
        return password_reset_done(request, **defaults)

    def pwd_reset_confirm_complete(self, request):
        """
        Handles the "change password" task -- both form display and validation.
        """

        
        from Core.UserManagement.views import password_reset_complete
        url = '/%s/' % ( get_country_from_url(request.get_full_path()))
        extra_context = {
            'country' : '%s' % ( get_country_from_url(request.get_full_path())),
            'home_url' : url
        }
        defaults = {
            'current_app': self.name,
            'extra_context' : extra_context,
        }
        return password_reset_complete(request, **defaults)
    
    def pwd_reset_confirm(self, request):
        """
        Handles the "change password" task -- both form display and validation.
        """


        from Core.UserManagement.views import password_reset_confirm
        url = '/%s/' % ( get_country_from_url(request.get_full_path()))
        extra_context = {
            'country' : '%s' % ( get_country_from_url(request.get_full_path())),
            'home_url' : url
        }
        defaults = {
            'current_app': self.name,
            'uidb36': request.GET['uidb36'],
            'token' : request.GET['token'],
            'extra_context' : extra_context,
            'post_reset_redirect': '/%s/password/reset/confirm/complete/' % ( get_country_from_url(request.get_full_path())),
        }
        return password_reset_confirm(request, **defaults)


    def pwd_reset(self, request):
        """
        Handles the "change password" task -- both form display and validation.
        """
        from Core.UserManagement.views import password_reset
        #reverse('customer_admin:password_change_done', current_app=self.name)
        url = '/%s/password/reset/done/' % ( get_country_from_url(request.get_full_path()))
        extra_context = {
            'country' : '%s' % ( get_country_from_url(request.get_full_path())),
        }

        defaults = {
            'current_app': self.name,
            'post_reset_redirect': url,
            'extra_context' : extra_context,
            'from_email': 'no-reply@ec.is',
        }
        #import pdb
        #pdb.set_trace()

        if self.password_reset is not None:
            defaults['template_name'] = self.password_reset

        #print >> sys.stdout, password_reset(request, **defaults)
        return password_reset(request, **defaults)


    def i18n_javascript(self, request):
        """
        Displays the i18n JavaScript that the Django admin requires.

        This takes into account the USE_I18N setting. If it's set to False, the
        generated JavaScript will be leaner and faster.
        """
        if settings.USE_I18N:
            from django.views.i18n import javascript_catalog
        else:
            from django.views.i18n import null_javascript_catalog as javascript_catalog
        return javascript_catalog(request, packages=['django.conf', 'django.contrib.admin'])

    @never_cache
    def logout(self, request, extra_context=None):
        """
        Logs out the user for the given HttpRequest.

        This should *not* assume the user is already logged in.
        """
        from Core.UserManagement.views import logout
        extra_context = {
            'country' : '/%s/' % ( get_country_from_url(request.get_full_path())),
        }
        defaults = {
            'current_app': self.name,
            'extra_context': extra_context or {},
        }
        if self.logout_template is not None:
            defaults['template_name'] = 'base_templates/login.html'
        return logout(request, **defaults)

    @never_cache
    def login(self, request, extra_context=None):
        """
        Displays the login form for the given HttpRequest.
        """
        from Core.UserManagement.views import login
        from Core.Countries.models import WorldCountries
        from django.db.models import Q

        context = {
            'title': _('Log in'),
            'app_path': request.get_full_path(),
            'country' : get_country_from_url(request.get_full_path()),
            'password_reset_url' : '/%s/password/reset/' % (get_country_from_url(request.get_full_path())),
            REDIRECT_FIELD_NAME: request.get_full_path(),
            'countries':WorldCountries.objects.filter(~Q(pk=1000)),
        }
        context.update(extra_context or {})
        defaults = {
            'extra_context': context,
            'current_app': self.name,
            'authentication_form': self.login_form or AuthenticationForm,
            'template_name': self.login_template or 'base_templates/login.html',
        }
        return login(request, **defaults)

    @never_cache
    def my_account(self, request, extra_context=None):
        """
        Displays the main admin index page, which lists all of the installed
        apps that have been registered in this site.
        """
        #user = request.user
        user = get_user(request)

        if not get_country_from_url(request.get_full_path()).lower() == user.country.iso_code.lower():
            context = {
                'error':'You cannot access other market information',
                'home_url': '/%s/' % (user.country.iso_code)
            }
            return error_template('403',request=request,context=context,label='error')
            #return TemplateResponse(request, 'base_templates/403.html', context = {'error':'Permission denied'}, current_app=None)
            #raise Unauthorized("Permission denied")
        else:
            context = {
                'title': "Catalogue administartion",
                
            }

            extra_context = dict()
            extra_context['home_url'] = '/%s/' % (user.country.iso_code)
            extra_context['profile'] = user.get_profile();
            extra_context['modules'] = get_accessble_modules(request,sel_mod='Users',sel_action='')

            #print >> sys.stdout, extra_context['modules']
            #print >> sys.stdout, 'edit' in [x.lower() for x in modules['users']['models']]
            #context.url ='/US/'
            context.update(extra_context or {})
            defaults = {
                'extra_context': context,
                'template_name': 'base_templates/Users/my_account.html',
            }
            from Core.UserManagement.views import accout_information_update
            return accout_information_update(request, **defaults)            

    @never_cache
    def index(self, request, extra_context=None):
        """
        Displays the main admin index page, which lists all of the installed
        apps that have been registered in this site.
        """
        #user = request.user
        user = get_user(request)

        if not get_country_from_url(request.get_full_path()).lower() == user.country.iso_code.lower():
            context = {
                'error':'You cannot access other market information',
                'home_url': '/%s/' % (user.country.iso_code)
            }
            return error_template('403',request=request,context=context,label='error')
            #return TemplateResponse(request, 'base_templates/403.html', context = {'error':'Permission denied'}, current_app=None)
            #raise Unauthorized("Permission denied")
        else:
            context = {
                'title': "Catalogue administartion",
                
            }

            extra_context = dict()
            extra_context['home_url'] = '/%s/' % (user.country.iso_code)
            extra_context['profile'] = user.get_profile();
            extra_context['modules'] = get_accessble_modules(request,sel_mod='',sel_action='')
            #print >> sys.stdout, extra_context['modules']
            #print >> sys.stdout, 'edit' in [x.lower() for x in modules['users']['models']]
            #context.url ='/US/'
            context.update(extra_context or {})
            return TemplateResponse(request, [
                self.index_template or 'base_templates/index.html',
            ], context, current_app=self.name,)

    def app_index(self, request, app_label, extra_context=None):
        #user = request.user
        #print >> sys.stdout, request.get_full_path().split('/')[1]
        user = get_user(request)

        if not get_country_from_url(request.get_full_path()).lower() == user.country.iso_code.lower():
            context = {
                'error':'You cannot access other market information',
                'home_url': '/%s/' % (user.country.iso_code)
            }
            return error_template('403',request=request,context=context,label='error')

            #raise Unauthorized("Permission denied")
        else:
            context = {
                'title': _('%s administration') % capfirst(app_label),
                
            }
            """
            context = {
                'title': _('%s administration') % capfirst(app_label),
               
            }
            """
            extra_context = dict()
            extra_context['home_url'] = '/%s/' % (user.country.iso_code)
            extra_context['profile'] = user.get_profile();
            extra_context['modules'] = get_accessble_modules(request,sel_mod=app_label,sel_action='')
            if not extra_context['modules']:
                raise Http404('The requested admin page does not exist.')

            #print >> sys.stdout, extra_context['modules']['selected'][0]['options']
            context.update(extra_context or {})

            return TemplateResponse(request, self.app_index_template or [
                'base_templates/%s/app_index.html' % app_label,
                'base_templates/app_index.html'
            ], context, current_app=self.name)


    def app_mod_index(self, request, app_label,action,object_id=None, extra_context=None):
        #user = request.user
        user = get_user(request)
        permission_set = user.get_all_permissions()



        if not get_country_from_url(request.get_full_path()).lower() == user.country.iso_code.lower():
            context = {
                'error':'You cannot access other market information',
                'home_url': '/%s/' % (user.country.iso_code)
            }
            return error_template('403',request=request,context=context,label='error')
            #raise Unauthorized("Permission denied")
        
        else:
            if "%s.%s" % (app_label,action) in permission_set:
              
                context = {
                    'title': _('%s administration') % capfirst(app_label),
                    'add' : True,
                    'submit_row' : True,
                    'uid': '69c2bcfd-4bab-43ac-a746-e456bf096a36',
                    'maxfilesize': '16777216',
                    'minfilesize': '1024',
                    'open_tv': u'{{',
                    'close_tv': u'}}',
                    }
                
                extra_context = dict()
                extra_context['home_url'] = '/%s/' % (user.country.iso_code)
                extra_context['profile'] = get_user(request).get_profile();
                extra_context['action'] = action.lower();
                extra_context['object_id'] = object_id;
                extra_context['path'] = request.path;
                #print >> sys.stdout,action
                extra_context['modules'] = get_accessble_modules(request,sel_mod=app_label,sel_action=action)
                context.update(extra_context or {})

                return TemplateResponse(request, self.app_index_template or [
                    'base_templates/%s/%s.html' % (app_label,action),
                    #'customer_login/change_form.html' ,
                    'base_templates/app_index.html',
                ], context, current_app=self.name)
            else:
                context = {
                    'error':'Permission denied',
                    'home_url': '/%s/' % (user.country.iso_code)
                }
                return error_template('403',request=request,context=context,label='error')
                #raise Http404('!!!permission denied!!!')
                #raise Unauthorized("Permission denied")

    def app_mond_index(self, request, extra_context=None):
        #user = request.user
        app_label = 'Module'
        user = get_user(request)
        #print >> sys.stdout,request.path
        has_module_perms = user.has_module_perms(app_label)
        app_dict = {}
        #self._registry = admin.site._registry
        for model, model_admin in self._registry.items():
            if app_label == model._meta.app_label:
                if has_module_perms:
                    perms = model_admin.get_model_perms(request)

                    # Check whether user has any perm for this module.
                    # If so, add the module to the model_list.
                    if True in perms.values():
                        info = (app_label, model._meta.module_name)
                        model_dict = {
                            'name': capfirst(model._meta.verbose_name_plural),
                            'perms': perms,
                        }
                        if perms.get('change', False):
                            try:
                                model_dict['admin_url'] = reverse('customer_admin:%s_%s_changelist' % info, current_app=self.name)
                            except NoReverseMatch:
                                pass
                        if perms.get('add', False):
                            try:
                                model_dict['add_url'] = reverse('customer_admin:%s_%s_add' % info, current_app=self.name)
                            except NoReverseMatch:
                                pass
                        if app_dict:
                            app_dict['models'].append(model_dict),
                        else:
                            # First time around, now that we know there's
                            # something to display, add in the necessary meta
                            # information.
                            app_dict = {
                                'name': app_label.title(),
                                'app_url': '',
                                'has_module_perms': True,
                                'models': [model_dict],
                            }
        if not app_dict:
            #raise Http404('The requested admin page does not exist.')
            raise Unauthorized("Permission denied")
        # Sort the models alphabetically within each app.
        app_dict['models'].sort(key=lambda x: x['name'])
        context = {
            'title': _('%s administration') % capfirst(app_label),
            'app_list': [app_dict],
        }
        extra_context = dict()
        extra_context['profile'] = get_user(request).get_profile();
        
        
        context.update(extra_context or {})

        return TemplateResponse(request, self.app_index_template or [
            'base_templates/%s/app_index.html' % app_label,
            #'customer_login/change_form.html' ,
            'customer_login/app_index.html'
        ], context, current_app=self.name)

# This global object represents the default admin site, for the common case.
# You can instantiate AdminSite in your own code to create a custom admin site.
usersite = CustomerView()
