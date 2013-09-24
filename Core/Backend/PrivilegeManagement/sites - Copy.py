from functools import update_wrapper
from django.http import Http404,HttpResponseForbidden, HttpResponseRedirect
from django.contrib.admin import ModelAdmin, actions
from UserManagement.forms import AuthenticationForm
from UserManagement import REDIRECT_FIELD_NAME
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
from UserManagement import get_user
from django.core.urlresolvers import reverse


import sys

LOGIN_FORM_KEY = 'this_is_the_login_form'

class AlreadyRegistered(Exception):
    pass

class NotRegistered(Exception):
    pass

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
                if request.path == reverse('customer_admin:logout',
                                           current_app=self.name):
                    index_path = reverse('customer_admin:index', current_app=self.name)
                    return HttpResponseRedirect(index_path)
                return self.login(request)
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
            url(r'^password_change/done/$',
                wrap(self.password_change_done, cacheable=False),
                name='password_change_done'),
            url(r'^jsi18n/$',
                wrap(self.i18n_javascript, cacheable=False),
                name='jsi18n'),
            
            url(r'^r/(?P<content_type_id>\d+)/(?P<object_id>.+)/$',
                wrap(contenttype_views.shortcut)),
            url(r'^(?P<app_label>\w+)/$',
                wrap(self.app_index),
                name='app_list')
            
        )

        # Add in each model's views.
        

        from Components.models import UserModules
        for module in UserModules.objects.all():
            urlpatterns += patterns('',
                url(r'^%s/$' %(module.title()),
                    wrap(self.app_index,app_label= module.title()),
                    name=module.title()
                    #name='app_list'
                    )
            )
              
        from Components.models import UserPrivilleges
        for privillege in UserPrivilleges.objects.all():
            urlpatterns += patterns('',
                url(r'^%s/%s/$' % (privillege.module.title(), privillege.action.title()),
                    wrap(self.app_mod_index,app_label= privillege.module.title(),action=privillege.action.title()),
                    name=privillege.module.title()+"_"+privillege.action.title(),
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
        print >> sys.stdout, self.app_name, self.name
        return self.get_urls(), self.app_name, self.name

    def password_change(self, request):
        """
        Handles the "change password" task -- both form display and validation.
        """
        from UserManagement.views import password_change
        
        url = reverse('customer_admin:password_change_done', current_app=self.name)
        defaults = {
            'current_app': self.name,
            'post_change_redirect': url
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
        from UserManagement.views import password_change_done
        defaults = {
            'current_app': self.name,
            'extra_context': extra_context or {},
        }
        if self.password_change_done_template is not None:
            defaults['template_name'] = self.password_change_done_template
        return password_change_done(request, **defaults)

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
        from UserManagement.views import logout
        defaults = {
            'current_app': self.name,
            'extra_context': extra_context or {},
        }
        if self.logout_template is not None:
            defaults['template_name'] = 'customer_login/login.html'
        return logout(request, **defaults)

    @never_cache
    def login(self, request, extra_context=None):
        """
        Displays the login form for the given HttpRequest.
        """
        from UserManagement.views import login
        context = {
            'title': _('Log in'),
            'app_path': request.get_full_path(),
            REDIRECT_FIELD_NAME: request.get_full_path(),
        }
        context.update(extra_context or {})
        defaults = {
            'extra_context': context,
            'current_app': self.name,
            'authentication_form': self.login_form or AuthenticationForm,
            'template_name': self.login_template or 'customer_login/login.html',
        }
        return login(request, **defaults)

    @never_cache
    def index(self, request, extra_context=None):
        """
        Displays the main admin index page, which lists all of the installed
        apps that have been registered in this site.
        """
        app_dict = {}
        #user = request.user
        user = get_user(request)

        from Components.models import UserModules
        for module in UserModules.objects.all():
            app_label = module.module_name
            permission_set = user.get_all_permissions();
            has_module_perms = user.has_module_perms(app_label)
            if has_module_perms:
                perms = module.get_model_perms(module=module.pk)

                # Check whether user has any perm for this module.
                # If so, add the module to the model_list.
                info = (app_label, module.module_name)

                app_dict[app_label] = {
                    'name': app_label.title(),
                    'app_url': reverse('customer_admin:app_list', kwargs={'app_label': app_label}, current_app=self.name),
                    'has_module_perms': has_module_perms,
                    'models': [],
                }
                
                for prm in perms:
                    if "%s.%s" % (app_label,prm) in permission_set:
                        model_dict = {
                            'name': capfirst(prm),
                            #'app_url': reverse('customer_admin:%s/%s' % (app_label,prm), kwargs={'app_label': app_label}, current_app=prm),

                        }
                        #reverse('customer_admin:%s_%s' % (app_label,prm),urlconf=None, kwargs={'app_label': app_label}, current_app=self.name)
                        model_dict['admin_url'] = ('%s/%s' % (app_label,prm))
                        try:
                            model_dict['admin_url'] = reverse('customer_admin:%s/%s' % (app_label,prm),urlconf=None, kwargs={'app_label': app_label}, current_app=self.name)
                        except NoReverseMatch:
                            pass

                        #print >> sys.stdout,model_dict.name
                        app_dict[app_label]['models'].append(model_dict)
                        


        """
        for model, model_admin in self._registry.items():
            app_label = model._meta.app_label
            has_module_perms = user.has_module_perms(app_label)
            print model_admin
            if has_module_perms:
                perms = model_admin.get_model_perms(request)
                print perms
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
                    if app_label in app_dict:
                        app_dict[app_label]['models'].append(model_dict)
                    else:
                        app_dict[app_label] = {
                            'name': app_label.title(),
                            'app_url': reverse('customer_admin:app_list', kwargs={'app_label': app_label}, current_app=self.name),
                            'has_module_perms': has_module_perms,
                            'models': [model_dict],
                        }
        
        # Sort the apps alphabetically.
        """
        app_list = app_dict.values()
        app_list.sort(key=lambda x: x['name'])

        # Sort the models alphabetically within each app.
        for app in app_list:
            app['models'].sort(key=lambda x: x['name'])

        context = {
            'title': _('Site administration'),
            'app_list': app_list,
        }

        extra_context = dict()
        extra_context['profile'] = get_user(request).get_profile();
        #context.url ='/US/'
        context.update(extra_context or {})
        return TemplateResponse(request, [
            self.index_template or 'customer_login/index.html',
        ], context, current_app=self.name)

    def app_mod_index(self, request, app_label,action, extra_context=None):
        #user = request.user
        user = get_user(request)
        permission_set = user.get_all_permissions()
        if "%s.%s" % (app_label,action) in permission_set:
  
            app_dict = {}

            app_dict = {
                'name': app_label.title(),
                'app_url': '',
                'has_module_perms': True,
                'models': [],
            }
               
            model_dict = {
                'name': capfirst(action),
                #'app_url': reverse('customer_admin:%s/%s' % (app_label,prm), kwargs={'app_label': app_label}, current_app=prm),
            }
            model_dict['admin_url'] = ('/home/%s/%s' % (app_label,action))
            try:
                model_dict['admin_url'] = reverse('customer_admin:%s/%s' % (app_label,action),urlconf=None, kwargs={'app_label': app_label}, current_app=self.name)
            except NoReverseMatch:
                pass

                            #print >> sys.stdout,model_dict.name
            app_dict['models'].append(model_dict)

        

            if not app_dict:
                raise Http404('The requested admin page does not exist.')
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
                #'customer_login/%s/app_index.html' % app_label,
                'customer_login/change_form.html' ,
                #'customer_login/app_index.html',
            ], context, current_app=self.name)
        else:
            raise Http404('!!!permission denied!!!')

    def app_index(self, request, app_label, extra_context=None):
        #user = request.user
        user = get_user(request)
        permission_set = user.get_all_permissions()
        app_dict = {}
        #self._registry = admin.site._registry
        from Components.models import UserModules
        for module in UserModules.objects.filter(module_name=app_label):
            app_label = module.module_name
            
            has_module_perms = user.has_module_perms(app_label)
            if has_module_perms:
                perms = module.get_model_perms(module=module.pk)

                    # Check whether user has any perm for this module.
                    # If so, add the module to the model_list.
                app_dict = {
                    'name': app_label.title(),
                    'app_url': '',
                    'has_module_perms': has_module_perms,
                    'models': [],
                }
               
                for prm in perms:
                    if "%s.%s" % (app_label,prm) in permission_set:
                        model_dict = {
                            'name': capfirst(prm),
                                #'app_url': reverse('customer_admin:%s/%s' % (app_label,prm), kwargs={'app_label': app_label}, current_app=prm),
                        }
                        model_dict['admin_url'] = ('/home/%s/%s' % (app_label,prm))
                        try:
                            model_dict['admin_url'] = reverse('customer_admin:%s/%s' % (app_label,prm),urlconf=None, kwargs={'app_label': app_label}, current_app=self.name)
                        except NoReverseMatch:
                            pass

                        #print >> sys.stdout,model_dict.name
                        app_dict['models'].append(model_dict)

        

        if not app_dict:
            raise Http404('The requested admin page does not exist.')
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
            'customer_login/%s/app_index.html' % app_label,
            'customer_login/app_index.html'
        ], context, current_app=self.name)


    def app_mond_index(self, request, extra_context=None):
        #user = request.user
        app_label = 'Module'
        user = get_user(request)
        print >> sys.stdout,request.path
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
            raise Http404('The requested admin page does not exist.')
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
            'customer_login/change_form.html' ,
            #'customer_login/app_index.html'
        ], context, current_app=self.name)

# This global object represents the default admin site, for the common case.
# You can instantiate AdminSite in your own code to create a custom admin site.
usersite = CustomerView()
