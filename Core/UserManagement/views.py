import urlparse
import os, sys
from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, QueryDict
from django.template.response import TemplateResponse
from django.utils.http import base36_to_int, is_safe_url
from django.utils.translation import ugettext as _
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

from Core.UserManagement import get_user

# Avoid shadowing the login() and logout() views below.
#from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
from Core.UserManagement import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout
#from django.contrib.auth.decorators import login_required
from Core.UserManagement.decorators import login_required
from Core.UserManagement.forms import UpdateUserInformation as update_form,AuthenticationForm, PasswordResetForm, SetPasswordForm, PasswordChangeForm
from Core.UserManagement.models import GlobalUserModel as User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site


@sensitive_post_parameters()
@csrf_protect
@never_cache
def after_login(request, template_name='base_templates/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=PasswordResetForm,
          current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.REQUEST.get(redirect_field_name, './')

    if request.method == "POST":
        form = authentication_form(data=request.POST)
        if form.is_valid():
            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = settings.LOGIN_REDIRECT_URL

            # Okay, security check complete. Log the user in.
            auth_login(request, form.get_user())

            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    request.session.set_test_cookie()

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    extra_context = dict()
    extra_context['profile'] = get_user(request).get_profile();

    #import pdb
    #pdb.set_trace()
    #print >> sys.stdout,context
 
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)



@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name='base_templates/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=AuthenticationForm,
          current_app=None, extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.REQUEST.get(redirect_field_name, './')

    if request.method == "POST":
        form = authentication_form(data=request.POST)
        if form.is_valid():
            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, host=request.get_host()):
                redirect_to = settings.LOGIN_REDIRECT_URL

            # Okay, security check complete. Log the user in.
            auth_login(request, form.get_user())

            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    request.session.set_test_cookie()

    current_site = get_current_site(request)
    #print >> sys.stdout,form.errors
    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

@sensitive_post_parameters()
@csrf_protect
@never_cache
def accout_information_update(request, template_name='base_templates/login.html',
          extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    user = get_user(request)
    success = 0
    if request.method == "POST":
        form = update_form(user=user,data=request.POST)
        if form.is_valid():
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.email = request.POST['email']
            user.username = user.username
            form.save(user)
            success=1

    else:
        form = update_form(user=user,initial={'username': user.username,'first_name': user.first_name,'last_name':user.last_name,'email':user.email})

    form.fields['username'].widget.attrs['readonly'] = True

    #print >> sys.stdout,form.errors
    context = {
        'form': form,
    }
    if success == 1 :
        extra_context['saved'] = 'Updated successfully'
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context)

def homepage(request):
    User = get_user(request)
    if User.is_authenticated():
        from django.shortcuts import redirect
        return HttpResponseRedirect('/%s/' % User.country.iso_code)
    context ={}
    from Core.Countries.models import WorldCountries
    from django.db.models import Q
    context['countries'] = WorldCountries.objects.filter(~Q(pk=1000))
    #context['form']=AuthenticationForm
    return TemplateResponse(request, 'base_templates/home_page.html', context,)


def logout(request, next_page=None,
           template_name='base_templates/registration/logged_out.html',
           redirect_field_name=REDIRECT_FIELD_NAME,
           current_app=None, extra_context=None):
    """
    Logs out the user and displays 'You are logged out' message.
    """
    auth_logout(request)

    if redirect_field_name in request.REQUEST:
        next_page = request.REQUEST[redirect_field_name]
        # Security check -- don't allow redirection to a different host.
        if not is_safe_url(url=next_page, host=request.get_host()):
            next_page = request.path

    if next_page:
        # Redirect to this page until the session has been cleared.
        return HttpResponseRedirect(next_page)

    current_site = get_current_site(request)
    context = {
        'site': current_site,
        'site_name': current_site.name,
        'title': _('Logged out')
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
        current_app=current_app)

def logout_then_login(request, login_url=None, current_app=None, extra_context=None):
    """
    Logs out the user if he is logged in. Then redirects to the log-in page.
    """
    if not login_url:
        login_url = settings.LOGIN_URL
    return logout(request, login_url, current_app=current_app, extra_context=extra_context)

def redirect_to_login(next, login_url=None,
                      redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Redirects the user to the login page, passing the given 'next' page
    """
    if not login_url:
        login_url = settings.LOGIN_URL

    login_url_parts = list(urlparse.urlparse(login_url))
    if redirect_field_name:
        querystring = QueryDict(login_url_parts[4], mutable=True)
        querystring[redirect_field_name] = next
        login_url_parts[4] = querystring.urlencode(safe='/')

    return HttpResponseRedirect(urlparse.urlunparse(login_url_parts))

# 4 views for password reset:
# - password_reset sends the mail
# - password_reset_done shows a success message for the above
# - password_reset_confirm checks the link the user clicked and
#   prompts for a new password
# - password_reset_complete shows a success message for the above

@csrf_protect
def password_reset(request, is_admin_site=False,
                   template_name='base_templates/registration/password_reset_form.html',
                   email_template_name='base_templates/registration/password_reset_email.html',
                   subject_template_name='base_templates/registration/password_reset_subject.txt',
                   password_reset_form=PasswordResetForm,
                   token_generator=default_token_generator,
                   post_reset_redirect=None,
                   from_email=None,
                   current_app=None,
                   extra_context=None):


    if post_reset_redirect is None:
        post_reset_redirect = reverse('UserManagement.views.password_reset_done')
    if request.method == "POST":
        form = password_reset_form(request.POST)
        if form.is_valid():
            opts = {
                'use_https': request.is_secure(),
                'token_generator': token_generator,
                'from_email': from_email,
                'email_template_name': email_template_name,
                'subject_template_name': subject_template_name,
                'request': request,
            }
            if is_admin_site:
                opts = dict(opts, domain_override=request.get_host())
            form.save(**opts)
            return HttpResponseRedirect(post_reset_redirect)
    else:
        form = password_reset_form()
    context = {
        'form': form,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

def password_reset_done(request,
                        template_name='base_templates/registration/password_reset_done.html',
                        current_app=None, extra_context=None):
    context = {}
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

# Doesn't need csrf_protect since no-one can guess the URL
#@sensitive_post_parameters()
#@never_cache
def password_reset_confirm(request, uidb36=None, token=None,
                           template_name='base_templates/registration/password_reset_confirm.html',
                           token_generator=default_token_generator,
                           set_password_form=SetPasswordForm,
                           post_reset_redirect=None,
                           current_app=None, extra_context=None):
    """
    View that checks the hash in a password reset link and presents a
    form for entering a new password.
    """
    assert uidb36 is not None and token is not None # checked by URLconf
    if post_reset_redirect is None:
        post_reset_redirect = reverse('UserManagement.views.password_reset_complete')
    try:
        uid_int = base36_to_int(uidb36)
        user = User.objects.get(id=uid_int)
    except (ValueError, User.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        validlink = True
        if request.method == 'POST':
            form = set_password_form(user, request.POST)
            if form.is_valid():
                form.save()
                return HttpResponseRedirect(post_reset_redirect)
        else:
            form = set_password_form(None)
    else:
        validlink = False
        form = None
    context = {
        'form': form,
        'validlink': validlink,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

def password_reset_complete(request,
                            template_name='base_templates/registration/password_reset_complete.html',
                            current_app=None, extra_context=None):
    context = {
        'login_url': settings.LOGIN_URL
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

#@sensitive_post_parameters()
#@csrf_protect
#@login_required
def password_change(request,
                    template_name='base_templates/registration/password_change_form.html',
                    post_change_redirect=None,
                    password_change_form=PasswordChangeForm,
                    current_app=None, extra_context=None):
    User = get_user(request)
    
    if post_change_redirect is None:
        post_change_redirect = reverse('UserManagement.views.password_change_done')
    if request.method == "POST":
        form = password_change_form(user=User, data=request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(post_change_redirect)
    else:
        form = password_change_form(user=User)
    context = {
        'form': form,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)

#@login_required
def password_change_done(request,
                         template_name='base_templates/registration/password_change_done.html',
                         current_app=None, extra_context=None):
    context = {}
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context,
                            current_app=current_app)
