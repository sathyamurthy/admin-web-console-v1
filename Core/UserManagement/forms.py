from django import forms
from django.forms.util import flatatt
from django.template import loader
from django.utils.encoding import smart_str
from django.utils.http import int_to_base36
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext, ugettext_lazy as _

from django.contrib.auth.hashers import UNUSABLE_PASSWORD, is_password_usable, get_hasher
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site


#from app.auth_backends.CustomUserModelBackend import authenticate
from Core.UserManagement import authenticate
from Core.UserManagement.models import GlobalUserModel as User,UserStatus,UserType
from Core.Countries.models import WorldCountries

import sys

UNMASKED_DIGITS_TO_SHOW = 6

mask_password = lambda p: "%s%s" % (p[:UNMASKED_DIGITS_TO_SHOW], "*" * max(len(p) - UNMASKED_DIGITS_TO_SHOW, 0))


class ReadOnlyPasswordHashWidget(forms.Widget):
    def render(self, name, value, attrs):
        encoded = value

        if not is_password_usable(encoded):
            return "None"

        final_attrs = self.build_attrs(attrs)

        encoded = smart_str(encoded)

        if len(encoded) == 32 and '$' not in encoded:
            algorithm = 'unsalted_md5'
        else:
            algorithm = encoded.split('$', 1)[0]

        try:
            hasher = get_hasher(algorithm)
        except ValueError:
            summary = "<strong>Invalid password format or unknown hashing algorithm.</strong>"
        else:
            summary = ""
            for key, value in hasher.safe_summary(encoded).iteritems():
                summary += "<strong>%(key)s</strong>: %(value)s " % {"key": ugettext(key), "value": value}

        return mark_safe("<div%(attrs)s>%(summary)s</div>" % {"attrs": flatatt(final_attrs), "summary": summary})


class ReadOnlyPasswordHashField(forms.Field):
    widget = ReadOnlyPasswordHashWidget

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("required", False)
        super(ReadOnlyPasswordHashField, self).__init__(*args, **kwargs)


class UserCreationForm(forms.ModelForm):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """
    error_messages = {
        'duplicate_username': _("A user with that username already exists."),
        'password_mismatch': _("The two password fields didn't match."),
    }

    first_name = forms.RegexField(label=_("first_name"), max_length=30,
        regex=r"^[\w.@+\\ -]+$",
        help_text = _("Required. 30 characters or fewer. Letters, digits and "
                      "@/./+/-/_ only."),
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    username = forms.RegexField(label=("username"), max_length=30,
        regex=r'^[\w.@+-]+$',
        help_text = _("Required. 30 characters or fewer. Letters, digits and "
                      "@/./+/-/_ only."),
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    password1 = forms.CharField(label=_("Password"),
        widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password confirmation"),
        widget=forms.PasswordInput,
        help_text = _("Enter the same password as above, for verification."))
    
    is_active = forms.ModelChoiceField(queryset= UserStatus.objects.all(), empty_label="Select status")

    user_type = forms.ModelChoiceField(queryset= UserType.objects.all(), empty_label="Select type")

    """
    def clean_username(self):
        username = self.cleaned_data["username"]
        try:
            self.Meta.model.objects.get(username=username)
        except self.Meta.model.DoesNotExist:
            return username
        raise forms.ValidationError(self.error_messages['duplicate_username'])
    """
    def clean_password2(self):
        password1 = self.cleaned_data.get("password1", "")
        password2 = self.cleaned_data["password2"]
        if password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'])
        return password2

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class UserCreationFormAPI(forms.Form):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """
    error_messages = {
        'duplicate_username': _("A user with that username already exists."),
        'password_mismatch': _("The two password fields didn't match."),
        'invalid_email': _("Please enter a valid email ID "),
    }
    username = forms.RegexField(label=("username"), max_length=30,
        regex=r'^[\w.@+-]+$',
        help_text = _("Required. 30 characters or fewer. Letters, digits and "
                      "@/./+/-/_ only."),
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    email = forms.EmailField(label=_("E-mail"), max_length=75)
    country = ""
    isUpdate = False
    oldName = ""
    class Meta:
        model = User
        fields = ("username",)

    def clean_email(self):
        """
        Validates that an active user exists with the given email address.
        """
        email = self.cleaned_data["email"]
        return email

    def clean_username(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        username = self.cleaned_data["username"]
        if not self.isUpdate:
            try:
                User.objects.get(username=username,country=self.country)
            except User.DoesNotExist:
                return username
        else:
            if self.oldName == username:
                return username
            else:
                try:
                    User.objects.get(username=username,country=self.country)
                except User.DoesNotExist:
                    return username
        error = self.error_messages['duplicate_username']
        raise forms.ValidationError(self.error_messages['duplicate_username'])





class UpdateUserInformation(forms.ModelForm):
    error_messages = {
        'password_incorrect': _("Your password was entered incorrectly. "
                                "Please enter it again."),
    }
    first_name = forms.RegexField(
        label=_("First name"), max_length=30, regex=r"^[\w.@+\\ -]+$",
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    last_name = forms.RegexField(
        label=_("Last name"), max_length=30, regex=r"^[\w.@+\\ -]+$",
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    email = forms.EmailField(label=_("E-mail"), max_length=75)
    username = forms.RegexField(
        label=_("Username"),max_length=30, regex=r"^[\w.@+-]+$",
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput)
    class Meta:
        model = User
        fields = ("first_name","last_name","email")

    def clean_password(self):
        """
        Validates that the old_password field is correct.
        """
        password = self.cleaned_data["password"]
        if not self.user.check_password(password):
            raise forms.ValidationError(
                self.error_messages['password_incorrect'])
        return password

    def __init__(self,user, *args, **kwargs):
        self.user = user
        super(UpdateUserInformation, self).__init__(*args, **kwargs)
        instance = getattr(self, 'instance', None)
        if instance and instance.pk:
            self.fields['username'].widget.attrs['readonly'] = True

    def save(self,user):
        user.save()
        return user


class UserChangeForm(forms.ModelForm):
    username = forms.RegexField(
        label=_("Username"), max_length=30, regex=r"^[\w.@+-]+$",
        help_text = _("Required. 30 characters or fewer. Letters, digits and "
                      "@/./+/-/_ only."),
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    password = ReadOnlyPasswordHashField(label=_("Password"),
        help_text=_("Raw passwords are not stored, so there is no way to see "
                    "this user's password, but you can change the password "
                    "using <a href=\"password/\">this form</a>."))
    first_name = forms.RegexField(
        label=_("first_name"), max_length=30, regex=r"^[\w.@+\\ -]+$",
        help_text = _("Required. 30 characters or fewer. Letters, digits and "
                      "@/./+/-/_ only."),
        error_messages = {
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})

    def clean_password(self):
        return self.initial["password"]

    class Meta:
        model = User

    def __init__(self, *args, **kwargs):
        super(UserChangeForm, self).__init__(*args, **kwargs)
        f = self.fields.get('user_permissions', None)
        if f is not None:
            f.queryset = f.queryset.select_related('content_type')


class AuthenticationForm(forms.Form):
    """
    Base class for authenticating users. Extend this to get a form that accepts
    username/password logins.
    """
    from django.db.models import Q
    username = forms.CharField(label=_("Username"), max_length=30)
    #country = forms.ChoiceField(label=_("Country"),choices=[(country.pk, country.country_name) for country in WorldCountries.objects.filter(~Q(pk=1000))])
    country = forms.CharField(label=_("Country"), max_length=3)
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput)

    error_messages = {
        'invalid_login': _("Please enter a correct username and password. "
                           "Note that both fields are case-sensitive."),
        'no_cookies': _("Your Web browser doesn't appear to have cookies "
                        "enabled. Cookies are required for logging in."),
        'inactive': _("This account is inactive."),
    }

    def __init__(self, request=None, *args, **kwargs):
        """
        If request is passed in, the form will validate that cookies are
        enabled. Note that the request (a HttpRequest object) must have set a
        cookie with the key TEST_COOKIE_NAME and value TEST_COOKIE_VALUE before
        running this validation.
        """
        self.request = request
        self.user_cache = None
        super(AuthenticationForm, self).__init__(*args, **kwargs)

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        country = self.cleaned_data.get('country')
        if username and password:
            self.user_cache = authenticate(username=username,
                                           password=password,country=country)
            
            if self.user_cache is None:
                raise forms.ValidationError(self.error_messages['invalid_login'])
            elif not self.user_cache.is_active:
                raise forms.ValidationError(self.error_messages['inactive'])
        self.check_for_test_cookie()
        return self.cleaned_data

    def check_for_test_cookie(self):
        if self.request and not self.request.session.test_cookie_worked():
            raise forms.ValidationError(self.error_messages['no_cookies'])

    def get_user_id(self):
        if self.user_cache:
            return self.user_cache.id
        return None

    def get_user(self):
        return self.user_cache


class PasswordResetForm(forms.Form):
    error_messages = {
        'unknown_country': _("unknown country "),
        'invalid_email': _("Please enter a valid email ID "),
        'unknown': _("That e-mail address doesn't have an associated "
                     "user account. Are you sure you've registered?"),
        'unusable': _("The user account associated with this e-mail "
                      "address cannot reset the password."),
    }
    email = forms.EmailField(label=_("E-mail"), max_length=75)
    country = forms.CharField(label=_("country"), max_length=3)

    def clean_email(self):
        """
        Validates that an active user exists with the given email address.
        """
        email = self.cleaned_data["email"]
        return email

    def clean(self):
        try:
            email = self.cleaned_data["email"]
        except:
            raise forms.ValidationError(self.error_messages['invalid_email'])
        country = self.cleaned_data["country"]
        #print >>sys.stdout, email
        #print >>sys.stdout, self.cleaned_data.get('country')
        try:
            country = WorldCountries.objects.get(iso_code=country)
        except country.DoesNotExist:
            raise forms.ValidationError(self.error_messages['unknown_country'])
        
        self.users_cache = User.objects.filter(email__iexact=email,is_active=True,country=country.pk)
        #self.users_cache = User.objects.filter(email__iexact=email,is_active=True)
        if not len(self.users_cache):
            raise forms.ValidationError(self.error_messages['unknown'])
        if any((user.password == UNUSABLE_PASSWORD)
               for user in self.users_cache):
            raise forms.ValidationError(self.error_messages['unusable'])
        

    def save(self, domain_override=None,
             subject_template_name='base_templates/registration/password_reset_subject.txt',
             email_template_name='base_templates/registration/password_reset_email.html',
             use_https=False, token_generator=default_token_generator,
             from_email=None, request=None):
        """
        Generates a one-use only link for resetting password and sends to the
        user.
        """
        from django.core.mail import send_mail
        for user in self.users_cache:
            if not domain_override:
                current_site = get_current_site(request)
                site_name = current_site.name
                domain = current_site.domain
            else:
                site_name = domain = domain_override
            from SiteManagement.sites import get_country_from_url
            c = {
                'email': user.email,
                'domain': domain,
                'site_name': site_name,
                'uid': int_to_base36(user.id),
                'user': user,
                'token': token_generator.make_token(user),
                'protocol': use_https and 'https' or 'http',
                'home_url': '/%s/' % get_country_from_url(request.get_full_path()),
            }
            subject = loader.render_to_string(subject_template_name, c)
            # Email subject *must not* contain newlines
            subject = ''.join(subject.splitlines())
            email = loader.render_to_string(email_template_name, c)
            #print >>sys.stdout,from_email
            #print >>sys.stdout,subject
            #print >>sys.stdout,user.email
            #print >>sys.stdout,email
            send_mail(subject, email, from_email, [user.email])


class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set his/her password without entering the
    old password
    """
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    new_password1 = forms.CharField(label=_("New password"),
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=_("New password confirmation"),
                                    widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(SetPasswordForm, self).__init__(*args, **kwargs)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'])
        return password2

    def save(self, commit=True):
        self.user.set_password(self.cleaned_data['new_password1'])
        if commit:
            self.user.save()
        return self.user


class PasswordChangeForm(SetPasswordForm):
    """
    A form that lets a user change his/her password by entering
    their old password.
    """
    error_messages = dict(SetPasswordForm.error_messages, **{
        'password_incorrect': _("Your old password was entered incorrectly. "
                                "Please enter it again."),
    })
    old_password = forms.CharField(label=_("Old password"),
                                   widget=forms.PasswordInput)

    def clean_old_password(self):
        """
        Validates that the old_password field is correct.
        """
        old_password = self.cleaned_data["old_password"]
        if not self.user.check_password(old_password):
            raise forms.ValidationError(
                self.error_messages['password_incorrect'])
        return old_password
PasswordChangeForm.base_fields.keyOrder = ['old_password', 'new_password1',
                                           'new_password2']


class AdminPasswordChangeForm(forms.Form):
    """
    A form used to change the password of a user in the admin interface.
    """
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    password1 = forms.CharField(label=_("Password"),
                                widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password (again)"),
                                widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(AdminPasswordChangeForm, self).__init__(*args, **kwargs)

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'])
        return password2

    def save(self, commit=True):
        """
        Saves the new password.
        """
        self.user.set_password(self.cleaned_data["password1"])
        if commit:
            self.user.save()
        return self.user
