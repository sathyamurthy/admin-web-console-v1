from Core.UserManagement.models import GlobalUserModel as User
from Core.Countries.models import WorldCountries

import sys

class ModelBackend(object):
    """
    Authenticates against django.contrib.auth.models.User.
    """
    supports_inactive_user = True

    # TODO: Model, login attribute name and password attribute name should be
    # configurable.
    #def authenticate(self, username=None, password=None):
    def authenticate(self, username=None, password=None,country=None):
     
        try:
            try:
                country = WorldCountries.objects.get(iso_code=country)
            except country.DoesNotExist:
                return None
            user = User.objects.get(username=username,country=country.pk)
            if user.check_password(password):
                return user

            #import pdb
            #pdb.set_trace()
        except User.DoesNotExist:
            return None
    """
    def authenticate(self, username=None, password=None):
     
        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user

            #import pdb
            #pdb.set_trace()
        except User.DoesNotExist:
            return None
    """
    def get_all_permissions(self, user_obj, obj=None):
        if user_obj.is_anonymous() or obj is not None:
            return set()

        if not hasattr(user_obj, '_perm_cache'):
            from UserManagement.models import UserGroups
            from Components.models import UserPrivileges
            try :
                if user_obj.is_superuser:
                    user_obj._perm_cache = set([u"%s.%s" % (p.module, p.action) for p in UserGroups.objects.filter(pk=1)[0].modules.all()])
                else:
                    user_obj._perm_cache = set([u"%s.%s" % (p.module, p.action) for p in UserGroups.objects.filter(pk=user_obj.groups.id)[0].modules.all()])
            except :
                user_obj._perm_cache = set()

        return user_obj._perm_cache
    
        #if not hasattr(user_obj, '_perm_cache'):
            #user_obj._perm_cache = set([u"%s.%s" % (p.content_type.app_label, p.codename) for p in user_obj.user_permissions.select_related()])
            #user_obj._perm_cache.update(self.get_group_permissions(user_obj))
        #return user_obj._perm_cache

    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active:
            return False
        return perm in self.get_all_permissions(user_obj, obj)

    def has_module_perms(self, user_obj, app_label):
        """
        Returns True if user_obj has any permissions in the given app_label.
        """
        if not user_obj.is_active:
            return False
        for perm in self.get_all_permissions(user_obj):
            if perm[:perm.index('.')] == app_label:
                return True
        return False

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class RemoteUserBackend(ModelBackend):
    """
    This backend is to be used in conjunction with the ``RemoteUserMiddleware``
    found in the middleware module of this package, and is used when the server
    is handling authentication outside of Django.

    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """

    # Create a User object if not already in the database?
    create_unknown_user = True

    def authenticate(self, remote_user):
        """
        The username passed as ``remote_user`` is considered trusted.  This
        method simply returns the ``User`` object with the given username,
        creating a new ``User`` object if ``create_unknown_user`` is ``True``.

        Returns None if ``create_unknown_user`` is ``False`` and a ``User``
        object with the given username is not found in the database.
        """
        if not remote_user:
            return
        user = None
        username = self.clean_username(remote_user)

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = User.objects.get_or_create(username=username)
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                pass
        return user

    def clean_username(self, username):
        """
        Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, returns the username unchanged.
        """
        return username

    def configure_user(self, user):
        """
        Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user
