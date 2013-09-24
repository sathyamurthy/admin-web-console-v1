from django.db import transaction
from django.conf import settings
from django.contrib import admin
from Core.Backend.Components.models import UserModules,UserActions,UserPrivileges,ModulesGroup


class ModulesGroupAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = ModulesGroup
        fields = ('module_name')

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(ModulesGroupAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class UserModulesAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = UserModules
        fields = ('module_name')

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserModulesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class UserPrivilegesAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = UserPrivileges
        fields = ('privilage_name')

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserPrivilegesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user    

class UserActionsAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = UserActions
        fields = ('action_name')

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserActionsAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user



admin.site.register(UserModules,UserModulesAdmin)
admin.site.register(UserActions,UserActionsAdmin)
admin.site.register(UserPrivileges,UserPrivilegesAdmin)
admin.site.register(ModulesGroup,ModulesGroupAdmin)
