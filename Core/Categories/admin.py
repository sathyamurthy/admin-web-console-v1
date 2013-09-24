from django.conf import settings
from django.contrib import admin
from Categories.models import Categories
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django import forms
from mptt.admin import MPTTModelAdmin
from SiteManagement import site
from Countries.models import WorldCountries
from Categories.views import CategoriesForm
from UserManagement import get_user

import sys 

class CategoriesAdmin(MPTTModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = Categories
        fields = ('category_name')


    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(CategoriesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class ClientCategoriesAdmin(MPTTModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = Categories
        fields = ('category_name')

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(CategoriesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user


admin.site.register(Categories,CategoriesAdmin)
site.usersite.register(Categories,ClientCategoriesAdmin)
