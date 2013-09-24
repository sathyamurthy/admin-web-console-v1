from django.conf import settings
from django.contrib import admin
from Categories.models import Categories
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django import forms
from mptt.admin import MPTTModelAdmin
from SiteManagement import site
from Countries.models import WorldCountries


class CategoriesForm(forms.ModelForm): 
    def __init__(self, *args, **kwargs):
        super(CategoriesForm, self).__init__(*args, **kwargs)
        wtf = WorldCountries.objects.filter(pk=1);
        w = self.fields['countries'].widget
        choices = []
        for choice in wtf:
            choices.append((choice.id, choice.country_name))
        w.choices = choices
    class Meta:
        model = Categories
