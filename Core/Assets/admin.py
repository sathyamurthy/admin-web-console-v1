from django.db import transaction
from django import forms
from django.conf import settings
from django.contrib import admin
from Assets.models import Properties,GalleryPreset,ExtendedContent,ExtentedType

class PropertiesAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = Properties

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(PropertiesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class ExtentedTypeAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = ExtentedType

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(ExtentedTypeAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class ExtendedContentAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = ExtendedContent

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(ExtendedContentAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class GalleryPresetForm(forms.ModelForm):
    class Meta:
        model = GalleryPreset
        widgets = {
            'properties': forms.SelectMultiple(attrs={'size': 20})
        }

class GalleryPresetAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    form = GalleryPresetForm
    class Meta:
        model = GalleryPreset

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(GalleryPresetAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user


admin.site.register(Properties,PropertiesAdmin)
admin.site.register(GalleryPreset,GalleryPresetAdmin)
admin.site.register(ExtendedContent,ExtendedContentAdmin)
admin.site.register(ExtentedType,ExtentedTypeAdmin)
