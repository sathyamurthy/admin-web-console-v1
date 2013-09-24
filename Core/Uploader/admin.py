from django.db import transaction
from django.conf import settings
from django.contrib import admin
from Uploader.models import Files

class FilesAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = Files

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(FilesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

admin.site.register(Files,FilesAdmin)
