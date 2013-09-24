from django.db import transaction
from django.conf import settings
from django.contrib import admin
from Publication.models import Publication

class PublicationAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = Publication

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(PublicationAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user


admin.site.register(Publication,PublicationAdmin)
