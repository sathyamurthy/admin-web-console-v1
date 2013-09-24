from django.db import transaction
from django.conf import settings
from django.contrib import admin
from Loggers.models import Logging,LogDefinition

class LoggingAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = Logging

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(LoggingAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class LogDefinitionAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = LogDefinition

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(LogDefinitionAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user
admin.site.register(Logging,LoggingAdmin)
admin.site.register(LogDefinition,LogDefinitionAdmin)
