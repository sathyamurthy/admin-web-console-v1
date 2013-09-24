from django.db import transaction
from django.conf import settings
from django.contrib import admin
from Core.Countries.models import WorldCountries,WorldRegion




class WorldRegionAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    class Meta:
        model = WorldRegion
        fields = ('region')

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(WorldRegionAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

class WorldCountriesAdmin(admin.ModelAdmin):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    """
    def queryset(self, request):
        qs = super(WorldCountriesAdmin, self).queryset(request)

        User = request.user
        if User.is_superuser:
            return qs
        if User.is_anonymous() is not None:
            LocalUser = get_user(request)
            if LocalUser.is_superuser == 0:
                return qs
            else:
                return qs.filter(Q(country=LocalUser.country))
    """
    class Meta:
        model = WorldCountries
        fields = ('country_name','iso_code','region')

    """
    def queryset(self, request):
        
        Filter the objects displayed in the change_list to only
        display those for the currently signed in user.
        
        qs = super(WorldCountriesAdmin, self).queryset(request)
        #if request.user.is_superuser:
            #return qs
        return qs.filter(id=1)
    """
    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(WorldCountriesAdmin, self).save(commit=False)
        if commit:
            user.save()
        return user

admin.site.register(WorldCountries,WorldCountriesAdmin)
admin.site.register(WorldRegion,WorldRegionAdmin)
