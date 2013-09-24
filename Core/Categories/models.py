import urllib

from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db import models
from Countries.models import WorldCountries
from django.db.models.manager import EmptyManager
from mptt.models import MPTTModel, TreeForeignKey


class Categories(MPTTModel):
    category_name = models.CharField(max_length=500, null=False, blank=False)
    parent = TreeForeignKey('self', null=True, blank=True, related_name='children')
    countries = models.ManyToManyField(WorldCountries, blank=True,default="all")
    owner = models.IntegerField(blank=False,default=0)
    modified = models.DateTimeField(auto_now=True)
    is_system_folder = models.BooleanField(default=False)
    class Meta:
        verbose_name = 'Book category information'
        verbose_name_plural = 'Book category informations'

    def get_full_name(self):
        # The user is identified by their email address
        if self.is_system_folder:
            return '[system] ' + self.category_name
        else:
            system  = 'system'
            try:
                system = WorldCountries.objects.get(pk=self.owner).country_name
            except:
                pass
            return '[' + system +'] '+ self.category_name

    def get_short_name(self):
        # The user is identified by their email address
        if self.is_system_folder:
            return '[system] ' + self.category_name
        else:
            system  = 'system'
            try:
                system = WorldCountries.objects.get(pk=self.owner).country_name
            except:
                pass
            return '[' + system +'] '+ self.category_name

    def __unicode__(self):
        if self.is_system_folder:
            return '[system] ' + self.category_name
        else:
            system  = 'system'
            try:
                system = WorldCountries.objects.get(pk=self.owner).country_name
            except:
                pass
            return '[' + system +'] '+ self.category_name



