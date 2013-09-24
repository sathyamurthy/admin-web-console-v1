import urllib

from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db import models
from Countries.models import WorldCountries
from Categories.models import Categories
from django.db.models.manager import EmptyManager


class Publication(models.Model):
    book_id = models.CharField( max_length=30, unique=True, null=False, blank=False)
    name = models.CharField(max_length=500, null=False, blank=False)
    category = models.ForeignKey(Categories, blank=True)
    url = models.URLField( max_length=255, unique=True, null=True, blank=True)
    countries = models.ForeignKey(WorldCountries, blank=False)
    class Meta:
        verbose_name = 'Publication information'
        verbose_name_plural = 'Publication informations'

    def get_full_name(self):
        # The user is identified by their email address
        return self.name

    def get_short_name(self):
        # The user is identified by their email address
        return self.name

    def __unicode__(self):
        return self.name



