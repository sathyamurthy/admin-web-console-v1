import urllib
from django.db import models
from django.db.models.manager import EmptyManager

class WorldRegion(models.Model):
    region = models.CharField(max_length=80, unique=True)
    class Meta:
        verbose_name = 'World region'
        verbose_name_plural = 'World regions'

    def get_full_name(self):
        # The user is identified by their email address
        return self.region

    def get_short_name(self):
        # The user is identified by their email address
        return self.region

    def __unicode__(self):
        return self.region

class WorldCountries(models.Model):
    country_name = models.CharField(max_length=250)
    iso_code = models.CharField(max_length=3, unique=True,blank=False)
    region = models.ForeignKey('WorldRegion', blank=False)

    class Meta:
        verbose_name = 'World country'
        verbose_name_plural = 'World countries'

    def get_full_name(self):
        # The user is identified by their email address
        return self.country_name

    def get_short_name(self):
        # The user is identified by their email address
        return self.country_name

    def __unicode__(self):
        return self.country_name



