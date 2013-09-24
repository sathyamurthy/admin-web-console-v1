import urllib

from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db import models
from django.db.models.manager import EmptyManager
from jsonfield import JSONField
import collections
from Countries.models import WorldCountries


class ExtendedContent(models.Model):
    name = models.CharField(max_length=50,  null=False, blank=False)
    gallery_id = models.CharField(max_length=50, unique=True, null=False, blank=False)
    #properties = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})
    properties = JSONField(default=None)
    items = JSONField(default=None)
    countries = models.ManyToManyField(WorldCountries, blank=True,default="all")
    preset = models.BigIntegerField(blank=False)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Extended content'
        verbose_name_plural = 'Extended content'

    def get_full_name(self):
        # The user is identified by their email address
        return '[Gallery Id : '+ self.gallery_id +' ] '+ self.name

    def get_short_name(self):
        # The user is identified by their email address
        return  '[Gallery Id :'+ self.gallery_id +' ] '+ self.name

    def __unicode__(self):
        return  '[Gallery Id :'+ self.gallery_id +' ] '+ self.name
    

class ExtentedType(models.Model):
    name = models.CharField( max_length=50, unique=True, null=False, blank=False)
    class Meta:
        verbose_name = 'Extended content type'
        verbose_name_plural = 'Extended content type'
    def get_full_name(self):
        # The user is identified by their email address
        return self.name

    def get_short_name(self):
        # The user is identified by their email address
        return self.name

    def __unicode__(self):
        return self.name


class Properties(models.Model):
    TYPE = (
        ('text', 'Text'),
        ('select', 'Select'),
        ('check', 'Check'),
        ('textarea', 'Text area'),
        ('filebrowser', 'File browser'),
    )
    Groups = (
        ('default', 'Default'),
        ('gallery', 'Gallery'),
        ('item', 'Item'),
    )
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)
    friendly_name = models.CharField(max_length=200,default='', blank=True)
    ptype = models.CharField(max_length=10,choices=TYPE,default='text', null=False, blank=False)
    value = JSONField(null=True, blank=True)
    group = models.CharField(max_length=10,choices=Groups,default='default', null=False, blank=False)
    validator = JSONField(null=True, blank=True)
    class Meta:
        verbose_name = 'Property'
        verbose_name_plural = 'Properties'

    def get_full_name(self):
        # The user is identified by their email address
        return '['+self.group+']' + self.friendly_name

    def get_short_name(self):
        # The user is identified by their email address
        return '['+self.group+']' + self.friendly_name

    def __unicode__(self):
        return '['+self.group+']' + self.friendly_name


class GalleryPreset(models.Model):
    name = models.CharField( max_length=50, unique=True, null=False, blank=False)
    properties = models.ManyToManyField('Properties',blank=False)
    gallery_type = models.ManyToManyField('ExtentedType',blank=False)
    class Meta:
        verbose_name = 'Gallery preset'
        verbose_name_plural = 'Gallery presets'

    def get_full_name(self):
        # The user is identified by their email address
        return self.name

    def get_short_name(self):
        # The user is identified by their email address
        return self.name

    def __unicode__(self):
        return self.name
    
