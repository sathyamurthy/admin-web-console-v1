from django.db import models


from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db import models
from django.db.models.manager import EmptyManager
from jsonfield import JSONField
from Assets.models import ExtendedContent
# Create your models here.

class Files(models.Model):
    name = models.CharField(max_length=50,  null=False, blank=False)
    #properties = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})
    properties = JSONField(default=None)
    limited_properties = JSONField(default=None)
    path = models.TextField(null=False, blank=False)
    relative_path = models.TextField(null=False, blank=False)
    extension = models.CharField(max_length=30,  null=False, blank=False)
    file_type = models.CharField(max_length=70,  null=False, blank=False)
    gallery = models.ForeignKey(ExtendedContent, blank=True,default="all")
    modified = models.DateTimeField(auto_now=True)
    position = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = 'File'
        verbose_name_plural = 'Files'
        unique_together = (('name', 'gallery'),)
        ordering = ['gallery','-position']

    def get_full_name(self):
        # The user is identified by their email address
        return ' [ '+ self.gallery.gallery_id+' ] '+ self.name

    def get_short_name(self):
        # The user is identified by their email address
        return ' [ '+ self.gallery.gallery_id+' ] '+ self.name

    def __unicode__(self):
        return ' [ '+ self.gallery.gallery_id+' ] '+ self.name
