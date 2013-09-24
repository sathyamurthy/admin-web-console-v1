import urllib

from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db import models
from django.db.models.manager import EmptyManager
from mptt.models import MPTTModel, TreeForeignKey



class ModulesGroup(models.Model):
    group_name = models.CharField(max_length=80, unique=True)
    class Meta:
        verbose_name = 'Module group'
        verbose_name_plural = 'Module groups'

    def get_full_name(self):
        # The user is identified by their email address
        return self.group_name

    def title(self):
        # The user is identified by their email address
        return self.group_name

    def get_short_name(self):
        # The user is identified by their email address
        return self.group_name

    def __unicode__(self):
        return self.group_name



class UserModules(models.Model):
    module_name = models.CharField(max_length=80, unique=True)
    groups = models.ForeignKey('ModulesGroup',null=True,blank=True,default=1)
    is_active = models.BooleanField(('is_active'), default=True,)
    class Meta:
        verbose_name = 'Module'
        verbose_name_plural = 'Modules'

    def get_full_name(self):
        # The user is identified by their email address
        return self.module_name

    def title(self):
        # The user is identified by their email address
        return self.module_name

    def get_short_name(self):
        # The user is identified by their email address
        return self.module_name

    def __unicode__(self):
        return self.module_name

    def get_model_perms(self,module):
        raction = {}
        from Components.models import UserPrivileges,UserActions
        for userPriv in UserPrivileges.objects.filter(module=module):
            if userPriv.action.is_active:
                raction[userPriv.action.action_name] = True 
        return raction


class UserActions(models.Model):
    action_name = models.CharField( max_length=80, unique=True)
    friendly_name = models.CharField( max_length=80, blank=True)
    is_active = models.BooleanField(('is_active'), default=True,)
    class Meta:
        verbose_name = 'User action'
        verbose_name_plural = 'User action'

    def get_full_name(self):
        # The user is identified by their email address
        return self.action_name
    def id(self):
        # The user is identified by their email address
        return self.pk

    def title(self):
        # The user is identified by their email address
        return self.action_name

    def get_short_name(self):
        # The user is identified by their email address
        return self.action_name

    def __unicode__(self):
        return self.action_name


class UserPrivileges(models.Model):
    module = models.ForeignKey('UserModules', related_name='module')
    action = models.ForeignKey('UserActions', related_name='action')
    privilege_name = models.CharField( max_length=300)
    privilege_id = models.AutoField(primary_key=True)
    friendly_name = models.CharField(max_length=300,blank=True)
    show_as_link = models.BooleanField(('show_as_link'), default=True,)

    class Meta:
        verbose_name = 'User privilege'
        verbose_name_plural = 'User privileges'
        unique_together = (('module', 'action'),)

    def get_full_name(self):
        # The user is identified by their email address
        return self.privilege_name

    def get_short_name(self):
        # The user is identified by their email address
        return self.privilege_name

    def __unicode__(self):
        return self.privilege_name

