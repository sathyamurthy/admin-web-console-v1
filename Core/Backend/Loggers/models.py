from django.db import models


from django.core.exceptions import ImproperlyConfigured
from django.db import models
from jsonfield import JSONField
from UserManagement.models import User,AnonymousUser
# Create your models here.


class LogDefinition (models.Model):
    component = models.CharField(max_length=250, blank=False,)
    sub_component = models.CharField(max_length=250, blank=False,)
    action = models.CharField(max_length=250, blank=False,)
    sub_action = models.CharField(max_length=250, blank=False,)
    friendly_name = models.CharField(max_length=250, blank=False,)
    description = models.TextField(max_length=8000, blank=True,default="",)
    enable_log = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Log definition'
        verbose_name_plural = 'Log definitions'

    def get_full_name(self):
        # The user is identified by their email address
        return  self.component+ '[' + self.sub_component + '] > ' + self.action + '[' + self.sub_action+']'

    def get_short_name(self):
        # The user is identified by their email address
        return  self.component+ '[' + self.sub_component + '] > ' + self.sub_action

    def __unicode__(self):
        return  self.component+ '[' + self.sub_component + '] > ' + self.action + '[' + self.sub_action+']'


class Logging(models.Model):
    log_type = models.CharField(max_length=50, blank=False,)
    version = models.CharField(max_length=15, blank=True,)
    size = models.BigIntegerField(default=0)
    data = JSONField(default=None)
    log_entry = models.TextField(blank=False,)
    comments = models.TextField(blank=True,default="",)
    code = models.ForeignKey('LogDefinition', blank=False)
    date = models.DateTimeField(auto_now=True)
    user_id = models.BigIntegerField(default=0)
    name = models.CharField(max_length=30, blank=True,)
    country = models.PositiveIntegerField(default=0)
    process_code = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = 'Logger'
        verbose_name_plural = 'Loggers'

    def get_full_name(self):
        # The user is identified by their email address
        return  self.code.get_short_name()+ ' ['+ str(self.process_code)+'] > '+ (self.name)

    def get_short_name(self):
        # The user is identified by their email address
        return self.code.get_short_name()+ ' ['+ str(self.process_code)+'] > '+ (self.name)

    def __unicode__(self):
        return self.code.get_short_name()+ ' ['+ str(self.process_code)+'] > '+ (self.name)

    def RequestCapture(self,request):
        SAVE_DATA = {}
        SAVE_DATA["post"] = request.POST
        SAVE_DATA["get"] = request.GET
        SAVE_DATA["ip"] = request.META['REMOTE_ADDR']
        SAVE_DATA["method"] = request.META['REQUEST_METHOD']
        SAVE_DATA["cookie"] = request.COOKIES
        SAVE_DATA["q_s"] = request.META['QUERY_STRING'] 
        SAVE_DATA["h_r"] = request.META['HTTP_REFERER']
        SAVE_DATA["u_a"] =request.META['HTTP_USER_AGENT']
        return SAVE_DATA



    def log(self,request=None,log_entry="",User=User or AnonymousUser,log_type="app",comments="",process_code=200):
        version="v1"
        user_id=0,
        name='Anonymous'
        country=-1
        process_code = process_code
        data=self.RequestCapture(request)
        try:
            if User.is_authenticated():
                user_id=User.pk
                name=User.username
                country=User.country.pk
        except:
            pass

        code = None
        try:
            log_component = log_entry.split('/')
            C = LogDefinition.objects.get(component= log_component[1],sub_component=log_component[2],action=log_component[3],sub_action=log_component[4])
            code = C
        except LogDefinition.DoesNotExist:
            log_com = LogDefinition(component= log_component[1],sub_component=log_component[2],action=log_component[3],sub_action=log_component[4])
            log_com.save()
            code = log_com
        
        if code is not None:
            import sys
            #print >> sys.stdout,code.enable_log
            if code.enable_log:
                log = Logging(version=version,log_type=log_type,comments=comments,data=data,code=code,user_id=user_id,name=name,country=country,log_entry=log_entry,process_code=process_code)
                log.save()
    
