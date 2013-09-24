import sys
from django.conf import settings
class DBRouter(object): 
    def db_for_read(self, model, **hints):
        "Point all operations on loggers models to 'logging_database'"
        if model._meta.app_label == 'Loggers':
            return 'logging'
        return 'default'

    def db_for_write(self, model, **hints):
        "Point all operations on loggers models to 'logging_database'"
        if model._meta.app_label == 'Loggers':
            return 'logging'
        return 'default'
    
    def allow_relation(self, obj1, obj2, **hints):
        "Allow any relation if a both models in chinook app"
        if obj1._meta.app_label == 'Loggers' and obj2._meta.app_label == 'Loggers':
            return True
        # Allow if neither is chinook app
        elif 'Loggers' not in [obj1._meta.app_label, obj2._meta.app_label]: 
            return True
        return False
    
    def allow_syncdb(self, db, model):
        #print >> sys.stdout,model._meta.app_label
        if db == 'default':
            if model._meta.app_label in settings.DEFAULT_DB['components']:
                return True
        elif db == 'logging':
            if model._meta.app_label in settings.LOGGING_DB['components']:
                return True
        return True
        """
        if db == 'default' and model._meta.app_label == "Loggers":
            return False # we're not using syncdb on our legacy database
        elif db == 'logging' and not model._meta.app_label == "Loggers":
            return False # we're using syncdb on our legacy database
        elif db == 'logging' and model._meta.app_label == "Loggers":
            return True # we're using syncdb on our legacy database
        else: # but all other models/databases are fine
            return True
        """
