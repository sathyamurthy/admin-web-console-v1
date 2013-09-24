# Django settings for catalog project.
import os

RELATIVE_EXTENDED_CONTENT =  "/upload/files/assests/extended/"

EXTENDED_CONTENT_ROOT = os.path.abspath(os.path.dirname(os.path.abspath(__file__))) + RELATIVE_EXTENDED_CONTENT

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    ('sathya','sathya@ec.is')
    # ('Your Name', 'your_email@example.com'),
)
#API_LIMIT_PER_PAGE = 50
MANAGERS = ADMINS
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

GALLERY_ASSETS_VERSION = {
    'images': [{
        'name': 'thumbnail',
        'friendly_name': 'Thumbnail', 
        'path': 'thumbnail',
        'width' : 180
        },
        {
        'name': 'thumbnail', 
        'friendly_name': 'Thumbnail', 
        'path': '256',
        'width' : 256
        },
        {
        'name': '480', 
        'friendly_name': 'Medium', 
        'path': '480',
        'width' : 480
        },                 
        {
        'name': '960', 
        'friendly_name': 'Large', 
        'path': '960',
        'width' : 960
        },                 
        {
        'name': '1024', 
        'friendly_name': 'Extra large', 
        'path': '1024',
        'width' : 1024
        },                 
        {
        'name': '2048', 
        'friendly_name': 'High resolution', 
        'path': '2048',
        'width' : 2048
        }]
}
DATABASE_ROUTERS = ['admin-web-console.Core.Backend.Database.Routing.DBRouter']
DEFAULT_DB = { 'db_name':'default','components': ['Client','UserManagement','Categories','Components','Countries','SiteManagement','Publication','Assets','Uploader','gunicorn']}
LOGGING_DB = { 'db_name':'logging','components':  ['Loggers']}
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'admin_web_console',                      # Or path to database file if using sqlite3.
        # The following settings are not used with sqlite3:
        'USER': 'root',
        'PASSWORD': 'admin123!',
        'HOST': '127.0.0.1',
        
        #'HOST': '192.168.26.231',                      # Empty for localhost through domain sockets or '127.0.0.1' for localhost through TCP.
        'PORT': '3306',                      # Set to empty string for default.
    },
    'logging': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'admin_web_console_log',                      # Or path to database file if using sqlite3.
        # The following settings are not used with sqlite3:
        'USER': 'root',
        'PASSWORD': 'admin123!',
        'HOST': '127.0.0.1',
        
        #'HOST': '192.168.26.231',                      # Empty for localhost through domain sockets or '127.0.0.1' for localhost through TCP.
        'PORT': '3306',                      # Set to empty string for default.
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/Chicago'

ANONYMOUS_USER_ID = -1

LOGIN_URL = '/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_URL = '/'
LOGIN_PROFILE_MODULE = 'Core.UserManagement.User'
# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'
EMAIL_HOST = '127.0.0.1'
EMAIL_PORT = 25
DEFAULT_FROM_EMAIL = "no-reply@ec.is"
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
#EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'

# URL prefix for admin static files -- CSS, JavaScript and images.
# Make sure to use a trailing slash.
# Examples: "http://foo.com/static/admin/", "/static/admin/".
ADMIN_MEDIA_PREFIX = '/static/admin/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    '/opt/admin-web-console/static',
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Make this unique, and don't share it with anybody.
#SECRET_KEY = 'l82laem^n5#$+uk$n_f-7rk5$i_s=!_w7f61ta*i5x-rcg_4wm'
#AUTHENTICATION_BACKENDS = (    'django.contrib.auth.backends.ModelBackend',)
# List of callables that know how to import templates from various sources.

SECRET_KEY = 'l82lsat^n5#$+uk$n_f-7rk5$i_s=!_w7f61ta*i5x-rcg_4wmur'
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
)


USER_AUTHENTICATION_BACKENDS = (
    'Core.UserManagement.backends.ModelBackend',
)
MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'admin-web-console.Core.Backend.SessionManagement.middleware.SessionExpiredMiddleware',
    'admin-web-console.Core.Backend.SessionManagement.middleware.APIExceptionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

ROOT_URLCONF = 'admin-web-console.Core.URL.urls'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    #os.path.join(BASE_DIR,'..', 'tstypie'),
    '/opt/admin-web-console/templates',
)
ALLOWED_HOSTS = [
    '192.168.26.240:8000', # Allow domain and subdomains
    '192.168.26.240', # Also allow FQDN and subdomains
    '192.168.26.196:8000', # Allow domain and subdomains
    '192.168.26.196', # Also allow FQDN and subdomains

]
INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    # Uncomment the next line to enable admin documentation:
    # 'django.contrib.admindocs',
    'admin-web-console',
    'templateaddons',
    'mptt',
    'Core.Countries',
    'Core.Backend.Components',
    'Core.UserManagement',
    'Client.Ikea.Users',
    'Client.Sandvik.Users',
)
AUTH_BACKEND_CLIENT = {
        'ikea' :{
            'SESSION_KEY' : '_ikea_login_user_id',
            'BACKEND_SESSION_KEY' : '_ikea__login_user_backend',
            'REDIRECT_FIELD_NAME' : '_ikea_login_user_next'
        },
        'ec-small-client' :{
            'SESSION_KEY' : '_ec-small-client_login_user_id',
            'BACKEND_SESSION_KEY' : '_ec-small-client_login_user_backend',
            'REDIRECT_FIELD_NAME' : '_ec-small-client_login_user_next'
        },
        'sandvik' :{
            'SESSION_KEY' : '_ec_login_user_id',
            'BACKEND_SESSION_KEY' : '_ec__login_user_backend',
            'REDIRECT_FIELD_NAME' : '_ec_login_user_next'
        },
        'ecadmin' :{
            'SESSION_KEY' : '_ecadmin_login_user_id',
            'BACKEND_SESSION_KEY' : '_ecadmin_login_user_backend',
            'REDIRECT_FIELD_NAME' : '_ecadmin_login_user_next'
        },
    }
# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
    }
}
# Multiple upload files settings
