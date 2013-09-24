from datetime import datetime
from django.http import HttpResponseRedirect
import sys

class SessionExpiredMiddleware:
    def process_request(self,request):
        now = datetime.now()
        #request.session['last_activity'] = now
        last_activity = now
        try:
            last_activity = request.session['last_activity']
        except:
            pass
        #print >> sys.stdout, last_activity
        #print >> sys.stdout, (now - last_activity).seconds/60
        if (now - last_activity).seconds/60 > 30:
            # Do logout / expire session
            # and then...
            from Core.UserManagement import logout
            from Core.Backend.PrivilegeManagement.sites import get_country_from_url
            logout(request)
            request.session['last_activity'] = now
            return HttpResponseRedirect("/%s/" %get_country_from_url(request.get_full_path()))

        if not request.is_ajax():
            # don't set this for ajax requests or else your
            # expired session checks will keep the session from
            # expiring :)
            request.session['last_activity'] = now


class APIExceptionMiddleware:
    def process_response(self,request, response):
        #print >> sys.stdout,response
        return response
    def process_exception(self,request,exception):
        if "/api/v1" in request.get_full_path():
            print >> sys.stdout, "exception happen"
        
