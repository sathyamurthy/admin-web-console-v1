from tastypie.authentication import Authentication
from tastypie.authorization import Authorization
from UserManagement import get_user
class CheckForAuthentication(Authentication):
    def is_authenticated(self, request, **kwargs):
        user = get_user(request)
        if user.is_active:
          return True
        return False

    # Optional but recommended
    def get_identifier(self, request):
        user = get_user(request)
        return user.username

class CheckForAuthorization(Authorization):
    def is_authorized(self, request,perm):
        user = get_user(request)
        permission_set = user.get_all_permissions()
        if "%s" % (perm) in permission_set:
            return True
        else:
            return False
    def is_authorized_collection(self, request=None,permission=[],must_all=False,atleast_one=False):
        user = get_user(request)
        permission_set = user.get_all_permissions()
        avl_perm = 0
        all_perm = 0
        if must_all:
            atleast_one = False
        if atleast_one:
            must_all = False
        one_perm_avilable = False
        for perm in permission:
            all_perm=all_perm+1
            if "%s" % (perm) in permission_set:
                avl_perm=avl_perm+1
                one_perm_avilable = True
                if atleast_one:
                    return one_perm_avilable
        #import sys
        #print >> sys.stdout,all_perm
        #print >> sys.stdout,avl_perm
        if must_all:
            return avl_perm ==  all_perm
        else:
            return one_perm_avilable
        #return False

    # Optional but useful for advanced limiting, such as per user.
    def apply_limits(self, request, object_list):
        if request and hasattr(request, 'user'):
            return object_list.filter(author__username=request.user.username)

        return object_list.none()
