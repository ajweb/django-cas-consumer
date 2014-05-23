from urllib import urlencode, urlopen
from urlparse import urljoin

from django.conf import settings

# UNUSABLE_PASSWORD removed for django 1.6, we use set_unusable_password() instead
from misago.models.usermodel import User
from django.contrib.auth.models import User as djangoUser
import random

__all__ = ['CASBackend']

service = settings.CAS_SERVICE
cas_base = settings.CAS_BASE
cas_login = cas_base + settings.CAS_LOGIN_URL
cas_validate = cas_base + settings.CAS_VALIDATE_URL
cas_logout = cas_base + settings.CAS_LOGOUT_URL
cas_next_default = settings.CAS_NEXT_DEFAULT

def _verify_cas1(ticket, service):
    """Verifies CAS 1.0 authentication ticket.

    Returns username on success and None on failure.
    """
    params = settings.CAS_EXTRA_VALIDATION_PARAMS
    params.update({settings.CAS_TICKET_LABEL: ticket, settings.CAS_SERVICE_LABEL: service})
    url = cas_validate + '?'
    if settings.CAS_URLENCODE_PARAMS:
        url += urlencode(params)
    else:
        raw_params = ['%s=%s' % (key, value) for key, value in params.items()]
        url += '&'.join(raw_params)
    page = urlopen(url)
    try:
        verified = page.readline().strip()
        if verified == 'yes':
            return page.readline().strip()
        else:
            return None
    finally:
        page.close()

class CASBackend(object):
    """CAS authentication backend"""

    def authenticate(self, ticket, service):
        """Verifies CAS ticket and gets or creates User object"""

        username = _verify_cas1(ticket, service)
        print "username from _verify_cas1", username
        if not username:    
            return None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                # user will have an "unusable" password (thanks to James Bennett)
                # with django 1.6 we need to call a function
                short_username = username.split('@')[0]
                if len(short_username) > 16: 
                    short_username = short_username[0:16]
                user = User.objects.create_user(short_username, username, djangoUser.objects.make_random_password())
                user.save()
        if settings.CAS_USERINFO_CALLBACK is not None:
            settings.CAS_USERINFO_CALLBACK(user)
        return user

    def get_user(self, user_id):
        """Retrieve the user's entry in the User model if it exists"""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
