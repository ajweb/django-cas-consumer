from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render_to_response, get_list_or_404
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.core.exceptions import SuspiciousOperation
from django.template import RequestContext
from django.contrib.auth.models import User
from cas_consumer.backends import CASBackend
from django.conf import settings
from importlib import import_module

__all__ = ['login', 'logout',]

service = settings.CAS_SERVICE
cas_base = settings.CAS_BASE
cas_login = cas_base + settings.CAS_LOGIN_URL
cas_validate = cas_base + settings.CAS_VALIDATE_URL
cas_logout = cas_base + settings.CAS_LOGOUT_URL
cas_next_default = settings.CAS_NEXT_DEFAULT
cas_redirect_on_logout = settings.CAS_REDIRECT_ON_LOGOUT

# a function to run after authentication
# TODO we could automate that and run anything we have under a given directory/module
if hasattr(settings, 'CAS_POST_AUTH_CALL'):
    post_auth = import_module(settings.CAS_POST_AUTH_CALL)
else:
    post_auth = None

try:
    from django.contrib.auth import login as auth_login
except:
    auth_login = None

if hasattr(settings, 'CAS_MESSAGES_APP'):
    messages = import_module(settings.CAS_MESSAGES_APP)
else:
    from django.contrib import messages


# to integrate authentication when we cannot use AUTHENTICATION_BACKENDS setting
if hasattr(settings, 'CAS_AUTH_CLASS'):
    auth_class = getattr(import_module(settings.CAS_AUTH_CLASS[0]), settings.CAS_AUTH_CLASS[1])
    auth_method = auth_class().authenticate
else:
    auth_method = getattr(import_module('django.contrib.auth'), 'authenticate') 

if hasattr(settings, 'CAS_LOGOUT_CALLER'):
    logout_caller = getattr(import_module(settings.CAS_LOGOUT_CALLER[0]), settings.CAS_LOGOUT_CALLER[1])
else:
    logout_caller = getattr(import_module('django.contrib.auth'), 'logout')

def login(request):
    """ Fairly standard login view.

        1. Checks request.GET for a service ticket.
        2. If there is NOT a ticket, redirects to the CAS provider's login page.
        3. Otherwise, attempt to authenticate with the backend using the ticket.
        4. If the backend is able to validate the ticket, then the user is logged in and redirected to *CAS_NEXT_DEFAULT*.
        5. Otherwise, the process fails and displays an error message.

    """
    ticket = request.GET.get(settings.CAS_TICKET_LABEL, None)
    next = request.GET.get('next_page', cas_next_default)
    if ticket is None:
        params = settings.CAS_EXTRA_LOGIN_PARAMS
        params.update({settings.CAS_SERVICE_LABEL: service})
        url = cas_login + '?'
        raw_params = ['%s=%s' % (key, value) for key, value in params.items()]
        url += '&'.join(raw_params)
        return HttpResponseRedirect(url)
    user = auth_method(service=service, ticket=ticket)
    if user is not None:
        # standard django login
        if auth_login and (not hasattr(settings, 'CAS_DISABLE_DJANGO_LOGIN') or settings.CAS_DISABLE_DJANGO_LOGIN is False):
            auth_login(request, user)
        # anything we need to run after our auth/login or custom logins
        if post_auth:
            post_auth.run(request, user)
        if hasattr(user, "first_name") and user.first_name:
            name = user.first_name
        else:
            name = user.username
        message ="Login succeeded. Welcome, %s." % name
        messages.add_message(request, messages.INFO, message)
        return HttpResponseRedirect(next)
    else:
        message = "An error has ocurred while authenticating with CAS. Please contact the system administrator."
        if hasattr(settings, 'CAS_REDIRECT_ON_ERROR'):
            messages.add_message(request, messages.INFO, message)
            return HttpResponseRedirect(settings.CAS_REDIRECT_ON_ERROR)
        else:
            return HttpResponseForbidden(message)


def logout(request, next_page=cas_redirect_on_logout):
    """ Logs the current user out. If *CAS_COMPLETELY_LOGOUT* is true, redirect to the provider's logout page,
        which will redirect to ``next_page``.

    """
    logout_caller(request)
    if settings.CAS_COMPLETELY_LOGOUT:
        return HttpResponseRedirect('%s?url=%s' % (cas_logout, next_page))
    return HttpResponseRedirect(cas_redirect_on_logout)
