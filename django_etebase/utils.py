from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

from . import app_settings
from .ldap import LDAPConnection


User = get_user_model()


def get_user_queryset(queryset, view):
    custom_func = app_settings.GET_USER_QUERYSET_FUNC
    if custom_func is not None:
        return custom_func(queryset, view)
    return queryset


def create_user(*args, **kwargs):
    # Check if the LDAP query returns exactly one user
    if app_settings.USE_LDAP:
        if not LDAPConnection.get_instance().has_user(kwargs['username']):
            raise PermissionDenied('User is not listed in the LDAP registry.')

    custom_func = app_settings.CREATE_USER_FUNC
    if custom_func is not None:
        return custom_func(*args, **kwargs)
    _ = kwargs.pop('view')
    return User.objects.create_user(*args, **kwargs)


def create_user_blocked(*args, **kwargs):
    raise PermissionDenied('Signup is disabled for this server. Please refer to the README for more information.')
