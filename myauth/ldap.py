import logging

from django.utils import timezone
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django_etebase.utils import CallbackContext
from myauth.models import get_typed_user_model
from rest_framework.permissions import BasePermission

import ldap

User = get_typed_user_model()

def ldap_setting(name, default):
    """Wrapper around django.conf.settings"""
    return getattr(settings, f"LDAP_{name}", default)


class LDAPConnection:
    __instance__ = None
    __user_cache = {}  # Username -> Valid until

    @staticmethod
    def get_instance():
        """To get a Singleton"""
        if not LDAPConnection.__instance__:
            return LDAPConnection()
        else:
            return LDAPConnection.__instance__

    def __init__(self):
        # Cache some settings
        self.__LDAP_FILTER = ldap_setting("FILTER", "")
        self.__LDAP_SEARCH_BASE = ldap_setting("SEARCH_BASE", "")

        self.__ldap_connection = ldap.initialize(ldap_setting("SERVER", ""))
        try:
            self.__ldap_connection.simple_bind_s(ldap_setting("BIND_DN", ""), ldap_setting("BIND_PW", ""))
        except ldap.LDAPError as err:
            logging.error(f"LDAP Error occuring during bind: {err.desc}")

    def __is_cache_valid(self, username):
        """Returns True if the cache entry is still valid. Returns False otherwise."""
        if username in self.__user_cache:
            if timezone.now() <= self.__user_cache[username]:
                # Cache entry is still valid
                return True
        return False

    def __remove_cache(self, username):
        del self.__user_cache[username]

    def has_user(self, username):
        """
        Since we don't care about the password and so authentication
        another way, all we care about is whether the user exists.
        """
        if self.__is_cache_valid(username):
            return True
        if username in self.__user_cache:
            self.__remove_cache(username)

        filterstr = self.__LDAP_FILTER.replace("%s", username)
        try:
            result = self.__ldap_connection.search_s(self.__LDAP_SEARCH_BASE, ldap.SCOPE_SUBTREE, filterstr=filterstr)
        except ldap.NO_RESULTS_RETURNED:
            # We handle the specific error first and the the generic error, as
            # we may expect ldap.NO_RESULTS_RETURNED, but not any other error
            return False
        except ldap.LDAPError as err:
            logging.error(f"Error occured while performing an LDAP query: {err.desc}")
            return False

        if len(result) == 1:
            self.__user_cache[username] = timezone.now() + timezone.timedelta(hours=1)
            return True
        return False


class LDAPUserExists(BasePermission):
    """
    A permission check which first checks with the LDAP directory if the user
    exists.
    """

    def has_permission(self, request, view):
        return LDAPConnection.get_instance().has_user(request.user.username)

def create_user(context: CallbackContext, *args, **kwargs):
    """
    A create_user function which first checks if the user already exists in the
    configured LDAP directory.
    """
    if not LDAPConnection.get_instance().has_user(kwargs["username"]):
        raise PermissionDenied("User not in the LDAP directory.")
    return User.objects.create_user(*args, **kwargs)
