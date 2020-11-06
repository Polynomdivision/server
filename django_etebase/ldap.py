import logging

from . import app_settings

import ldap

class LDAPConnection:
    __instance__ = None

    @staticmethod
    def get_instance():
        '''To get a Singleton'''
        if not LDAPConnection.__instance__:
            return LDAPConnection()
        else:
            return LDAPConnection.__instance__

    def __init__(self):
        # Pull settings from django.conf.settings
        # NOTE: We assume that settings.USE_LDAP is True
        self.__ldap_connection = ldap.initialize(app_settings.LDAP_SERVER)
        try:
            self.__ldap_connection.simple_bind_s(app_settings.LDAP_BIND_DN,
                                                 app_settings.LDAP_BIND_PASSWORD)
        except ldap.LDAPError as err:
            logging.error(f'LDAP Error occuring during initialization: {err.desc}')

    def has_user(self, username):
        '''
        Since we don't care about the password and so authentication
        another way, all we care about is whether the user exists.
        '''
        filterstr = app_settings.LDAP_FILTER.replace('%s', username)
        try:
            result = self.__ldap_connection.search_s(app_settings.LDAP_SEARCH_BASE,
                                                     ldap.SCOPE_SUBTREE,
                                                     filterstr=filterstr)
        except ldap.NO_RESULTS_RETURNED:
            # We handle the specific error first and the the generic error, as
            # we may expect ldap.NO_RESULTS_RETURNED, but not any other error
            return False
        except ldap.LDAPError as err:
            logging.error(f'Error occured while performing an LDAP query: {err.desc}')
            return False
        return len(result) == 1
