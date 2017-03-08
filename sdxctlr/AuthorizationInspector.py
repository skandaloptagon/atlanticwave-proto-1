# Copyright 2016 - Sean Donovan
# AtlanticWave/SDX Project


import logging
from lib.Singleton import SingletonMixin

from miracle import Acl
import msgpack
import umsgpack
import pickle

class AuthorizationInspectorError(Exception):
    ''' Parent class, can be used as a catch-all for the other errors '''
    pass

class AuthorizationInspectorLoginNotAuthorized(AuthorizationInspectorError):
    ''' Raised when a login is disallowed. '''
    pass

class AuthorizationInspectorRuleNotAuthorized(AuthorizationInspectorError):
    ''' Raised when a rule installation is not authorized. '''
    pass

class AuthorizationInspector(SingletonMixin):
    ''' The AuthorizationInspector is responsible for authorizing actions. 
        Actions include viewing status of the network, viewing rules of the
        network, pushing rules to network, removing own rules from network, and 
        removing any rules from network. Most users will be authorized for a 
        subset of these actions, with only administrators able to remove rules 
        from other participants. In the future, more granularity will be added 
        (i.e., Alice will be able to install rule types X, Y, and Z, while Bob 
        can only install rule type X). The actions will likely evolve 
        significantly.
        Singleton. '''

    def __init__(self):
        self._setup_logger()
        self.acl = Acl()
        self._load_acl()
        pass

    def is_authorized(self, username, action, **kwargs):
        ''' Returns true if user is allowed to take a particular action, false 
            otherwise. If a user is not in the database, raise and error. '''
        #FIXME: Actions need to be defined.
        #FIXME: This will always return true for the time being.
        return True

    def set_user_authorization(self, username, list_of_permitted_actions):
        ''' Adds authorization information for a particular user. Replaces 
            previous authorization record for that particular user. Must only be
            called by the ParticipantManager. '''
        pass
    
    
    def add_user(self, username):
        ''' Adds a user to the ACL. This happens when a user logs into the 
            system for the first time.'''

        # Right now we are treating every individual as a role.
        self.acl.add_role(username)

        # If other users get access to this users rules and other stuff, 
        # then it is important to make them a resource also.
        self.acl.add_resource(username)

        self._save_acl()
        pass

    def _save_acl(self):
        ''' Save the ACL everytime you do anything to prevent losses. '''
        self.logger.info("Saving ACL")
        with open("security/acl.pkl","wb") as f:
            save = self.acl.__getstate__()
            pickle.dump(save,f)

    def _load_acl(self):
        ''' Load the ACL in the initialization if the ACL exists, otherwise 
            continue with an empty ACL. '''
        self.logger.info("Loading ACL")
        try:
            with open("security/acl.pkl","rb") as f:
                save = pickle.load(f)
                self.acl.__setstate__(save)
        except (IOError,EOFError) as e:
            self.logger.warning("ACL File doesn not exist, continuing with empty ACL")
            self._setup_acl()

    def _setup_acl(self):
        self.logger.info('Adding resources to new ACL')
        self.acl.add_resource('login')
        self.acl.add_resource('admin_console')
        self.acl.add_resource('scientist')
        self.acl.add_resource('engineer')
        self._save_acl()

    def _setup_logger(self):
        ''' Internal function for setting up the logger formats. '''
        # reused from https://github.com/sdonovan1985/netassay-ryu/blob/master/base/mcm.py
        formatter = logging.Formatter('%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(formatter)
        logfile = logging.FileHandler('sdxcontroller.log')
        logfile.setLevel(logging.DEBUG)
        logfile.setFormatter(formatter)
        self.logger = logging.getLogger('sdxcontroller.authentication')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console)
        self.logger.addHandler(logfile) 

    
