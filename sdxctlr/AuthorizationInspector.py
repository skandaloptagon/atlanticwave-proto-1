# Copyright 2016 - Sean Donovan
# AtlanticWave/SDX Project
# Edited by John Skandalakis

import logging
from lib.Singleton import SingletonMixin

from miracle import Acl

# normally I am opposed to pickle, but for this specific situation it is okay. 
# Change to msgpack if transfering the acl across systems.
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

    def __init__(self, db):
        self._setup_logger()

        self.acl_store = db['acl']

        self.acl = Acl()
        self._load_acl()
        pass

    def is_role_authorized(self, role, resource, permission):
        ''' Returns true if a role is allowed to take a particular action, false 
            otherwise. If a role is not in the database, raise an error. '''
        self.logger.info("check:{};{};{}".format(role, resource, resource))
        return self.acl.check(role, resource, permission)

    def is_user_authorized(self, roles, resource, permission):
        ''' Returns true if user is allowed to take a particular action, false 
            otherwise. If a user is not in the database, raise an error. '''
        self.logger.info("check:{};{};{}".format(','.join(roles), resource, resource))
        for role in roles:
            if self.acl.check(role, resource, permission):
                return True

        return False

    def set_authorization(self, role, resource, permission):
        ''' Adds authorization information for a particular user or role. Replaces 
            previous authorization record for that particular user. '''
        self.logger.info("grant:{};{};{}".format(role, resource, resource))
        self.acl.grant(role,resource,permission)
        self._save_acl()

    def revoke_authorization(self, role, resource, permission):
        ''' Revokes authorization information for a particular user or role. '''
        self.logger.info("revoke:{};{};{}".format(role, resource, resource))
        self.acl.revoke(role,resource,permission)
        self._save_acl()

    def get_roles(self):
        return self.acl.get_roles()

    def add_role(self, role):
        ''' Adds a role to miracle ACL. This will be called when ungrouped users
            are added to the system and when the admin decided to create group '''

        self.logger.info("Adding Role " + role)
        self.acl.add_role(role)
        self._save_acl()
        pass

    def add_resource(self, resource, list_of_permissions):
        self.logger.info("Add Resource:{};{}".format(resource, ','.join(list_of_permissions)))
        self.acl.add_resource(resource)

        for permission in list_of_permissions:
            self.acl.add_permission(resource,permission)

        pass

    def get_resource_table(self):
        ''' gets a dictionary of the resources with permissions inside '''
        self.logger.info("Getting resource table")

        resources = {}

        for resource in self.acl.get_resources():
            resources[resource]=self.acl.get_permissions(resource)

        return resources

    def show(self):
        self.logger.info("Show")
        return self.acl.show()

    def _save_acl(self):
        ''' Save the ACL everytime you do anything to prevent losses. '''
        self.logger.info("Saving ACL")
        
        save = self.acl.__getstate__()
        save = pickle.dumps(save)

        if len(self.acl_store) == 0:
            self.acl_store.insert(dict(name="ACL",acl=save))
        else:
            self.acl_store.update(dict(name="ACL",acl=save),['name'])

        # This is code for saving the ACL to a file
        '''
        with open("security/acl.pkl","wb") as f:
            save = self.acl.__getstate__()
            pickle.dump(save,f)
        '''


    def _load_acl(self):
        ''' Load the ACL in the initialization if the ACL exists, otherwise 
            continue with an empty ACL. '''
        self.logger.info("Loading ACL")

        if len(self.acl_store) == 0:
            self.logger.info("No ACL Exists. Starting with new ACL")
            self._setup_acl()
        elif len(self.acl_store) > 1:
            self.logger.warn("Multiple ACLs Stored")
        else:
            temp_acl=self.acl_store.find_one(name="ACL")
            save=pickle.loads(temp_acl['acl'])
            self.acl.__setstate__(save)


        # This is code for loading the ACL from a file
        '''
        try:
            with open("security/acl.pkl","rb") as f:
                save = pickle.load(f)
                self.acl.__setstate__(save)
        except (IOError,EOFError) as e:
            self.logger.warning("ACL File does not exist, continuing with empty ACL")
        '''

    def _setup_acl(self):
        self.logger.info('Adding resources to new ACL')

        #TODO: Add additional resources here

        
        self.acl.add_resource('rules')
        self.acl.add_permission('rules','search')
        self.acl.add_permission('rules','hash')
        self.acl.add_permission('rules','add')
        self.acl.add_permission('rules','delete')
 
        self.acl.add_resource('topo')
        self.acl.add_permission('topo','show')

        self.acl.add_resource('setting')
        self.acl.add_permission('setting','role')

        self.acl.grant('ADMIN','setting', 'role')
        self.acl.grant('DEFAULT','setting', 'role')
        #TODO:SAVE and LOAD from DB
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

    
