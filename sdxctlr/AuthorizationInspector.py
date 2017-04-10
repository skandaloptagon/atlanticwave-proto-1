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
        self.rule_boundaries = db['rb']

        #Bandwidth limit and html5 form type
        self.valid_btypes = {"BW Limit":"number", "BW Guarantee":"number", "Number of Rules":"number"}

        self.acl = Acl()
        self._load_acl()

        for role in self.get_roles():
            self.touch_boundary(role)

    def get_all_boundaries(self):
        bounds = []
        for bound in self.rule_boundaries.all():
            bounds.append(bound)
        return bounds

    def touch_boundary(self, role):
        ''' this adds a row in the DB for a role. call this whenever a new role is added. '''
        self.logger.info("touch role, {}, for rule boundary".format(role))

        if self.rule_boundaries.find_one(role=role) != None:
            return

        data = dict(role=role)
        for btype in self.valid_btypes:
            data[btype] = 0

        self.rule_boundaries.upsert(data,[role])


    def set_rule_boundary(self, role, btype, value):
        self.logger.info("set:{};{};{}".format(role, btype, value))
        if not btype in self.valid_btypes:
            raise AuthorizationInspectorError()

        value = self._check_btype(btype,value)

        data = self.rule_boundaries.find_one(role=role)
        data[btype] = value
        self.rule_boundaries.update(data,['role'])

    def _check_btype(self, btype, value):
        if not btype in self.valid_btypes:
            raise AuthorizationInspectorError()

        #return value

        if self.valid_btypes[btype] == "number":
            try:
                return int(value)
            except ValueError:
                return 0
        elif self.valid_btypes[btype] == "text":
            return value

    def get_rule_boundary(self, role, btype):
        self.logger.info("get:{};{}".format(role, btype))
        if not btype in self.valid_btypes:
            raise AuthorizationInspectorError() 
        return self.rule_boundaries.find_one(role=role)[btype]


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

        if not role in self.acl.get_roles():
            self.acl.add_role(role)
            self.touch_boundary(role)

            self._save_acl()
        else:
            self.logger.warn("role already exists")
        
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


    def _setup_acl(self):
        self.logger.info('Adding resources to new ACL')

        self.add_role('ADMIN')
        self.add_role('DEFAULT')

        self.acl.add_resource('rules')
        self.acl.add_permission('rules','search')
        self.acl.add_permission('rules','hash')
        self.acl.add_permission('rules','add')
        self.acl.add_permission('rules','delete')
 
        self.acl.add_resource('topo')
        self.acl.add_permission('topo','show')

        self.acl.add_resource('settings')
        self.acl.add_permission('settings','admin')

        self.acl.grant('ADMIN','settings', 'admin')
        self.acl.grant('ADMIN','rules', 'search')
        self.acl.grant('ADMIN','rules', 'hash')
        self.acl.grant('ADMIN','rules', 'add')
        self.acl.grant('ADMIN','rules', 'delete')
        self.acl.grant('ADMIN','topo', 'show')

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

    
