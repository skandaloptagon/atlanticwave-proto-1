# Copyright 2016 - Sean Donovan
# AtlanticWave/SDX Project

import dataset
import cPickle as pickle
import logging

from lib.Singleton import SingletonMixin
from AuthorizationInspector import AuthorizationInspector

from passlib.hash import pbkdf2_sha256

class UserManager(SingletonMixin):
    
    def __init__(self, database, ungrouped):
        self._setup_logger()

        # Start database/dictionary
        self.db = database
        self.ungrouped = ungrouped
        self.user_table = self.db['users']        # All the find live here.


        # Used for filtering.
        self._valid_table_columns = ['email', 'password', 'role', 'settings']
        
    def add_user(self, user, credentials):
        ''' Adds a user to the system with default rules. If the group policy is 
            activated then the username will also be added as a role in the ACL.
            the user's password is also hashed and added to the database. '''

        self.logger.info("adding user: {}: {}".format(user,','.join(credentials)))

        hash = pbkdf2_sha256.hash(credentials)

        role=set(["DEFAULT_USER"])
        role.add(user)

        AuthorizationInspector.instance().add_role(user)
        AuthorizationInspector.instance().add_resource(user,['setting','show'])

        settings = self._build_default_settings()

        self.user_table.insert(dict(email=user,password=hash, role=pickle.dumps(role), settings=pickle.dumps(settings)))
        pass

    def remove_user(self, user):
        ''' Removes the rule that corresponds to the rule_hash that wa returned 
            either from add_rule() or found with get_rules(). If user does not 
            have removal ability, returns an error. '''
        self.logger.info("removing user: {}".format(user))

        self.user_table.delete(email=user)

    def get_user(self, user):
        self.logger.info("getting user: {}".format(user))
        user = self.user_table.find_one(email=user)
        return self._convert_db_user(user)

    def get_users(self):
        self.logger.info("getting all users") 

        users = []
        for user in self.user_table.all():
            users.append(self._convert_db_user(user))
        return users

    def assign_role(self, username, role):
        '''
        Stores a user's role in the database. A user can have more than one role,
        so role is a set of identifiers. If the role does not exist it will throw 
        an InvalidRoleException from AZI'''

        #TODO: if role exists in Authorization Inspector
        if False:
            #TODO throw exception from AZI
            return

        user = self.get_user(username)
        user['role'].add(role)
        user = self._format_db_entry(user)
        
        self.logger.info("Assigning {} to {}".format(username,role))
        self.user_table.update(user, ['email'])

    def unassign_role(self, username, role):
        '''
        Stores a user's role in the database. A user can have more than one role,
        so role is a set of identifiers. If the role does not exist it will throw 
        an InvalidRoleException from AZI'''

        #TODO: if role does not exist in Authorization Inspector
        if False:
            #TODO throw exception from AZI
            return

        user = self.get_user(username)
        user['role'].remove(role)        
        user = self._format_db_entry(user)

        self.logger.info("Unassigning {} to {}".format(username,role))
        self.user_table.update(user, ['email'])


    def _build_default_settings(self):
        return {"Home Screen":
                    {
                        "Show Topology":True,
                        "Show About":True
                    },
                "Rules":
                    {
                        "Heir":"admin"
                    },
                "Topology":
                    {
                        "Geographical":False
                    }
                }

    def _convert_db_user(self, user):
        temp_user = {}
        temp_user['email']=user['email']
        temp_user['password']=user['password']
        temp_user['role']=pickle.loads(str(user['role']))
        temp_user['settings']=pickle.loads(str(user['settings']))
        return temp_user

    
    def _format_db_entry(self, user):
        temp_user = {}
        temp_user['email']=user['email']
        temp_user['password']=user['password']
        temp_user['role']=pickle.dumps(user['role'])
        temp_user['settings']=pickle.dumps(user['settings'])
        return temp_user
 

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
        self.logger = logging.getLogger('sdxcontroller.localctlrmgr')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console)
        self.logger.addHandler(logfile)
