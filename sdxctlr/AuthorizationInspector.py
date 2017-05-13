# Copyright 2016 - Sean Donovan
# AtlanticWave/SDX Project
# Edited by John Skandalakis

import logging
from lib.Singleton import SingletonMixin
from shared.EndpointConnectionPolicy import EndpointConnectionPolicy
from shared.L2TunnelPolicy import L2TunnelPolicy
from shared.constants import *

from miracle import Acl

from TopologyManager import TopologyManager

import time
from math import ceil
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

    def __init__(self, db, um, rm):
        self._setup_logger()

        self.um = um
        self.rm = rm

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

    def is_authorized(self):
        return

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

    def _user_bw_limit(self, user):
        ''' roles have bw limits. Users have roles. This determines the max bw 
            limit for the set of users. '''
        limit = 0
        for role in self.um.get_user(user)['role']:
            temp_limit = self.get_rule_boundary(role, 'BW Limit')
            if temp_limit > limit:
                limit = temp_limit
        return limit
            

    def _max_bw_for_user(self, user, startdate, enddate):
        ''' Take a username, startdate, and enddate and returns the largest amount 
            of BW during that time period. Use this to check if a user will go over the 
            limit by adding the returned value to the desired value to add. '''
        limit = self._user_bw_limit(user)
        events = []

        #FIXME: Currently, bw is filled using the dataquantity which is not correct. 
        #       This should be done with the actual bandwidth
        for rule in self.rm.get_rules():
            if rule[-2]!=user:
                continue

            bw = None
            end = None
            start = None
            if rule[-3] == 'EndpointConnection':

                data = rule[1]['endpointconnection']['dataquantity']

                # This start time may be incorrect, but it is not contained in EndPointConnectionPolicy.
                start = int(time.time())

                date_time = rule[1]['endpointconnection']['deadline']
                end = int(time.mktime(time.strptime(date_time, rfc3339format)))
                
                
                # Compute the bw for the rule
                bw = int(ceil(max(data/(total_time - EndpointConnectionPolicy.buffer_time_sec),
                                  (data/total_time)*EndpointConnectionPolicy.buffer_bw_percent)))

            elif rule[-3] == 'L2Tunnel':

                date_time = rule[1]['l2tunnel']['starttime']
                start = int(time.mktime(time.strptime(date_time, rfc3339format)))

                date_time = rule[1]['l2tunnel']['endtime']
                end = int(time.mktime(time.strptime(date_time, rfc3339format)))

                bw = rule[1]['l2tunnel']['bandwidth']

            total_time = end - start


            # append these as events for the algorithm below.
            events.append((bw, True, start))
            events.append((bw, False,end))


        # Simple algorithm to compute the max sum. Adds bw at start 
        # of rule time and removes bw at the end of rule time and
        # appends this value to a list at every change. Then it just
        # gets the max from that list.
        time_table = [0]
        current_bw = 0
        for event in sorted(events, key=lambda x:x[2]):
            if event[1]:
                current_bw += event[0]
            else:
                current_bw -= event[0]
            if event[2] > startdate or event[2] < enddate:
                time_table.append(current_bw)
            
        self.logger.debug("Time table: {}".format(time_table))
        return max(time_table)

    def _is_node_authorized(self, user, node):
        ''' checks an individual node for authorization. '''
        #TODO: Discus this with Sean, not sure where to store this.
        return True

    def is_rule_authorized(self, user, rule):
        ''' Take a user row from UserManager and a rule from RuleManager and returns 
            True, or throws an AuthorizationInspectorError with helpful information about 
            the Authorization. Currently Authorizes based on nodes and bandwidth usage. '''

        startdate = None
        enddate = None
        bandwidth = None
        fullpath = None
        
        # Check if the rule is an EndpointConnectionPolicy and set up the parameters
        if isinstance(rule, EndpointConnectionPolicy):
            startdate = int(time.time())
            enddate = int(time.mktime(time.strptime(rule.deadline, rfc3339format)))
            rule.src
            rule.dst
            rule.data

            bandwidth = rule.bandwidth
            rule.intermediate_vlan
            fullpath=rule.fullpath

        # Check if the rule is a L2TunnelPolicy and set up the parameters
        elif isinstance(rule, L2TunnelPolicy):
            startdate = int(time.mktime(time.strptime(rule.start_time, rfc3339format)))
            enddate = int(time.mktime(time.strptime(rule.stop_time, rfc3339format)))

            rule.src_switch
            rule.dst_switch
            rule.src_port
            rule.dst_port
            rule.src_vlan
            rule.dst_vlan
            bandwidth = rule.bandwidth

            rule.intermediate_vlan
            fullpath = rule.fullpath
        else: raise AuthorizationInspectorError("Invalid rule type: " + str(rule))

        # Check the nodes in the path and see if the user is authorized
        blocked_nodes = []
        for node in fullpath:
            if not self._is_node_authorized(self.um.get_user(user)['role'], node):
                blocked_nodes.append(node)
        if len(blocked_nodes) > 0:
            raise AuthorizationInspectorError('You are not authorized to access the following nodes: {}'.format(', '.join(blocked_nodes)))


        # Get the highest bound limit for each role. Not 100% sure if this is how we want to limit users
        rule_limit = 0
        bw_bound = 0
        for role in self.um.get_user(user)['role']:
            tmp_limit = self.get_rule_boundary(role, "Number of Rules")
            if tmp_limit > rule_limit:
                rule_limit = tmp_limit

            role_bw = self.get_rule_boundary(role, "BW Limit")
            if role_bw > bw_bound:
                bw_bound = role_bw

        # TODO: check number of rules
        rule_number = 0
        for rule in self.rm.get_rules():
            print rule[-2]
            if user == rule[-2]:
                rule_number += 1
        print "rule limit", rule_limit, rule_number
        if rule_number >= rule_limit:
            raise AuthorizationInspectorError(''' You have created {} rules, exceding your limit of {}. '''.format(rule_number, rule_limit))


        # Check Boundary Limit for BW
        #TODO:ToCToU Vulnerability.
        current_bw = self._max_bw_for_user(user, startdate, enddate)
        if current_bw + bandwidth > bw_bound:
            raise AuthorizationInspectorError('''You are using a peak of {} bps 
                during this time period and you are requesting {} bps, which will 
                put you over your limit of {} bps'''.format(current_bw, bandwidth, bw_bound))

        return True

    def is_remove_authorized(self, user, rule):
        return True

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
        #TODO: Build everything here from a manifest file.

        self.logger.info('Adding resources to new ACL')

        self.add_role('ADMIN')
        self.add_role('DEFAULT')
        self.add_role('ECPUser')
        self.add_role('L2TUser')
        self.add_role('NOwner')
        self.add_role('NOperator')

        self.acl.add_resource('ECP')
        self.acl.add_permission('ECP','view')
        self.acl.add_permission('ECP','create')
        self.acl.grant('ECPUser','ECP','view')
        self.acl.grant('ECPUser','ECP','create')

        self.acl.add_resource('L2T')
        self.acl.add_permission('L2T','view')
        self.acl.add_permission('L2T','create')
        self.acl.grant('L2TUser','L2T','view')
        self.acl.grant('L2TUser','L2T','create')

        self.acl.add_resource('rules')
        self.acl.add_permission('rules','search')
        self.acl.add_permission('rules','hash')
        self.acl.add_permission('rules','add')
        self.acl.add_permission('rules','delete')
 
        self.acl.add_resource('topo')
        self.acl.add_permission('topo','show')

        self.acl.add_resource('settings')
        self.acl.add_permission('settings','admin')
        self.acl.add_permission('settings','appkey')

        self.acl.grant('ADMIN','settings', 'admin')
        self.acl.grant('ADMIN','rules', 'search')
        self.acl.grant('ADMIN','rules', 'hash')
        self.acl.grant('ADMIN','rules', 'add')
        self.acl.grant('ADMIN','rules', 'delete')
        self.acl.grant('ADMIN','topo', 'show')

        self.acl.grant('DEFAULT','settings','appkey')

        import pprint
        self.acl.add_resource('DTNs')
        self.acl.add_resource('Hosts')
        self.acl.add_resource('Switches')

        self.set_rule_boundary('DEFAULT',"Number of Rules",3)
        self.set_rule_boundary('DEFAULT',"BW Limit",5000000)
        

        pp = pprint.PrettyPrinter(indent=4)
        # Create rules for topology
        topo = TopologyManager.instance().get_topology()
        for node in topo.nodes(data=True):
            print node
            if node[1]['type'] == 'dtn':
                self.acl.add_permission('DTNs',node[0])
            elif node[1]['type'] == 'switch':
                self.acl.add_permission('Switches',node[0])
            elif node[1]['type'] == 'host':
                self.acl.add_permission('Hosts',node[0])

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

    
