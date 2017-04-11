# Copyright 2016 - Sean Donovan
# Edited by John Skandalakis
# AtlanticWave/SDX Project
# Login based on example code from https://github.com/maxcountryman/flask-login

from lib.Singleton import SingletonMixin
from shared.L2TunnelPolicy import L2TunnelPolicy
from shared.EndpointConnectionPolicy import EndpointConnectionPolicy
from shared.SDXControllerConnectionManager import *
from shared.constants import *
from AuthenticationInspector import AuthenticationInspector
from AuthorizationInspector import AuthorizationInspector, AuthorizationInspectorError
from RuleManager import RuleManager
from TopologyManager import TopologyManager
from UserManager import UserManager
# from RuleRegistry import RuleRegistry

# API Stuff
import flask
from flask import Flask, session, redirect, request, url_for, send_from_directory, render_template, Markup

import flask_login
from flask_login import LoginManager

# from flask_sso import *

# Topology json stuff
import networkx as nx

from networkx.readwrite import json_graph
import json

# multiprocess stuff - This must be a thread, as Process is problematic with
# syncing is necessary. With multiprocessing.Process, objects are not synched
# after the Process is started.
from threading import Thread

# stuff to serve sdxctlr/static content - I will change this in an update but for now this is viable.
import SimpleHTTPServer
import SocketServer

# System stuff
import sys, os, traceback

# datetime
from datetime import datetime
import time
from dateutil.parser import parse as pd

# Constants

from flask import make_response
from functools import wraps, update_wrapper
from datetime import datetime


# From: https://arusahni.net/blog/2014/03/flask-nocache.html
def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return update_wrapper(no_cache, view)


class RestAPI(SingletonMixin):
    ''' The REST API will be the main interface for participants to use to push 
        rules (eventually) down to switches. It will gather authentication 
        information from the participant and check with the 
        AuthenticationInspector if the participant is authentic. It will check 
        with the AuthorizationInspector if a particular action is available to a 
        given participant. Once authorized, rules will be pushed to the 
        RuleManager. It will draw some of its API from the RuleRegistry, 
        specifically for the libraries that register with the RuleRegistry. 
        Singleton. '''

    global User, app, login_manager, shibboleth, unauthorized_handler, page_not_found, authorize

    app = Flask(__name__, static_url_path='', static_folder='')

    # TODO: security file
    # FIXME: This should be more secure.
    app.secret_key = 'ChkaChka.....Boo, Ohhh Yeahh!'

    login_manager = LoginManager()

    def api_process(self):
        login_manager.init_app(app)
        app.run(host=self.host, port=self.port)

    def __init__(self, host='0.0.0.0', port=5000, shib=False):
        # FIXME: Creating user only for testing purposes
        self._setup_logger()

        # TODO: Render stuff like this from manifest
        UserManager.instance().add_user('sdonovan', '1234')
        UserManager.instance().add_user('jskandalakis3', '1234')
        # AuthorizationInspector.instance().add_role('ADMIN')
        UserManager.instance().assign_role('sdonovan', 'ADMIN')

        global shibboleth
        shibboleth = shib

        self.host = host
        self.port = port

        p = Thread(target=self.api_process)
        p.daemon = True
        p.start()
        # app.config['SSO_LOGIN_URL'] = 'http://aw.cloud.rnoc.gatech.edu/secure/login2.cgi'
        pass

    def _setup_logger(self):
        ''' Internal fucntion for setting up the logger formats. '''
        # reused from https://github.com/sdonovan1985/netassay-ryu/blob/master/base/mcm.py
        formatter = logging.Formatter('%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        logfile = logging.FileHandler('sdxcontroller.log')
        logfile.setLevel(logging.DEBUG)
        logfile.setFormatter(formatter)
        self.logger = logging.getLogger('sdxcontroller.rest')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(console)
        self.logger.addHandler(logfile)

    class User(flask_login.UserMixin):
        pass

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def page_not_found(e):
        return render_template('500.html', error=e), 500

    # This builds a shibboleth session
    @staticmethod
    @app.route('/build_session')
    def build_session():
        login_session = request.args.get('login_session')
        user = User()
        with open('../../login_sessions/' + login_session, 'r') as session:
            user.id = session.read()

        if request.args.get('remote_user').strip() != user.id.strip():
            return "Invalid Login"

        # TODO: Check to make sure the token isn't old.
        #       I may do this through authentication manager 
        #       and include in every function.
        '''
        import time
        timestamp = int(time.time())
        print int(login_session.split('.')[0]),timestamp
        '''

        AuthorizationInspector.instance().add_user(user)

        flask_login.login_user(user)
        return flask.redirect(flask.url_for('home'))

    @staticmethod
    @login_manager.user_loader
    def user_loader(email):
        ''' This maintains the state of a logged in user. It is a necessary 
            function for flask_login '''
        user = User()
        user.id = email
        return user

    global authorize

    def authorize(resource, permission):
        ''' This decorator takes the resource and the the permission 
            and either continues or presents the user with a not 
            authorized page. '''

        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                user = flask_login.current_user.id
                roles = UserManager.instance().get_user(user)['role']
                if AuthorizationInspector.instance() \
                        .is_user_authorized(roles, resource, permission):
                    app.logger.info('{} authorized for {}:{}' \
                                    .format(user, resource, permission))
                else:
                    raise AuthorizationInspectorError('You are not authorized to access {} > {}'.format(resource,permission) )
                    '''
                    return flask.render_template('not_authorized.html', \
                                                 home=False, resource=resource, \
                                                 permission=permission)'''
                return f(*args, **kwargs)

            return wrapper

        return decorator

    # Preset the login form to the user and request to log user in
    @staticmethod
    @app.route('/', methods=['GET'])
    def home():
        if flask_login.current_user.get_id() == None:

            return flask.render_template('index.html', \
                                         current_user="Sign in", \
                                         logged_out=True, home=True, \
                                         shibboleth=shibboleth)
            '''
            if shibboleth:
                return app.send_static_file('static/index_shibboleth.html')
            return app.send_static_file('static/index.html')
            '''
        else:
            # Get the Topo for dynamic list gen
            G = TopologyManager.instance().get_topology()

            switches = {}
            dtns = {}

            # Creating all of the HTML Tags for drop down lists
            for node_id in G.nodes():
                node = G.node[node_id]
                if "friendlyname" in node and "type" in node:
                    fname = node["friendlyname"]
                    if node["type"] == "dtn":
                        dtns[node_id] = fname
                    if node["type"] == "switch":
                        switches[node_id] = fname

            # Pass to flask to render a template
            return flask.render_template('index.html', \
                                         home=True, switches=switches,
                                         dtns=dtns)

    # Preset the login form to the user and request to log user in
    @staticmethod
    @app.route('/login', methods=['POST', 'GET'])
    def login():
        ''' Renders the login screen and processes a username 
            and password for new users. The login screen must 
            confirm the new user password. '''
        email = flask.request.form['email']
        # if flask.request.form['pw'] == users[email]['pw']:
        if AuthenticationInspector.instance() \
                .is_authenticated(email, flask.request.form['pw']):
            user = User()
            user.id = email
            flask_login.login_user(user)
            return flask.redirect(flask.url_for('home'))

        return 'Bad login'

    # TODO: Make this part of the above function's POST
    @staticmethod
    @app.route("/new_user", methods=['POST', 'GET'])
    def new_user():
        if request.method == 'POST':
            username = flask.request.form['username']
            password = flask.request.form['password']
            return username + password
        else:
            return flask.render_template('new_user.html', home=False)

    # TODO: Combine this with the resource forms endpoint as the POST
    @staticmethod
    @app.route('/settings/authorization', methods=['POST'])
    @authorize('settings', 'admin')
    def grant_authorization():
        role = str(request.form["role"])
        resource = str(request.form["resource"])
        permission = str(request.form["permission"])
        action = str(request.form["action"])
        if action == 'grant':
            AuthorizationInspector.instance() \
                .set_authorization(role, resource, permission)
        elif action == 'revoke':
            AuthorizationInspector.instance() \
                .revoke_authorization(role, resource, permission)
        return '{}'
        return flask.redirect('/settings/resources?role=' + role)

    # TODO: Combine this with the role endpoint as POST
    @staticmethod
    @app.route('/settings/assign_role', methods=['POST'])
    @authorize('settings', 'admin')
    def assign_role():
        user = None
        role = None
        if 'user' in request.form:
            user = request.form["user"]
        elif 'user' in request.args:
            user = request.args["user"]
        else:
            return "bad request"

        if 'role' in request.args:
            role = request.args["role"]
        elif 'role' in request.form:
            role = request.form["role"]
        else:
            return "bad request"

        if 'assign' in request.args or 'assign' in request.form:
            UserManager.instance().assign_role(user, role)
        else:
            UserManager.instance().unassign_role(user, role)

        return "{}"

    @staticmethod
    @app.route('/settings/add_role', methods=['post'])
    @authorize('settings', 'admin')
    def add_role():
        ''' adds a new role to the ACL. New users may have many roles.
            This is not an interface, but it is accessed by the role
            menu interface. '''
        if 'role' in request.form:
            role = request.form["role"]
            AuthorizationInspector.instance().add_role(role)
            return '{}'
        return "bad request"

    @staticmethod
    @app.route('/settings')
    @nocache
    def settings():
        ''' Simply renders the settings menu '''
        roles = AuthorizationInspector.instance().get_roles()
        users = UserManager.instance().get_users()
        return flask.render_template('settings.html', \
                                     home=False, roles=roles, users=users)

    # Present the admin console to authorized admins
    @staticmethod
    @app.route('/settings/resources', methods=['POST', 'GET'])
    @nocache
    @authorize('settings', 'admin')
    def admin_console_user_resources():
        ''' Handles the resource page. The resource page lists all of the
            resources and next to each resource shows a button for
            each permission which toggles the permission on or off. '''
        if request.method == 'POST':
            role = str(request.form["role"])
            resource = str(request.form["resource"])
            permission = str(request.form["permission"])
            action = str(request.form["action"])
            if action == 'grant':
                AuthorizationInspector.instance() \
                    .set_authorization(role, resource, permission)
            elif action == 'revoke':
                AuthorizationInspector.instance(). \
                    revoke_authorization(role, resource, permission)
            return '{}'
        else:
            role = None
            if 'role' in request.args:
                role = request.args['role']
            elif 'role' in request.form:
                role = request.form['role']
            else:
                # TODO: something else
                return "bad request"

            resource_table = AuthorizationInspector \
                .instance().get_resource_table()
            button = {}
            for resource in resource_table:
                button[resource] = {}
                for perm in resource_table[resource]:
                    # TODO: Make these strings into the tags for HTML Buttons.
                    #      Will Need to make and endpoint for Grant and Revoke

                    if AuthorizationInspector.instance() \
                            .is_role_authorized(role, resource, perm):
                        button[resource][perm] = "revoke"
                    else:
                        button[resource][perm] = "grant"

            return flask.render_template('resource_table.html', \
                                         home=False, role=role, \
                                         button=button, \
                                         resources=resource_table)

    @staticmethod
    @app.route('/settings/roles')
    @nocache
    @authorize('settings', 'admin')
    def admin_console_user_roles():

        users = UserManager.instance().get_users()
        roles = AuthorizationInspector.instance().get_roles()

        return flask.render_template('role_table.html', home=False, \
                                     users=users, roles=roles)

    @staticmethod
    @app.route('/settings/users')
    def admin_console():

        if len(request.args) == 0 and len(request.form) == 0:
            show = AuthorizationInspector.instance().show()
            users = UserManager.instance().get_users()
            return flask.render_template('admin_settings.html', home=False, user_list=users, privs=show)

        username = None
        if len(request.args) == 1 and 'user' in request.args:
            username = str(request.args['user'])
        elif len(request.form) == 1 and 'user' in request.form:
            username = request.form['user']
        else:
            return "bad request"

        ''' Hacky way of using a decorator in the middle of a method '''
        @authorize(username, 'setting')
        def Auth():
            pass
        
        auth = Auth()
        if auth!=None:
            return auth

        user = UserManager.instance().get_user(username)

        return flask.render_template('user_settings.html', home=False, user=username, settings=user['settings'])

    @staticmethod
    @app.route('/settings/rules', methods=['GET', 'POST'])
    @authorize('settings', 'admin')
    def admin_console_rules():
        vtypes = AuthorizationInspector.instance().valid_btypes
        if request.method == "POST":
            role = request.form['role']
            for name in request.form:
                if not name == 'role':
                    AuthorizationInspector.instance().set_rule_boundary(role, name, request.form[name])

        rows = AuthorizationInspector.instance().get_all_boundaries()
        return flask.render_template('rule_bounds.html', home=False, vtypes=vtypes, rows=rows)

    # Log out of the system
    @staticmethod
    @app.route('/logout')
    def logout():
        ''' A simple endpoint which alters the state of flask_login.
            flask_login is used to keep track of which user is currently 
            signed in. It does not handle Authentication. This is handled 
            in AuthenticationInspector. '''
        flask_login.logout_user()
        return flask.redirect(flask.url_for('home') + '?n=' + str(time.time()))

    @staticmethod
    @login_manager.unauthorized_handler
    def unauthorized():
        # do stuff
        return flask.render_template('404.html')

    # Access information about a user
    @staticmethod
    @app.route('/user/<username>')
    # TODO: Authorize View user
    def show_user_information(username):
        return "Test: %s" % username

    # Return the network topology in json format
    @staticmethod
    @app.route('/topology.json')
    @authorize('topo', 'show')
    def show_network_topology_json():
        G = TopologyManager.instance().get_topology()
        data = json_graph.node_link_data(G)
        return json.dumps(data)

    # Return the network topology in json format
    @staticmethod
    @app.route('/topology_node.json')
    @authorize('topo', 'show')
    def show_network_topology_node_json():
        G = TopologyManager.instance().get_topology()

        height = 300
        width = 960

        links = []
        for edge in G.edges(data=True):
            links.append({"source": edge[0], \
                          "target": edge[1], \
                          "value": edge[2]["weight"]})

        nodes = []
        for node in G.nodes(data=True):
            xy = node[1]['location'].split(',')
            nodes.append({"id": node[0], \
                          "group": node[1]['type'], \
                          "friendlyname": node[1]["friendlyname"], \
                          "lx": str(height * (-1 * (float(xy[0]) - 90) / 180)), \
                          "ly": str(width * (float(xy[1]) + 180) / 360)})
            try:
                nodes[-1]["ip"] = node[1]["ip"]
            except KeyError:
                pass
            try:
                nodes[-1]["lcip"] = node[1]["lcip"]
            except KeyError:
                pass
            try:
                nodes[-1]["vlan"] = node[1]["vlan"]
            except KeyError:
                pass

        json_data = {"nodes": nodes, "links": links}

        return json.dumps(json_data)

    # Return the network topology in json format
    @staticmethod
    @app.route('/topology')
    @authorize('topo', 'show')
    def show_network_topology():
        return flask.render_template('topology.html')

    @staticmethod
    @app.route('/batch_rule', methods=['POST'])
    # TODO: Write a decorator which checks command line users
    @authorize('rules', 'batch')
    def make_many_pipes():
        data = request.json
        hashes = []
        for rule in data['rules']:
            policy = L2TunnelPolicy(flask_login.current_user.id, rule)
            hashes.append(RuleManager.instance().add_rule(policy))

        return '<pre>%s</pre><p>%s</p>' % (json.dumps(data, indent=2), str(hashes))

    @staticmethod
    @app.route('/rule', methods=['POST'])
    @authorize('rules', 'add')
    def make_new_pipe():
        theID = flask_login.current_user.id

        # TODO: YUUUGGGGGEEEE security hole here. Patch after demo.
        policy = None
        try:

            # Just making sure the datetimes are okay
            starttime = datetime.strptime(str(pd(request.form['startdate'] + ' ' + request.form['starttime'])),
                                          '%Y-%m-%d %H:%M:%S')
            endtime = datetime.strptime(str(pd(request.form['enddate'] + ' ' + request.form['endtime'])),
                                        '%Y-%m-%d %H:%M:%S')

            # The Object to pass into L2TunnelPolicy
            data = {"l2tunnel": {"starttime": str(starttime.strftime(rfc3339format)),
                                 "endtime": str(endtime.strftime(rfc3339format)),
                                 "srcswitch": request.form['source'],
                                 "dstswitch": request.form['dest'],
                                 "srcport": request.form['sp'],
                                 "dstport": request.form['dp'],
                                 "srcvlan": request.form['sv'],
                                 "dstvlan": request.form['dv'],
                                 "bandwidth": request.form['bw']}}

            policy = L2TunnelPolicy(theID, data)
            rule_hash = RuleManager.instance().add_rule(policy)
        except:
            data = {"endpointconnection": {
                "deadline": request.form['deadline'] + ':00',
                "srcendpoint": request.form['source'],
                "dstendpoint": request.form['dest'],
                "dataquantity": int(request.form['size']) * int(request.form['unit'])}}
            policy = EndpointConnectionPolicy(theID, data)

            #FIXME: EndpointConnectionPolicy is not getting set properly so I am doing it here
            policy.bandwidth = data['endpointconnection']['dataquantity']
            rule_hash = RuleManager.instance().add_rule(policy)

        return flask.redirect('/rule/' + str(rule_hash))

    # Get information about a specific rule IDed by hash.
    @staticmethod
    @app.route('/rule/<rule_hash>', methods=['GET', 'POST'])
    @authorize('rules', 'hash')
    def get_rule_details_by_hash(rule_hash):

        # Shows info for rule
        if request.method == 'GET':
            try:
                detail = RuleManager.instance().get_rule_details(rule_hash)
                return flask.render_template('details.html', detail=detail)
            except Exception as e:
                return "Invalid rule hash"

        # Deletes Rules : POST because HTML does not support DELETE Requests
        if request.method == 'POST':
            RuleManager.instance().remove_rule(rule_hash, flask_login.current_user.id)
            return flask.redirect(flask.url_for('get_rules'))

        # Handles other HTTP request methods
        else:
            return "Invalid HTTP request for rule manager"

    # Get a list of rules that match certain filters or a query.
    @staticmethod
    @app.route('/rule/all/', methods=['GET', 'POST'])
    @authorize('rules', 'search')
    def get_rules():
        # TODO: Throws exception currently
        if request.method == 'POST':
            RuleManager.instance().remove_all_rules(flask_login.current_user.id)
        return flask.render_template('rules.html',\
                    rules=RuleManager.instance().get_rules())

    # Get a list of rules that match certain filters or a query.
    @staticmethod
    @app.route('/rule/search/<query>')
    @authorize('rules', 'search')
    def get_rule_search_by_query(query):
        # TODO: Parse query into filters and ordering
        return str(RuleManager.instance().get_rules(filter={query}, ordering=query))


if __name__ == "__main__":
    def blah(param):
        pass


    sdx_cm = SDXControllerConnectionManager()
    import dataset

    db = dataset.connect('sqlite:///:memory:',\
                            engine_kwargs={'connect_args':\
                                               {'check_same_thread': False}})

    rm = RuleManager.instance(db, blah, blah)

    RestAPI()

    raw_input('Press <ENTER> to quit at any time...\n')
