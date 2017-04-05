# Copyright 2016 - Sean Donovan
# Edited by John Skandalakis
# AtlanticWave/SDX Project
# Login based on example code from https://github.com/maxcountryman/flask-login

from lib.Singleton import SingletonMixin
from shared.L2TunnelPolicy import L2TunnelPolicy
from shared.EndpointConnectionPolicy import EndpointConnectionPolicy
from shared.SDXControllerConnectionManager import *
from AuthenticationInspector import AuthenticationInspector
from AuthorizationInspector import AuthorizationInspector
from RuleManager import RuleManager
from TopologyManager import TopologyManager
#from RuleRegistry import RuleRegistry

#API Stuff
import flask
from flask import Flask, session, redirect, request, url_for, send_from_directory, render_template, Markup

import flask_login
from flask_login import LoginManager

#from flask_sso import *

#Topology json stuff
import networkx as nx

from networkx.readwrite import json_graph
import json

#multiprocess stuff - This must be a thread, as Process is problematic with 
#syncing is necessary. With multiprocessing.Process, objects are not synched
#after the Process is started. 
from threading import Thread

#stuff to serve sdxctlr/static content - I will change this in an update but for now this is viable.
import SimpleHTTPServer
import SocketServer

#System stuff
import sys, os, traceback

#datetime
from datetime import datetime
import time
from dateutil.parser import parse as pd

#Constants
from shared.constants import *


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

    global User, app, login_manager, shibboleth, unauthorized_handler, page_not_found

    app = Flask(__name__, static_url_path='', static_folder='')

    #FIXME: This should be more secure.
    app.secret_key = 'ChkaChka.....Boo, Ohhh Yeahh!'

    login_manager = LoginManager()

    def api_process(self):
        login_manager.init_app(app)
        app.run(host=self.host, port=self.port)

    def __init__(self,host='0.0.0.0',port=5000, shib=False):
        #FIXME: Creating user only for testing purposes
        AuthenticationInspector.instance().add_user('sdonovan','1234')

        global shibboleth
        shibboleth = shib

        self.host=host
        self.port=port
        
        p = Thread(target=self.api_process)
        p.daemon = True
        p.start()


    def _setup_logger(self):
        ''' Internal fucntion for setting up the logger formats. '''
        # reused from https://github.com/sdonovan1985/netassay-ryu/blob/master/base/mcm.py
        formatter = logging.Formatter('%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
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


    # This builds a shibboleth session
    @staticmethod
    @app.route('/build_session')
    def build_session():
        login_session = request.args.get('login_session')
        user = User()
        with open('../../login_sessions/'+login_session,'r') as session:
            user.id = session.read()
             
        if request.args.get('remote_user').strip()!=user.id.strip():
            return "Invalid Login"
   
        # TODO: Check to make sure the token isn't old.
        #       I may do this through authentication manager 
        #       and include in every function.
        '''
        import time
        timestamp = int(time.time())
        print int(login_session.split('.')[0]),timestamp
        '''

        UserManager.instance().add_user(user)

        flask_login.login_user(user)
        return flask.redirect(flask.url_for('home'))


    # This maintains the state of a logged in user.
    @staticmethod
    @login_manager.user_loader
    def user_loader(email):
        user = User()
        user.id = email
        return user


    # Preset the login form to the user and request to log user in
    #@staticmethod
    @app.route('/', methods=['GET'])
    def home():
        if flask_login.current_user.get_id() == None:

            return flask.render_template('index.html', current_user="Sign in", logged_out=True, home=True, shibboleth=shibboleth)
        else: 
            # Get the Topo for dynamic list gen
            G = TopologyManager.instance().get_topology()            

            switches=[]
            dtns=[]

            # Creating all of the HTML Tags for drop down lists
            for node_id in G.nodes():
                node = G.node[node_id]
                if "friendlyname" in node and "type" in node:
                    fname = node["friendlyname"]
                    if node["type"]=="dtn":
                        dtns.append((node_id,fname))
                        dtns.append(Markup('<option value="{}">{}</option>'.format(node_id,fname)))
                    if node["type"]=="switch":
                        switches.append((node_id,fname))
               
            # Pass to flask to render a template
            return flask.render_template('index.html', home=True, switches=switches, dtns=dtns)
    
    # Preset the login form to the user and request to log user in
    @staticmethod
    @app.route('/login', methods=['POST','GET'])
    def login(): 
        email = flask.request.form['email']
        #if flask.request.form['pw'] == users[email]['pw']:
        if AuthenticationInspector.instance().is_authenticated(email,flask.request.form['pw']):
            user = User()
            user.id = email
            flask_login.login_user(user)
            return flask.redirect(flask.url_for('home'))

        return 'Bad login'
    # Present the admin console to authorized admins
    @staticmethod
    @app.route('/settings/authorization')
    def admin_console():
        users = AuthorizationInspector.instance().list_users()
        return flask.render_template('admin_settings.html', home=False, shibboleth=shibboleth, user_list=users)

    # This is a worthless function. The redirect will eventually take you somewhere else.
    @staticmethod
    @app.route('/protected')
    @flask_login.login_required
    def protected():
        if AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'login'):
            return 'Logged in as: ' + flask_login.current_user.id
        return unauthorized_handler()

    # Log out of the system
    @staticmethod
    @app.route('/logout')
    def logout():
        flask_login.logout_user()
        return flask.redirect(flask.url_for('home')+'?n='+str(time.time()))

    @login_manager.unauthorized_handler
    def unauthorized():
        # do stuff
        return flask.render_template('404.html')

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    # Access information about a user
    @staticmethod
    @app.route('/user/<username>')
    def show_user_information(username):
        if AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'get_user_info'):
            return "Test: %s"%username
        return unauthorized_handler()

    # Return the network topology in json format
    @staticmethod
    @app.route('/topology.json')
    def show_network_topology_json():
        if AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'show_topology'):
            G = TopologyManager.instance().get_topology()
            data = json_graph.node_link_data(G)
            return json.dumps(data)
        return unauthorized_handler()

    # Return the network topology in json format
    @staticmethod
    @app.route('/topology_node.json')
    def show_network_topology_node_json():
        if True or AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'show_topology'):
            G = TopologyManager.instance().get_topology()

            height = 300
            width = 960

            links = []
            for edge in G.edges(data=True):
                links.append({"source":edge[0], "target":edge[1], "value":edge[2]["weight"]})

            nodes = []
            for node in G.nodes(data=True):
                xy = node[1]['location'].split(',')
                nodes.append({"id":node[0], "group":node[1]['type'],"friendlyname":node[1]["friendlyname"],
                            "lx":str(height*(-1*(float(xy[0])-90)/180)),
                            "ly":str(width*(float(xy[1])+180)/360)})
                try:
                    nodes[-1]["ip"]=node[1]["ip"]
                except KeyError:
                    pass 
                try:
                    nodes[-1]["lcip"]=node[1]["lcip"]
                except KeyError:
                    pass
                try:
                    nodes[-1]["vlan"]=node[1]["vlan"]
                except KeyError:
                    pass

            json_data = {"nodes":nodes, "links":links}
            
            return json.dumps(json_data)
        return unauthorized_handler()

    # Return the network topology in json format
    @staticmethod
    @app.route('/topology')
    def show_network_topology():
        if True or AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'show_topology'):
            return flask.render_template('topology.html')
        return unauthorized_handler()

    @staticmethod
    @app.route('/batch_rule', methods=['POST'])
    def make_many_pipes():
        data = request.json
        hashes = []
        for rule in data['rules']: 
            policy = L2TunnelPolicy(flask_login.current_user.id, rule)
            hashes.append(RuleManager.instance().add_rule(policy))
            
        return '<pre>%s</pre><p>%s</p>'%(json.dumps(data, indent=2),str(hashes))
            
    @staticmethod
    @app.route('/rule',methods=['POST'])
    def make_new_pipe():
        theID = "curlUser"
        try:
            if AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'show_topology'):
                theID = flask_login.current_user.id
            else:
                theID = "curlUser"
        except:
            pass

        #TODO: YUUUGGGGGEEEE security hole here. Patch after demo.
        policy = None
        try:

            # Just making sure the datetimes are okay
            starttime = datetime.strptime(str(pd(request.form['startdate'] + ' ' + request.form['starttime'])), '%Y-%m-%d %H:%M:%S')
            endtime = datetime.strptime(str(pd(request.form['enddate'] + ' ' + request.form['endtime'])), '%Y-%m-%d %H:%M:%S')
    
            # The Object to pass into L2TunnelPolicy
            data = {"l2tunnel":{"starttime":str(starttime.strftime(rfc3339format)),
                                            "endtime":str(endtime.strftime(rfc3339format)),
                                            "srcswitch":request.form['source'],
                                            "dstswitch":request.form['dest'],
                                            "srcport":request.form['sp'],
                                            "dstport":request.form['dp'],
                                            "srcvlan":request.form['sv'],
                                            "dstvlan":request.form['dv'],
                                            "bandwidth":request.form['bw']}}
            
            policy = L2TunnelPolicy(theID, data)
            rule_hash = RuleManager.instance().add_rule(policy)
        except:
            data =  {"endpointconnection":{
            "deadline":request.form['deadline']+':00',
            "srcendpoint":request.form['source'],
            "dstendpoint":request.form['dest'],
            "dataquantity":int(request.form['size'])*int(request.form['unit'])}}
            policy = EndpointConnectionPolicy(theID, data)
            rule_hash = RuleManager.instance().add_rule(policy)

        print rule_hash
        return flask.redirect('/rule/' + str(rule_hash))


    # Get information about a specific rule IDed by hash.
    @staticmethod
    @app.route('/rule/<rule_hash>',methods=['GET','POST'])
    def get_rule_details_by_hash(rule_hash):
        if AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'access_rule_by_hash'):

            # Shows info for rule
            if request.method == 'GET':
                try:
                    detail=RuleManager.instance().get_rule_details(rule_hash)
                    print detail
                    return  flask.render_template('details.html', detail=detail)
                except Exception as e:
                    print e
                    return "Invalid rule hash"

            # Deletes Rules : POST because HTML does not support DELETE Requests
            if request.method == 'POST':
                RuleManager.instance().remove_rule(rule_hash, flask_login.current_user.id)
                return flask.redirect(flask.url_for('get_rules'))

            # Handles other HTTP request methods
            else:
                return "Invalid HTTP request for rule manager"
        return page_not_found(e)


    # Get a list of rules that match certain filters or a query.
    @staticmethod
    @app.route('/rule/all/', methods=['GET','POST'])
    #TODO: Make this decorator work
    #@login_required
    def get_rules():
        print flask_login.current_user.is_authenticated
        if flask_login.current_user.is_authenticated and AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'search_rules'):
            #TODO: Throws exception currently    
            if request.method == 'POST':
                RuleManager.instance().remove_all_rules(flask_login.current_user.id)
            return flask.render_template('rules.html', rules=RuleManager.instance().get_rules())
        return ""

 
    # Get a list of rules that match certain filters or a query.
    @staticmethod
    @app.route('/rule/search/<query>')
    def get_rule_search_by_query(query):
        if AuthorizationInspector.instance().is_authorized(flask_login.current_user.id,'search_rules'):

            # TODO: Parse query into filters and ordering
            return str(RuleManager.instance().get_rules(filter={query},ordering=query))
        return page_not_found()


if __name__ == "__main__":
    def blah(param):
        pass

    sdx_cm = SDXControllerConnectionManager()
    import dataset    
    db = dataset.connect('sqlite:///:memory:', engine_kwargs={'connect_args':{'check_same_thread':False}})

    rm = RuleManager.instance(db, blah, blah)

    RestAPI()

    raw_input('Press <ENTER> to quit at any time...\n')
