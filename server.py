#!/usr/bin/env python
"""
SVAuth Python Platform
Time-stamp: <2017-11-16 21:42:32 phuong>
"""

import os
import requests
import json

import flask
from flask import Flask, request, session, redirect, render_template, flash, abort, make_response, session

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

MAX_CONCKEY_LENGTH = 38
IDENTITY_PROVIDER = "Facebook"
app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    """
    Show an index page with social login buttons
    """
    if "UserID" in request.form and len(request.form["UserID"]) == 0:
        session.clear()
    resp = make_response(render_template("index.html"))
    resp.set_cookie('LandingUrl',
                    '{}://{}'.format(config['WebAppSettings']['scheme'],
                                     config['WebAppSettings']['hostname']))
    if "UserID" not in session:
        session["UserID"] = ""
    return resp


@app.route('/SVAuth/adapters/py/RemoteCreateNewSession.py', methods=['GET'])
def remote_create_new_session():
    """
    Receive encrypted user profile from svauth remote agent
    Decode the encrypted user profile
    Set user profile to current session
    """
    try:
        url = '{}://{}:{}/CheckAuthCode?authcode={}'.format(
            config['AgentSettings']['scheme'],
            config['AgentSettings']['agentHostname'],
            config['AgentSettings']['port'], request.args.get("authcode"))
        req = requests.get(url, verify=False)
        req_json = json.loads(req.text)
        user_profile = req_json['userProfile']
        if ('conckey' not in req_json) or \
        (session["key"] != req_json['conckey']):
            raise "invalid conckey"
        fields = ["UserID", "FullName", "Email", "Authority"]
        for field in fields:
            session[field] = user_profile[field]
        return redirect("/")
    except:
        return "exception"


@app.route('/start', methods=['GET'])
def start():
    """
    Start the login flow by contacting the remote svauth agent
    """
    import hashlib
    sid_sha256 = hashlib.sha256(
        request.cookies.get('session').encode('utf-8')).hexdigest()
    conckey = sid_sha256[:MAX_CONCKEY_LENGTH]
    url = '{}://{}:{}/login/{}?conckey={}&concdst={}://{}?{}'.format(
        config['AgentSettings']['scheme'],
        config['AgentSettings']['agentHostname'],
        config['AgentSettings']['port'], IDENTITY_PROVIDER, conckey,
        config['WebAppSettings']['scheme'],
        config['WebAppSettings']['hostname'],
        config['WebAppSettings']['platform']['name'])
    session["key"] = sid_sha256[:MAX_CONCKEY_LENGTH]
    return redirect(url)


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect("/")


if __name__ == '__main__':
    global config
    app.debug = True
    app.secret_key = os.urandom(24)
    config_file = "config/adapter_config.json"
    # read adapter config
    with open(config_file, encoding='utf-8') as data_file:
        config = json.loads(data_file.read())
    port = int(os.environ.get('PORT', 80))
    app.run(host='0.0.0.0', port=port)
