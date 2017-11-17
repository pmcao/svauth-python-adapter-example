#!/usr/bin/env python
"""
SVAuth Python Platform
Time-stamp: <2017-11-17 07:20:51 phuong>
"""

import os
import requests
import json

from flask import Flask, request, session, redirect, render_template, make_response
from utils import init_token, validate_user, populate_session, request_userprofile, init_session

CHECK_AUTHCODE_URL = "https://authjs.westus.cloudapp.azure.com:3020/CheckAuthCode?authcode={}"
RELYING_PARTY = "https://svauth-python-adapter.herokuapp.com?py"
START_URL = "https://authjs.westus.cloudapp.azure.com:3020/login/Facebook?token={}&concdst={}"
AUTHORIZED_USERS = ["Phuong Cao"]

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    """
    Show an index page with social login buttons
    """
    init_session()
    resp = make_response(render_template("index.html"))
    return resp


@app.route('/logout', methods=['GET'])
def logout():
    """
    Clear session data
    """
    session.clear()
    return redirect("/")


@app.route('/start', methods=['GET'])
def start():
    """
    Start the login flow by contacting the remote svauth agent
    """
    token = init_token()
    return redirect(START_URL.format(token, RELYING_PARTY))


@app.route('/SVAuth/adapters/py/RemoteCreateNewSession.py', methods=['GET'])
def remote_create_new_session():
    """
    Retrieve an authentication code from public agent
    Request user profile from svauth public agent
    Populate user profile to current session
    """
    resp = request_userprofile(request.args.get("authcode"))
    validate_user(resp)
    populate_session(resp)
    return redirect("/")


if __name__ == '__main__':
    app.debug = True
    app.secret_key = os.urandom(24)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 80)))
