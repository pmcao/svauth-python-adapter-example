#!/usr/bin/env python
"""
SVAuth Python Platform
Time-stamp: <2017-11-22 20:58:59 phuong>
"""

import os
import requests
import json

from flask import Flask, request, session, redirect, render_template, make_response

CHECK_AUTHCODE_URL = "https://authjs.westus.cloudapp.azure.com:3020/CheckAuthCode?authcode={}"
RELYING_PARTY = "https://svauth-python-adapter.herokuapp.com?py"
START_URL = "https://authjs.westus.cloudapp.azure.com:3020/login/Facebook?conckey={}&concdst={}"
AUTHORIZED_USERS = ["Phuong Cao"]

import time
import coloredlogs, logging

coloredlogs.install(
    level='DEBUG',
    fmt='%(asctime)s %(name)s[%(funcName)s] %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S%z')

def init_session():
    """
    Init an empty session
    """
    if "UserID" not in session:
        session["UserID"] = ""


def init_token():
    """
    Init a token key used to validate user profile returned from the public agent
    """
    import hashlib
    MAX_TOKEN_LENGTH = 38
    sid_sha256 = hashlib.sha256(
        request.cookies.get('session').encode('utf-8')).hexdigest()
    token = sid_sha256[:MAX_TOKEN_LENGTH]
    session["token"] = sid_sha256[:MAX_TOKEN_LENGTH]
    return token


def validate_user(resp):
    fullname = resp['userProfile']["FullName"]
    logging.info("Validating {} ...".format(fullname))
    if fullname not in AUTHORIZED_USERS:
        raise Exception("unauthorized")

    logging.info("Validating conckey ...")
    if ('conckey' not in resp) or \
       (session["token"] != resp['conckey']):
        raise Exception("invalid token")

    logging.info("Completed validation for {}...".format(fullname))


def populate_user_profile(resp):
    fields = ["UserID", "FullName", "Email", "Authority"]
    for field in fields:
        session[field] = resp['userProfile'][field]


def request_user_profile(authcode):
    return json.loads(
        requests.get(CHECK_AUTHCODE_URL.format(authcode), verify=False).text)


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
    resp = request_user_profile(request.args.get("authcode"))
    validate_user(resp)
    populate_user_profile(resp)
    return redirect("/")


if __name__ == '__main__':
    host = '0.0.0.0'
    port = int(os.environ.get('PORT', 80))
    app.secret_key = os.urandom(24)
    app.run(host=host, port=port)
