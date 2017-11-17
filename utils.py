import os
import requests
import json

from flask import Flask, request, session, redirect, render_template, make_response

from .server import AUTHORIZED_USERS, CHECK_AUTHCODE_URL


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
    if session["FullName"] not in AUTHORIZED_USERS:
        raise "unauthorized"

    if ('token' not in resp) or \
       (session["token"] != resp['conckey']):
        raise "invalid token"


def populate_session(resp):
    fields = ["UserID", "FullName", "Email", "Authority"]
    for field in fields:
        session[field] = resp['userProfile'][field]


def request_userprofile(authcode):
    return json.loads(
        requests.get(CHECK_AUTHCODE_URL.format(authcode), verify=False).text)
