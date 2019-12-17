#!/usr/bin/env python3
# Ref: https://api.smugmug.com/api/v2/doc/tutorial/oauth/non-web.html
# Ref: https://requests-oauthlib.readthedocs.io/en/latest/oauth1_workflow.html

import configparser
import hashlib
import json
import os
import sys

import requests
from requests_oauthlib import OAuth1Session


def oauth_requests(api_key, api_secret, access_token, token_secret):
    """
    Skip the Out-of-Band PIN if you already have API key+secret and Access token+secret
    Return authenticated OAuth session and user's root node URI.
    1) Register Consumer to recieve API Key and Secret: https://api.smugmug.com/api/developer/apply
        Name: Photobooth, Type: Application|Plug-In|Service|Toy|Other (Service?), Platform: Linux, Use: Non-Commercial
        Account Settings -> Me -> API Keys -> Photobooth (per name used above)
    2) Retrieve Access Token and Secret from Account Settings
        Account Settings -> Privacy -> Authorized Services -> Photobooth [Token] (per name used above)
    """
    session = OAuth1Session(
        api_key,
        client_secret=api_secret,
        resource_owner_key=access_token,
        resource_owner_secret=token_secret
    )
    root_node_uri = get_root_node(session)
    return session, root_node_uri


def oauth_without_token(client_key, client_secret):
    """
    Get access token and secret.
    Use if Access Token and Access Token Secret are unknown. Usually if you didn't make App on your own User account.
    Ref: https://requests-oauthlib.readthedocs.io/en/latest/oauth1_workflow.html
    """
    # Obtain Request Token
    request_token_url = 'https://secure.smugmug.com/services/oauth/1.0a/getRequestToken'
    oauth = OAuth1Session(client_key, client_secret=client_secret)
    fetch_response = oauth.fetch_request_token(request_token_url, params={'oauth_callback': 'oob'}) # out-of-band, because not web app
    resource_owner_key = fetch_response.get('oauth_token')
    resource_owner_secret = fetch_response.get('oauth_token_secret')
    # Obtain Authorization from User
    base_authorization_url = 'https://secure.smugmug.com/services/oauth/1.0a/authorize'
    authorization_url = oauth.authorization_url(base_authorization_url)
    verifier_pin = input(f'URL: {authorization_url}&access=Full&permissions=Modify\nEnter PIN: ') # only good for a few minutes?
    # Obtain Access Token
    access_token_url = 'https://secure.smugmug.com/services/oauth/1.0a/getAccessToken'
    oauth = OAuth1Session(
        client_key,
        client_secret=client_secret,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=verifier_pin
    )
    oauth_tokens = oauth.fetch_access_token(access_token_url)
    resource_owner_key = oauth_tokens.get('oauth_token')
    resource_owner_secret = oauth_tokens.get('oauth_token_secret')
    return resource_owner_key, resource_owner_secret


def get_root_node(session):
    """Return URI of user's root node, given an authenticated session."""
    api_authuser = session.get(f'https://api.smugmug.com/api/v2!authuser', headers={'Accept': 'application/json'}).json()
    root_node_uri = api_authuser['Response']['User']['Uris']['Node']['Uri']
    print(f'[INFO] Got root node: "{root_node_uri}".')
    return root_node_uri


def get_node_children(session, node_uri):
    """Return JSON of all child nodes, given an authenticated session and parent node URI."""
    node_children = session.get(f'https://api.smugmug.com{node_uri}!children', headers={'Accept': 'application/json'}).json()
    """
    print(f"[INFO] Total Children: {node_children['Response']['Pages']['Total']}")  # DEBUG
    for child in node_children['Response']['Node']:
        print('[DEBUG]', json.dumps({
            'Name': child['Name'],
            'Type': child['Type'],
            'SecurityType': child['SecurityType'],
            'HasChildren': child['HasChildren'],
            'Uri': child['Uri'],
            'WebUri': child['WebUri'],
        }, indent=4))
    """
    return node_children


def get_node_else_create(session, parent_node_uri, node_type, node_name, node_password=False):
    """Return specific child node URI of a given parent node URI. Create if it doesn't exist."""
    node_uri = False
    try:
        node_children = get_node_children(session, parent_node_uri)
    except KeyError:    # 'Node' if node has no children
        pass
    else:
        try:
            for child_node in node_children['Response']['Node']:
                if child_node['Name'] == node_name:
                    node_uri = child_node['Uri']
                    print(f'[DEBUG] Node "{node_name}" ({node_type}) exits.')
                    break
        except KeyError:    # 'Node' if node has no children.
            pass
    if not node_uri:
        node_uri = create_node(session, parent_node_uri, node_type, node_name, node_password=node_password)
    print(f'[INFO] Got node "{node_name}" ({node_type}): "{node_uri}".')
    return node_uri


def create_node(session, parent_node_uri, node_type, node_name, node_password=False):
    """
    Return URI of newly created node, given parent node URI, new node type, and new node name.
    Ref: https://api.smugmug.com/api/v2/doc/reference/node.html
    """
    if node_type not in ['Folder', 'Album']:
        print(f'[WARN] Node type "{node_type}" not currently supported.')
        return False
    payload = {
        "Type": node_type,
        "Name": node_name,
        "Privacy": 'Public' # "Unlisted"
    }   # "UrlName": node_name.lower().replace(' ', '_'),    # the underscore may be a protected char
    if node_password:
        payload['SecurityType'] = 'Password'
        payload['Password'] = node_password
    r = session.post(f'https://api.smugmug.com{parent_node_uri}!children', headers={'Accept': 'application/json'}, data=payload)
    if r.status_code == 201:    # Created
        print(f'[INFO] Created {node_type} "{node_name}".')
        return r.json()['Response']['Node']['Uri']
    elif r.status_code == 409:  # Conflict
        print(f'[WARN] Already exists {node_type} "{node_name}".')
        conflicts = []
        for conflict in r.json()['Conflicts'].keys():
            conflicts.append(r.json()['Conflicts'][conflict]['Uri'])
        if len(conflicts) == 1:
            return conflicts[0]
        else:
            print('[DEBUG]', json.dumps(r.json()['Conflicts'], indent=4))
            return False
    elif r.status_code == 400:  # Bad Request
        print(f"[WARN] {r.status_code}: {r.json()['Message']}.")
        for param in r.json()['Options']['Parameters']['POST']:
            if 'Problems' in param.keys():
                print(f"[WARN] Problem with parameter \"{param['Name']}\": \"{param['Problems']}\"")
        return False
    else:
        # 401: 'The user has not granted the required permissions'    # Account Settings -> Privacy -> Authorized Services; needs Full+Modify
        print(f"[WARN] {r.status_code}: {r.json()['Message']}.")
        print('[DEBUG]', json.dumps(r.json(), indent=4))
        return False


def get_album_from_node(session, node_uri):
    """Return Album URI, given authenticated session and Album node URI."""
    node = session.get(f'https://api.smugmug.com{node_uri}', headers={'Accept': 'application/json'}).json()
    return node['Response']['Node']['Uris']['Album']['Uri']


def upload_image(session, album_uri, image_path, image_type='image/jpeg'):
    """Upload image to specified Album URI (NOT Album node URI), given an authenticated session and image file path."""
    # import mimetypes
    # image_type = mimetypes.guess_type(image_path)[0]
    with open(image_path, 'rb') as image:
        image_data = image.read()
    for i in range(2):
        # Retry once. Switching between SmugMug API and Uploader API occasionally causes SmugMug to RST connection.
        try:
            r = session.post(
                'https://upload.smugmug.com/',
                headers={
                    'Accept': b'application/json',
                    'Content-Length': str(len(image_data)),
                    'Content-MD5': hashlib.md5(image_data).hexdigest(),
                    'Content-Type': image_type,
                    'X-Smug-AlbumUri': album_uri,
                    'X-Smug-FileName': os.path.basename(image_path),
                    'X-Smug-ResponseType': 'JSON',
                    'X-Smug-Version': 'v2',
                },
                data=image_data,
            )
        except requests.exceptions.ConnectionError as e:
            r = False
            print(f'[WARN] Upload attempted while offline (attempt {i+1}). "{e}".')
        else:
            break
    if r and r.json()['stat'] == 'ok':
        print(f"[INFO] Upload Success: {r.json()['Image']['URL']}")
    else:
        print(f'[WARN] Upload Failed: "{image_path}"')   # TODO: increase failure handling. Upload error codes aren't great.
    return r


def setup(config_path):
    """Read config file. Return authenticated session and user's root node URI, given app and user's relevant API keys and secrets."""
    # Set up variables using specified config file.
    config = configparser.ConfigParser()
    config.read(config_path)
    ## App info (Account Settings -> Me -> API Keys -> Photobooth)
    api_key = config['SmugMug'].get('api_key')
    api_secret = config['SmugMug'].get('api_secret')
    ## User Info (Account Settings -> Privacy -> Authorized Services -> Photobooth [Full/Modify])
    access_token = config['SmugMug'].get('access_token')
    token_secret = config['SmugMug'].get('token_secret')
    ## Top-Level Folder and Sub-Album details for Upload
    folder_name = config['SmugMug'].get('folder_name')
    album_name = config['SmugMug'].get('album_name')
    album_password = config['SmugMug'].get('album_password')
    # Authenticate session and retrieve user's root node URI.
    if access_token and token_secret:
        # Not retrieving Out-of-Band PIN. Pulling token info right from account and skipping OAuth service step.
        print('[DEBUG] Using existing Token config.')
        smugmug_sess, root_node_uri = oauth_requests(api_key, api_secret, access_token, token_secret)
    else:
        print('[DEBUG] Retrieving OOB PIN and new Token.')
        access_token, token_secret = oauth_without_token(api_key, api_secret)
        print(f'[INFO] Update config file with token key "{access_token}" and secret "{token_secret}".')    # TODO: automate this
        smugmug_sess, root_node_uri = oauth_requests(api_key, api_secret, access_token, token_secret)
    # Check top-level custom folder exists, else create it
    photobooth_node_uri = get_node_else_create(smugmug_sess, root_node_uri, 'Folder', folder_name)
    # Check if custom album in top-level custom folder exists, else create it
    album_node_uri = get_node_else_create(smugmug_sess, photobooth_node_uri, 'Album', album_name, node_password=album_password)
    print(f"[DEBUG] Album URL: {smugmug_sess.get(f'https://api.smugmug.com{album_node_uri}', headers={'Accept': 'application/json'}).json()['Response']['Node']['WebUri']}")
    # Get Album URI in prep for future image uploads
    album_uri = get_album_from_node(smugmug_sess, album_node_uri)
    return smugmug_sess, album_uri


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('[ERROR] Expecting image file path as argument.')
        sys.exit(1)
    # Read config and set up directory and album online
    session, album = setup('default.ini')
    # Upload image to custom album
    upload_resp = upload_image(session, album, sys.argv[1]) # Currently defaults to Content-Type 'image/jpeg'
