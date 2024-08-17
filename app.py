from flask import Flask, redirect, url_for, session, request, render_template_string, render_template, url_for
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from google_auth_oauthlib.flow import Flow
from google.oauth2.id_token import verify_oauth2_token
from google.auth.transport import requests as google_requests
import requests
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv
import os
import identity.web

import microsoft_config

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
PORT = 8080
load_dotenv()
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  
app.config.from_object(microsoft_config)
Session(app)

app.secret_key = os.urandom(24)

# Google OAuth setup
client_config = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "project_id": os.getenv("GOOGLE_PROJECT_ID"),
        "auth_uri": os.getenv("GOOGLE_AUTH_URI"),
        "token_uri": os.getenv("GOOGLE_TOKEN_URI"),
        "auth_provider_x509_cert_url": os.getenv("GOOGLE_AUTH_PROVIDER"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uris": os.getenv("GOOGLE_REDIRECT_URIS").split(","),
        "javascript_origins": os.getenv("GOOGLE_JAVASCRIPT_ORIGINS").split(",")
    }
}

flow = Flow.from_client_config(
    client_config=client_config,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=os.getenv("GOOGLE_CALLBACK_URL")
)

# LinkedIn OAuth setup
linkedin_client_id = os.getenv("LINKEDIN_CLIENT_ID")
linkedin_client_secret = os.getenv("LINKEDIN_CLIENT_SECRET")
linkedin_redirect_uri = os.getenv("LINKEDIN_REDIRECT_URI")
linkedin_authorization_base_url = "https://www.linkedin.com/oauth/v2/authorization"
linkedin_token_url = "https://www.linkedin.com/oauth/v2/accessToken"
linkedin_user_info_url = "https://api.linkedin.com/v2/userinfo"

# Microsoft OAuth setup
auth = identity.web.Auth(
    session=session,
    authority=app.config["AUTHORITY"],
    client_id=app.config["CLIENT_ID"],
    client_credential=app.config["CLIENT_SECRET"],
)

@app.route("/")
def index():
    google_id = session.get("google_id", None)
    linkedin_id = session.get("linkedin_id", None)
    microsoft_id = session.get("microsoft_id", None)
    twitter_id = session.get("twitter_id", None)
    meta_id = session.get("meta_id", None)
    github_id = session.get("github_id", None)
    gitlab_id = session.get("gitlab_id", None)
    bitbucket_id = session.get("bitbucket_id", None)
    
    if google_id:
        return render_template_string("""
            <h1>Welcome, Developer!</h1>
            <p>Your Google ID is: {{ user_id }}</p>
            <a href="/logout">Logout</a>
        """, user_id=google_id)
    
    if linkedin_id:
        return render_template_string("""
            <h1>Welcome, LinkedIn User!</h1>
            <p>Your LinkedIn ID is: {{ linkedin_id }}</p>
            <a href="/logout">Logout</a>
        """, linkedin_id=linkedin_id)
    
    if microsoft_id:
        return render_template_string("""
            <h1>Welcome, Microsoft User!</h1>
            <p>Your Microsoft ID is: {{ microsoft_id }}</p>
            <a href="/logout">Logout</a>
        """, microsoft_id=microsoft_id)
    
    if twitter_id:
        return render_template_string("""
            <h1>Welcome, Twitter User!</h1>
            <p>Your Twitter ID is: {{ twitter_id }}</p>
            <a href="/logout">Logout</a>
        """, twitter_id=twitter_id)
    
    if meta_id:
        return render_template_string("""
            <h1>Welcome, Facebook User!</h1>
            <p>Your Meta/Facebook ID is: {{ meta_id }}</p>
            <a href="/logout">Logout</a>
        """, meta_id=meta_id)
    
    if github_id:
        return render_template_string("""
            <h1>Welcome, GitHub User!</h1>
            <p>Your GitHub ID is: {{ github_id }}</p>
            <a href="/logout">Logout</a>
        """, github_id=github_id)
    
    if gitlab_id:
        return render_template_string("""
            <h1>Welcome, GitLab User!</h1>
            <p>Your GitLab ID is: {{ gitlab_id }}</p>
            <a href="/logout">Logout</a>
        """, gitlab_id=gitlab_id)
        
    if bitbucket_id:
        return render_template_string("""
            <h1>Welcome, Bitbucket User!</h1>
            <p>Your Bitbucket ID is: {{ bitbucket_id }}</p>
            <a href="/logout">Logout</a>
        """, bitbucket_id=bitbucket_id)
        
    return render_template("index.html")

@app.route("/login")
def login():
    platform = request.args.get("platform")
    if platform == "google":
        authorization_url, state = flow.authorization_url(prompt="consent", access_type="offline")
        session["state"] = state
        return redirect(authorization_url)
    if platform == 'microsoft':
        login_response = auth.log_in(
            scopes=app.config["SCOPE"],
            redirect_uri=url_for("auth_response", _external=True),
            prompt="select_account"
        )
        return redirect(login_response['auth_uri'])
    
    if platform == 'facebook':
        facebook_client_id = os.getenv("FACEBOOK_CLIENT_ID")
        facebook_redirect_uri = url_for("facebook_callback", _external=True)
        facebook_oauth_url = "https://www.facebook.com/v20.0/dialog/oauth"
        facebook_authorization_url = (
            f"{facebook_oauth_url}?client_id={facebook_client_id}&"
            f"redirect_uri={facebook_redirect_uri}&"
            f"state={os.urandom(16).hex()}"
        )
        return redirect(facebook_authorization_url)
        
    if platform == 'github':
        github_client_id = os.getenv("GITHUB_CLIENT_ID")
        github_redirect_uri = url_for("github_callback", _external=True)
        github_authorization_url = (
            "https://github.com/login/oauth/authorize?"
            f"client_id={github_client_id}&"
            f"redirect_uri={github_redirect_uri}&"
            "scope=read:user&"
            f"state={os.urandom(16).hex()}"
        )
        return redirect(github_authorization_url)

    if platform == 'gitlab':
        gitlab_client_id = os.getenv("GITLAB_CLIENT_ID")
        gitlab_redirect_uri = url_for("gitlab_callback", _external=True)
        gitlab_authorization_url = (
            "https://gitlab.com/oauth/authorize?"
            f"client_id={gitlab_client_id}&"
            f"redirect_uri={gitlab_redirect_uri}&"
            "scope=profile&"
            "scope=read_user&"
            "scope=openid&"
            "response_type=code&"
            f"state={os.urandom(16).hex()}"
        )
        return redirect(gitlab_authorization_url)
    
    if platform == 'bitbucket':
        bitbucket_client_id = os.getenv("BITBUCKET_CLIENT_ID")
        bitbucket_redirect_uri = url_for("bitbucket_callback", _external=True)
        bitbucket_authorization_url = (
            "https://bitbucket.org/site/oauth2/authorize?"
            f"client_id={bitbucket_client_id}&"
            f"redirect_uri={bitbucket_redirect_uri}&"
            "scope=account&"
            "response_type=code&"
            f"state={os.urandom(16).hex()}"
        )
        return redirect(bitbucket_authorization_url)
    
    if platform == 'twitter':
        twitter_client_id = os.getenv("TWITTER_CLIENT_ID")
        twitter_redirect_uri = url_for("twitter_callback", _external=True)
        twitter_authorization_url = (
            "https://twitter.com/i/oauth2/authorize?"
            f"response_type=code&client_id={twitter_client_id}&"
            f"redirect_uri={twitter_redirect_uri}&"
            "scope=tweet.read%20users.read%20follows.read%20follows.write&"
            f"state={os.urandom(16).hex()}&"
            "code_challenge=challenge&code_challenge_method=plain"
        )
        return redirect(twitter_authorization_url)

    if platform == 'linkedin':
        linkedin = OAuth2Session(linkedin_client_id, redirect_uri=linkedin_redirect_uri, scope=["openid", "profile", "email"])
        authorization_url, state = linkedin.authorization_url(linkedin_authorization_base_url)
        session["state"] = state
        return redirect(authorization_url)


    return "Invalid platform", 400

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not flow.credentials:
        return "No credentials available."

    id_info = verify_oauth2_token(flow.credentials.id_token, google_requests.Request())

    if "sub" not in id_info:
        return "Could not retrieve Google ID."

    session["google_id"] = id_info["sub"]
    return redirect(url_for("index"))

@app.route("/linkedin/callback")
def linkedin_callback():
    code = request.args.get('code')
    
    # Equivalent to `get_access_token` in Tkinter
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": linkedin_redirect_uri,
        "client_id": linkedin_client_id,
        "client_secret": linkedin_client_secret
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Make the POST request to get the token
    token_response = requests.post(linkedin_token_url, data=token_data, headers=headers)
    print(f"Token response: {token_response.text}")
    
    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"
    
    # Extract the access token
    token = token_response.json().get("access_token")
    
    if not token:
        return "Failed to obtain access token."
    
    # Request user info using the access token
    headers = {'Authorization': f"Bearer {token}"}
    linkedin_info_response = requests.get(linkedin_user_info_url, headers=headers)
    
    print(f"LinkedIn info response: {linkedin_info_response.text}")
    
    if linkedin_info_response.status_code != 200:
        return f"Error fetching LinkedIn user info: {linkedin_info_response.text}"
    
    linkedin_info = linkedin_info_response.json()
    session["linkedin_id"] = linkedin_info.get("sub", "Unknown ID")
    
    return redirect(url_for("index"))

@app.route(microsoft_config.REDIRECT_PATH)
def auth_response():
    print(request.args)
    result = auth.complete_log_in(request.args)
    session["microsoft_id"] = result.get("sub", "Unknown ID")
    return redirect(url_for("index"))
    

@app.route("/twitter/callback")
def twitter_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code:
        return "Error: No authorization code provided."

    twitter_client_id = os.getenv("TWITTER_CLIENT_ID")
    twitter_client_secret = os.getenv("TWITTER_CLIENT_SECRET")
    twitter_redirect_uri = url_for("twitter_callback", _external=True)
    
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": twitter_redirect_uri,
        "client_id": twitter_client_id,
        "code_verifier": "challenge"  # Should be the same as the code challenge method used earlier
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    token_response = requests.post(
        "https://api.twitter.com/2/oauth2/token",
        data=token_data,
        headers=headers,
        auth=(twitter_client_id, twitter_client_secret)
    )
    
    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"

    token = token_response.json().get("access_token")
    
    if not token:
        return "Failed to obtain access token."

    # Use the access token to get user information
    headers = {'Authorization': f"Bearer {token}"}
    user_info_response = requests.get("https://api.twitter.com/2/users/me", headers=headers)
    
    if user_info_response.status_code != 200:
        return f"Error fetching Twitter user info: {user_info_response.text}"
    
    user_info = user_info_response.json()
    print(f"User info: {user_info}")
    session["twitter_id"] = user_info.get("data", {}).get("id")
    
    return redirect(url_for("index"))

@app.route("/facebook/callback")
def facebook_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code:
        return "Error: No authorization code provided."
    
    facebook_client_id = os.getenv("FACEBOOK_CLIENT_ID")
    facebook_client_secret = os.getenv("FACEBOOK_CLIENT_SECRET")
    facebook_redirect_uri = url_for("facebook_callback", _external=True)
    
    token_data = {
        "code": code,
        "redirect_uri": facebook_redirect_uri,
        "client_id": facebook_client_id,
        "client_secret": facebook_client_secret
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    token_response = requests.post(
        "https://graph.facebook.com/v20.0/oauth/access_token",
        data=token_data,
        headers=headers
    )
    
    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"
    
    token = token_response.json().get("access_token")
    
    if not token:
        return "Failed to obtain access token."
    
    user_info_response = requests.get(f"https://graph.facebook.com/v20.0/me?access_token={token}")
    
    if user_info_response.status_code != 200:
        return f"Error fetching Facebook user info: {user_info_response.text}"
    
    user_info = user_info_response.json()
    print(f"User info: {user_info}")
    session["meta_id"] = user_info.get("id")
    
    return redirect(url_for("index"))

@app.route("/github/callback")
def github_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code:
        return "Error: No authorization code provided."
    
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    github_redirect_uri = url_for("github_callback", _external=True)
    
    #ci/cd change
    token_data = {
        "code": code,
        "redirect_uri": github_redirect_uri,
        "client_id": github_client_id,
        "client_secret": github_client_secret
    }
    headers = {
        
        "Accept": "application/json"
    }
    
    token_response = requests.post(
        "https://github.com/login/oauth/access_token",
        data=token_data,
        headers=headers
    )

    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"
    
    token = token_response.json().get("access_token")
    
    if not token:
        return "Failed to obtain access token."
    
    user_info_response = requests.get(f"https://api.github.com/user?access_token={token}",
                                        headers={"Authorization": f"token {token}"})
                                      
    
    if user_info_response.status_code != 200:
        return f"Error fetching GitHub user info: {user_info_response.text}"
    
    user_info = user_info_response.json()
    print(f"User info: {user_info}")
    session["github_id"] = user_info.get("id")
    
    return redirect(url_for("index"))

@app.route("/gitlab/callback")
def gitlab_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code:
        return "Error: No authorization code provided."
    
    gitlab_client_id = os.getenv("GITLAB_CLIENT_ID")
    gitlab_client_secret = os.getenv("GITLAB_CLIENT_SECRET")
    gitlab_redirect_uri = url_for("gitlab_callback", _external=True)
    
    token_data = {
        "code": code,
        "redirect_uri": gitlab_redirect_uri,
        "client_id": gitlab_client_id,
        "client_secret": gitlab_client_secret,
        "grant_type": "authorization_code"
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    print(f"Token data: {token_data}")
    
    token_response = requests.post(
        "https://gitlab.com/oauth/token",
        data=token_data,
        headers=headers
    )
    print(f"Token response: {token_response.text}")
    
    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"
    
    token = token_response.json().get("access_token")
    
    if not token:
        return "Failed to obtain access token."
    
    # user_info_response = requests.get(f"https://gitlab.com/oauth/userinfo?access_token={token}")
    user_info_response = requests.get(f"https://gitlab.com/api/v4/user?access_token={token}")
    print(f"User info response: {user_info_response.text}")
    print(f"User info response status: {user_info_response.status_code}")
    
    
    if user_info_response.status_code != 200:
        return f"Error fetching GitLab user info: {user_info_response.text}"
    
    user_info = user_info_response.json()
    print(f"User info: {user_info}")
    session["gitlab_id"] = user_info.get("id")
    
    return redirect(url_for("index"))

@app.route("/bitbucket/callback")
def bitbucket_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code:
        return "Error: No authorization code provided."
    
    bitbucket_client_id = os.getenv("BITBUCKET_CLIENT_ID")
    bitbucket_client_secret = os.getenv("BITBUCKET_CLIENT_SECRET")
    bitbucket_redirect_uri = url_for("bitbucket_callback", _external=True)
    
    token_data = {
        "code": code,
        "redirect_uri": bitbucket_redirect_uri,
        "client_id": bitbucket_client_id,
        "client_secret": bitbucket_client_secret,
        "grant_type": "authorization_code"
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    token_response = requests.post(
        "https://bitbucket.org/site/oauth2/access_token",
        data=token_data,
        headers=headers
    )
    
    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"
    
    token = token_response.json().get("access_token")
    
    if not token:
        return "Failed to obtain access token."
    
    user_info_response = requests.get(f"https://api.bitbucket.org/2.0/user?access_token={token}")
    
    if user_info_response.status_code != 200:
        return f"Error fetching Bitbucket user info: {user_info_response.text}"
    
    user_info = user_info_response.json()
    print(f"User info: {user_info}")
    session["bitbucket_id"] = user_info.get("uuid").strip("{}")
    
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("google_id", None)
    session.pop("linkedin_id", None)
    session.pop("microsoft_id", None)
    session.pop("twitter_id", None)
    session.pop("meta_id", None)
    session.pop("github_id", None)
    session.pop("gitlab_id", None)
    session.pop("bitbucket_id", None)
    session.clear()
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=PORT, debug=True)
