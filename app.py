from flask import Flask, redirect, url_for, session, request, render_template_string, render_template, url_for
from flask_session import Session
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
    else:
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
        # Add Facebook login logic here
        pass
    if platform == 'tiktok':
        # Add TikTok login logic here
        pass
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
    


@app.route("/logout")
def logout():
    session.pop("google_id", None)
    session.pop("linkedin_id", None)
    session.pop("microsoft_id", None)
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=PORT, debug=True)
