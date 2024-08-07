from flask import Flask, redirect, url_for, session, request, render_template_string, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.id_token import verify_oauth2_token
from google.auth.transport import requests
from dotenv import load_dotenv
import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
PORT = 8080
load_dotenv()
app = Flask(__name__)
app.secret_key = os.urandom(24)
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

@app.route("/")
def index():
    user_id = session.get("google_id", None)
    if user_id:
        return render_template_string("""
            <h1>Welcome, Developer!</h1>
            <p>Your Google ID is: {{ user_id }}</p>
            <a href="/logout">Logout</a>
        """, user_id=user_id)
    else:
        return render_template("index.html")


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url(prompt="consent", access_type="offline")
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    
    if not flow.credentials:
        return "No credentials available."
    
    id_info = verify_oauth2_token(flow.credentials.id_token, requests.Request())
    
    if "sub" not in id_info:
        return "Could not retrieve Google ID."
    
    session["google_id"] = id_info["sub"]
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("google_id", None)
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=PORT, debug=False)
