import jwt
import requests
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import TokenExpiredError

class APISecurity:
    def __init__(self, client_id, client_secret, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.oauth = OAuth2Session(client_id, redirect_uri=redirect_uri)
        self.token = None

    def get_auth_url(self):
        authorization_url, state = self.oauth.authorization_url("https://provider.com/oauth/authorize")
        return authorization_url

    def fetch_token(self, authorization_response):
        try:
            self.token = self.oauth.fetch_token("https://provider.com/oauth/token",
                                                authorization_response=authorization_response,
                                                client_secret=self.client_secret)
        except TokenExpiredError:
            return False, "Token expired. Please log in again."
        except Exception as e:
            return False, str(e)
        return True, "Token fetched successfully."

    def verify_jwt(self):
        if not self.token:
            return False, "No token available."
        try:
            payload = jwt.decode(self.token, "YOUR_SECRET_KEY", algorithms=["HS256"])
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, "Signature expired. Please log in again."
        except jwt.InvalidTokenError:
            return False, "Invalid token. Please log in again."

# Example usage:
api_security = APISecurity("YOUR_CLIENT_ID", "YOUR_CLIENT_SECRET", "YOUR_REDIRECT_URI")
auth_url = api_security.get_auth_url()
print(f"Please go to the following URL and authorize the app: {auth_url}")
authorization_response = input("Enter the full callback URL: ")
success, message = api_security.fetch_token(authorization_response)
if not success:
    print(f"Error fetching token: {message}")
else:
    is_valid, message = api_security.verify_jwt()
    print(message)
