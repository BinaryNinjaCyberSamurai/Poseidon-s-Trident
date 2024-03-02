import requests

class Auth:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def authenticate(self, username, password):
        try:
            # Assuming your API uses basic authentication
            response = self.session.get(self.base_url, auth=(username, password))
            response.raise_for_status()  # Raise an exception if the request fails

            # Check if the response indicates successful authentication
            if response.status_code == 200:
                return True
            else:
                return False
        except requests.RequestException as e:
            print(f"Error during authentication: {e}")
            return False

if __name__ == "__main__":
    api_base_url = "https://api.example.com"  # Replace with your API base URL
    auth = Auth(api_base_url)
    username = "your_username"
    password = "your_password"

    if auth.authenticate(username, password):
        print("Authentication successful!")
    else:
        print("Authentication failed.")
