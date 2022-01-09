try:
    import getpass
    import json
    import os.path
    import requests
except (ModuleNotFoundError, ImportError) as module:
    quit(f'The following module needs to be installed:\n {module}\n Use "pip install $MODULE" then try again.\n')


class Login:
    def __init__(self):
        """Set the variables."""
        self.token = self.username = ''
        self.auth_url = 'https://api.example.com/auth/token'
        self.ping_url = 'https://api.example.com/info/ping'
        self.auth_file = os.getenv('HOME') + '/auth.txt'
        self.token_file = os.getenv('HOME') + '/token.txt'

    def user(self):
        """Checks file for username.  If needed prompts for one and writes it to file."""
        try:
            f = open(self.auth_file, 'r')
            self.username = f.readline().rstrip('\n')
            f.close()
        except FileNotFoundError:
            self.username = input('Username: ')
            f = open(self.auth_file, 'w')
            f.write(self.username)
            f.close()
        finally:
            return self.username

    def token_check(self):
        """Reads from token file.  If it does not exist a blank one is created."""
        try:
            tf = open(self.token_file, 'r')
            self.token = tf.readline().rstrip('\n')
        except FileNotFoundError:
            tf = open(self.token_file, 'w')
        finally:
            tf.close()
            return self.token

    def auth(self, ping_code):
        """Authenticate and write token to file."""
        print(ping_code + '\n Generating new token:')
        password = getpass.getpass()
        req = {'params': {'timeout': '36000'}}
        authreq = requests.post(self.auth_url, auth=(self.username, password), data=json.dumps(req))
        try:
            authres = authreq.json()
        except ValueError:
            quit(f' Password for "{self.username}" is invalid!')
        self.token = authres['token']
        tf = open(self.token_file, 'w')
        tf.write(self.token)
        tf.close()

    def ping(self):
        """Check to see if token is still valid."""
        self.user()
        self.token_check()
        try:
            response = requests.post(self.ping_url, auth=(self.username, self.token))
            code = response.status_code
            if code == 401:
                self.auth(response.text)
        except requests.exceptions.ConnectionError:
            quit(f'Unable to reach {self.ping_url}')
        return self.username, self.token


def main():
    """Gather billing username & token for global variables referenced outside of this file."""
    authenticate = Login()
    return authenticate.ping()


billing_user, billing_token = main()

if __name__ == '__main__':
    main()
