"""plugins/auth.py

Functions related to handling and checking authentication.
"""

import re

from .base import Plugin


class Auth(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in ['Api', 'Db', 'Duo', 'Users']:
            setattr(self,
                    plugin.lower(),
                    self.registry.get(plugin)(self.state))

    def get_api_token(self):
        """Log in to get a new API token."""
        if self.users.get_profile():
            return self.state.api_token
        csrf = self.get_login_csrf()
        progress_token = None
        duo_auth_url = None
        grant_token = None
        if csrf:
            auth_response = self.get_authentication_response(csrf)
            progress_token = auth_response.get('progress_token', '')
            duo_auth_url = auth_response.get('duo_auth_url', '')
        if duo_auth_url:
            grant_token = self.duo.get_grant_token(duo_auth_url)
        if grant_token:
            url = 'https://platform.synack.com/'
            headers = {
                'X-Requested-With': 'XMLHttpRequest'
            }
            query = {
                "grant_token": grant_token
            }
            res = self.api.request('GET',
                                   url + 'token',
                                   headers=headers,
                                   query=query)
            if res.status_code == 200:
                j = res.json()
                self.db.api_token = j.get('access_token')
                self.state.api_token = j.get('access_token')
                self.set_login_script()
                return j.get('access_token')

    def get_login_csrf(self):
        """Get the CSRF Token from the login page"""
        res = self.api.request('GET', 'https://login.synack.com')
        m = re.search('<meta name="csrf-token" content="([^"]*)"',
                      res.text)
        return m.group(1)

    def get_authentication_response(self, csrf):
        """Get progress_token and duo_auth_url from email and password login"""
        headers = {
            'X-CSRF-Token': csrf
        }
        data = {
            'email': self.state.email,
            'password': self.state.password
        }
        res = self.api.login('POST',
                             'authenticate',
                             headers=headers,
                             data=data)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 400:
            csrf = self.get_login_csrf()
            if csrf:
                return self.get_authentication_response(csrf)

    def get_notifications_token(self):
        """Request a new Notifications Token"""
        res = self.api.request('GET', 'users/notifications_token')
        if res.status_code == 200:
            j = res.json()
            self.db.notifications_token = j['token']
            self.state.notifications_token = j['token']
            return j['token']

    def set_login_script(self):
        script = "let forceLogin = () => {" +\
            "const loc = window.location;" +\
            "if(loc.href.startsWith('https://login.synack.com/')) {" +\
            "loc.replace('https://platform.synack.com');" +\
            "}};" +\
            "(function() {" +\
            "sessionStorage.setItem('shared-session-com.synack.accessToken'" +\
            ",'" +\
            self.state.api_token +\
            "');" +\
            "setTimeout(forceLogin,60000);" +\
            "let btn = document.createElement('button');" +\
            "btn.addEventListener('click',forceLogin);" +\
            "btn.style = 'margin-top: 20px;';" +\
            "btn.innerText = 'SynackAPI Log In';" +\
            "btn.classList.add('btn');" +\
            "btn.classList.add('btn-blue');" +\
            "document.getElementsByClassName('onboarding-form')[0]" +\
            ".appendChild(btn)}" +\
            ")();"
        with open(self.state.config_dir / 'login.js', 'w') as fp:
            fp.write(script)

        return script
