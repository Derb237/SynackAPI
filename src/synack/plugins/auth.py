"""plugins/auth.py

Functions related to handling and checking authentication.
"""

import pyotp
import re
import time

from .base import Plugin


class Auth(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in ['Api', 'Db', 'Users']:
            setattr(self,
                    plugin.lower(),
                    self.registry.get(plugin)(self.state))

    def build_otp(self):
        """Generate and return a OTP."""
        totp = pyotp.TOTP(self.state.otp_secret)
        totp.digits = 7
        totp.interval = 10
        totp.issuer = 'synack'
        return totp.now()

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
            progress_token = auth_response.get('progress_token')
            duo_auth_url = auth_response.get('duo_auth_url')
        if duo_auth_url:
            grant_token = self.get_duo_push(duo_auth_url)
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

    def get_duo_push_variables(self, duo_auth_url):
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referrer': 'https://login.synack.com/',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document'
        }
        res = self.api.request('GET', duo_auth_url, include_std_headers=False)
        if res.status_code == 200:
            return {
                'post_data': {
                    'tx': re.search('<input type="hidden" name="tx" value="([^"]*)"', res.text).group(1),
                    'parent': re.search('<input type="hidden" name="parent" value="([^"]*)"', res.text).group(1),
                    '_xsrf': re.search('<input type="hidden" name="_xsrf" value="([^"]*)"', res.text).group(1),
                    'version': re.search('<input type="hidden" name="version" value="([^"]*)"', res.text).group(1),
                    'akey': re.search('<input type="hidden" name="akey" value="([^"]*)"', res.text).group(1),
                    'has_session_trust_analysis_feature': re.search('<input type="hidden" name="has_session_trust_analysis_feature" value="([^"]*)"', res.text).group(1),
                    'session_trust_extension_id': re.search('<input type="hidden" name="session_trust_extension_id" value="([^"]*)"', res.text).group(1),
                    'java_version': re.search('<input type="hidden" name="java_version" value="([^"]*)"', res.text).group(1),
                    'flash_version': re.search('<input type="hidden" name="flash_version" value="([^"]*)"', res.text).group(1),
                    'screen_resolution_width': '3422',
                    'screen_resolution_height': '1465',
                    'extension_instance_key': '',
                    'color_depth': '24',
                    'has_touch_capability': 'false',
                    'ch_ua_error': '',
                    'client_hints': 'eyJicmFuZHMiOlt7ImJyYW5kIjoiQ2hyb21pdW0iLCJ2ZXJzaW9uIjoiMTMxIn0seyJicmFuZCI6Ik5vdF9BIEJyYW5kIiwidmVyc2lvbiI6IjI0In1dLCJmdWxsVmVyc2lvbkxpc3QiOltdLCJtb2JpbGUiOmZhbHNlLCJwbGF0Zm9ybSI6IkxpbnV4IiwicGxhdGZvcm1WZXJzaW9uIjoiIiwidWFGdWxsVmVyc2lvbiI6IiJ9',
                    'is_cef_browser': 'false',
                    'is_ipad_os': 'false',
                    'is_ie_compatibility_mode': '',
                    'is_user_verifying_platform_authenticator_available': 'false',
                    'user_verifying_platform_authenticator_available_error': '',
                    'acting_ie_version': '',
                    'react_support': 'false',
                    'react_support_error_message': ''
                },
                'sid': re.search('sid=([^&]*)', res.url).group(1),
                'url_last': res.url,
                'url_base': re.search('(https.*duosecurity\.com)/', res.url).group(1)
            }

    def get_duo_push_vars_post(self, push_vars):
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': push_vars.get('url_last', ''),
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        res = self.api.request('POST', push_vars.get('url_last', ''), include_std_headers=False, headers=headers, data=push_vars.get('post_data', {}))
        if res.status_code == 200:
            push_vars['url_last'] = res.url
        return push_vars

    def get_duo_push_xsrf_token(self, push_vars):
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': f'{push_vars.get("url_base", "")}/frame/v4/preauth/healthcheck?sid={push_vars.get("sid", "")}',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        }
        res = self.api.request('GET', f'{push_vars.get("url_base", "")}/frame/v4/return', include_std_headers=False, headers=headers, query={"sid": push_vars.get('sid', '')})
        if res.status_code == 200:
            push_vars['xsrf'] = re.search('<input type="hidden" name="_xsrf" value="([^"]*)"', res.text).group(1)
        return push_vars

    def get_duo_push_method_data(self, push_vars):
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': f'{push_vars.get("url_base", "")}/frame/v4/auth/prompt?sid={push_vars.get("sid", "")}',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'X-Xsrftoken': push_vars.get('xsrf', ''),
        }
        query = {
            'post_auth_action': 'OIDC_EXIT',
            'browser_features': '{"touch_supported":false,"platform_authenticator_status":"unavailable","webauthn_supported":true}',
            'sid': push_vars.get('sid', '')
        }
        res = self.api.request('GET', f'{push_vars.get("url_base", "")}/frame/v4/auth/prompt/data', include_std_headers=False, headers=headers, query=query)
        if res.status_code == 200:
            for method in res.json().get('response', {}).get('auth_method_order', []):
                if method.get('factor', '') == 'Duo Push':
                    push_vars['prompt_device_key'] = method.get('deviceKey', '')
                    break

            for phone in res.json().get('response', {}).get('phones', []):
                if phone.get('key', '') == push_vars.get('prompt_device_key', ''):
                    push_vars['prompt_device_index'] = phone.get('index', '')
        return push_vars

    def get_duo_hotp(self):
        hotp = pyotp.HOTP(s=self.state.otp_secret)
        return hotp.generate_otp(self.state.otp_count)

    def get_duo_hotp_txid(self, push_vars):
        # Doing the POST that should actually send the push notification
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': f'{push_vars.get("url_base", "")}/frame/v4/auth/prompt?sid={push_vars.get("sid", "")}',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'X-Xsrftoken': push_vars.get('xsrf', ''),
        }
        data = {
            'device': 'null',
            'passcode': self.get_duo_hotp(),
            'factor': 'Passcode',
            'postAuthDestination': 'OIDC_EXIT',
            'browser_features': '{"touch_supported":false,"platform_authenticator_status":"unavailable","webauthn_supported":true}',
            'sid': push_vars.get('sid', '')
        }
        res = self.api.request('POST', f'{push_vars.get("url_base", "")}/frame/v4/prompt', include_std_headers=False, headers=headers, data=data)
        if res.status_code == 200:
            push_vars['txid'] = res.json().get('response', {}).get('txid', '')
            self.db.otp_count+=1
        return push_vars

    def get_duo_push_notification_txid(self, push_vars):
        # Doing the POST that should actually send the push notification
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': f'{push_vars.get("url_base", "")}/frame/v4/auth/prompt?sid={push_vars.get("sid", "")}',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'X-Xsrftoken': push_vars.get('xsrf', ''),
        }
        data = {
            'device': push_vars.get('prompt_device_index', ''),
            'factor': 'Duo Push',
            'postAuthDestination': 'OIDC_EXIT',
            'browser_features': '{"touch_supported":false,"platform_authenticator_status":"unavailable","webauthn_supported":true}',
            'sid': push_vars.get('sid', '')
        }
        res = self.api.request('POST', f'{push_vars.get("url_base", "")}/frame/v4/prompt', include_std_headers=False, headers=headers, data=data)
        if res.status_code == 200:
            push_vars['txid'] = res.json().get('response', {}).get('txid', '')
        return push_vars

    def get_duo_push_status(self, push_vars):
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': f'{push_vars.get("url_base", "")}/frame/v4/auth/prompt?sid={push_vars.get("sid", "")}',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'X-Xsrftoken': push_vars.get('xsrf', ''),
        }
        data = {
            'txid': push_vars.get('txid', ''),
            'sid': push_vars.get('sid', '')
        }

        for i in range(5):
            res = self.api.request('POST', f'{push_vars.get("url_base", "")}/frame/v4/status', include_std_headers=False, headers=headers, data=data)
            if res.status_code == 200:
                status_enum = res.json().get('response', {}).get('status_enum', -1)
                status = res.json().get('response', {}).get('status', -1)
                if status_enum == 5 or status == 'SUCCESS':     # Valid Code
                    break
                elif status_enum == 11:  # Bad Code (or Future Code by 20+)
                    print("Bad OTP Code Sent")
                    print(res)
                    print(res.json())
                elif status_enum == 44:  # Prior Code
                    self.db.otp_count+=5
                    break
                elif status_enum == -1:  # Code Changed
                    print("Duo OTP Status Code Changed")
                    print(res)
                    print(res.json())
            time.sleep(5)

    def get_duo_push_grant_token(self, push_vars):
        headers = {
            'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Linux"',
            'Referer': f'{push_vars.get("url_base", "")}/frame/v4/auth/prompt?sid={push_vars.get("sid", "")}',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'X-Xsrftoken': push_vars.get('xsrf', ''),
        }
        data = {
            'sid': push_vars.get('sid', ''),
            'txid': push_vars.get('txid', ''),
            'factor': 'Passcode',
            'device_key': 'null',
            #'factor': 'Duo Push',
            #'device_key': push_vars.get('prompt_device_key', ''),
            '_xsrf': push_vars.get('xsrf', ''),
            'dampen_choice': 'false'
        }
        res = self.api.request('POST', f'{push_vars.get("url_base", "")}/frame/v4/oidc/exit', include_std_headers=False, headers=headers, data=data)
        if res.status_code == 200:
            push_vars['grant_token'] = re.search('grant_token=([^&]*)', res.url).group(1)

        return push_vars

    def get_duo_push(self, duo_auth_url):
        """Make Duo send a push notification"""
        push_vars = self.get_duo_push_variables(duo_auth_url)
        self.get_duo_push_vars_post(push_vars)
        push_vars = self.get_duo_push_xsrf_token(push_vars)
        self.get_duo_push_vars_post(push_vars)
        push_vars = self.get_duo_push_method_data(push_vars)
        push_vars = self.get_duo_hotp_txid(push_vars)
        #push_vars = self.get_duo_push_notification_txid(push_vars)
        self.get_duo_push_status(push_vars)
        push_vars = self.get_duo_push_grant_token(push_vars)
        return push_vars.get('grant_token', '')

    def get_login_grant_token(self, csrf, progress_token):
        """Get grant token from authy totp verification"""
        headers = {
            'X-Csrf-Token': csrf
        }
        data = {
            #"authy_token": self.build_otp(),
            "progress_token": progress_token
        }
        res = self.api.login('POST',
                             'authenticate',
                             headers=headers,
                             data=data)
        if res.status_code == 200:
            return res.json().get("grant_token")

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
