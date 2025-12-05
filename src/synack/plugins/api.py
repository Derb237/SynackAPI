"""plugins/api.py

Functions to handle interacting with the Synack APIs
"""

import time
import warnings

from .base import Plugin


class Api(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in ['Debug', 'Db']:
            setattr(self, '_'+plugin.lower(), self._registry.get(plugin)(self._state))

    def login(self, method, path, **kwargs):
        """Modify API Request for Login

        Arguments:
        method -- Request method verb
                  (GET, POST, etc.)
        path -- API endpoint path
                Can be an endpoint on platform.synack.com or a full URL
        headers -- Additional headers to be added for only this request
        data -- POST body dictionary
        query -- GET query string dictionary
        """
        if path.startswith('http'):
            base = ''
        else:
            base = f'https://login.{self._state.synack_domain}/api/'
        url = f'{base}{path}'
        res = self.request(method, url, **kwargs)
        return res

    def notifications(self, method, path, **kwargs):
        """Modify API Request for Notifications

        Arguments:
        method -- Request method verb
                  (GET, POST, etc.)
        path -- API endpoint path
                Can be an endpoint on platform.synack.com or a full URL
        headers -- Additional headers to be added for only this request
        data -- POST body dictionary
        query -- GET query string dictionary
        """
        if path.startswith('http'):
            base = ''
        else:
            base = f'https://notifications.{self._state.synack_domain}/api/v2/'
        url = f'{base}{path}'

        if not kwargs.get('headers'):
            kwargs['headers'] = dict()
        auth = "Bearer " + self._state.notifications_token
        kwargs['headers']['Authorization'] = auth

        res = self.request(method, url, **kwargs)
        if res.status_code == 422:
            self._db.notifications_token = ''
        return res

    def request(self, method, path, attempts=0, **kwargs):
        """Send API Request

        Arguments:
        method -- Request method verb
                  (GET, POST, etc.)
        path -- API endpoint path
                Can be an endpoint on platform.synack.com or a full URL
        attempts -- Number of times the request has been attempted
        headers -- Additional headers to be added for only this request
        data -- POST body dictionary
        query -- GET query string dictionary
        """
        if path.startswith('http'):
            base = ''
        else:
            base = f'https://platform.{self._state.synack_domain}/api/'
        url = f'{base}{path}'

        verify = False
        warnings.filterwarnings('ignore')

        proxies = self._state.proxies if self._state.use_proxies else None

        if f'{self._state.synack_domain}/api/' in url:
            headers = {
                'Authorization': f'Bearer {self._state.api_token}',
                'user_id': self._state.user_id
            }
        else:
            headers = dict()
        if kwargs.get('headers'):
            headers.update(kwargs.get('headers', {}))
        query = kwargs.get('query')
        data = kwargs.get('data')

        if method.upper() == 'GET':
            res = self._state.session.get(url,
                                          headers=headers,
                                          proxies=proxies,
                                          params=query,
                                          verify=verify)
        elif method.upper() == 'HEAD':
            res = self._state.session.head(url,
                                           headers=headers,
                                           proxies=proxies,
                                           params=query,
                                           verify=verify)
        elif method.upper() == 'PATCH':
            res = self._state.session.patch(url,
                                            json=data,
                                            headers=headers,
                                            proxies=proxies,
                                            verify=verify)
        elif method.upper() == 'POST':
            if 'urlencoded' in headers.get('Content-Type', ''):
                res = self._state.session.post(url,
                                               data=data,
                                               headers=headers,
                                               proxies=proxies,
                                               verify=verify)
            else:
                res = self._state.session.post(url,
                                               json=data,
                                               headers=headers,
                                               proxies=proxies,
                                               verify=verify)
        elif method.upper() == 'PUT':
            res = self._state.session.put(url,
                                          json=data,
                                          headers=headers,
                                          proxies=proxies,
                                          verify=verify)

        self._debug.log("Network Request",
                        f"{res.status_code} -- {method.upper()} -- {url}" +
                        f"\n\tHeaders: {headers}" +
                        f"\n\tQuery: {query}" +
                        f"\n\tData: {data}" +
                        f"\n\tContent: {res.content}")

        reason_failed = None
        if res.status_code == 400:
            reason_failed = 'Bad request'
        elif res.status_code == 401:
            reason_failed = 'Unauthorized'
        elif res.status_code == 403:
            reason_failed = 'Logged out'
        elif res.status_code == 412:
            reason_failed = 'Mission already claimed'
        elif res.status_code == 423:
            reason_failed = 'Locked'
        elif res.status_code == 429:
            self._debug.log('Too many requests', f'({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                self._debug.log('Pausing', 'Retrying in 30 seconds...')
                time.sleep(30)
                attempts += 1
                return self.request(method, path, attempts, **kwargs)
        elif res.status_code >= 400:
            self._debug.log(f'Request failed', f'({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                self._debug.log('Retrying', f'Attempt #{attempts + 1} after 2 second delay...')
                time.sleep(2)
                attempts += 1
                return self.request(method, path, attempts, **kwargs)

        # Log terminal failures (non-retryable errors)
        if res.status_code in [400, 401, 403, 412, 423]:
            self._debug.log(reason_failed, f'({res.status_code} - {res.reason}) {res.url}')

        return res

    def request_multipart(self, method, path, files, data=None, attempts=0, **kwargs):
        """Send multipart/form-data API Request (for file uploads)

        Arguments:
        method -- Request method verb (typically POST)
        path -- API endpoint path
                Can be an endpoint on platform.synack.com or a full URL
        files -- Dictionary of files to upload, format:
                 {'field_name': ('filename', file_object, 'mime_type')}
                 or {'field_name': file_path_string}
        data -- Additional form fields (dictionary)
        attempts -- Number of times the request has been attempted
        """
        base = '' if path.startswith('http') else f'https://platform.{self._state.synack_domain}/api/'
        url = f'{base}{path}'

        verify = False
        warnings.filterwarnings('ignore')

        proxies = self._state.proxies if self._state.use_proxies else None

        headers = {
            'Authorization': f'Bearer {self._state.api_token}',
            'user_id': self._state.user_id
        }
        # Don't set Content-Type - requests library will set it with boundary
        if kwargs.get('headers'):
            headers.update(kwargs.get('headers', {}))

        if method.upper() == 'POST':
            res = self._state.session.post(url,
                                           files=files,
                                           data=data,
                                           headers=headers,
                                           proxies=proxies,
                                           verify=verify)
        elif method.upper() == 'PUT':
            res = self._state.session.put(url,
                                          files=files,
                                          data=data,
                                          headers=headers,
                                          proxies=proxies,
                                          verify=verify)
        else:
            raise ValueError(f"Unsupported method for multipart: {method}")

        self._debug.log("Network Request (multipart)",
                        f"{res.status_code} -- {method.upper()} -- {url}" +
                        f"\n\tHeaders: {headers}" +
                        f"\n\tData fields: {list(data.keys()) if data else None}" +
                        f"\n\tFile fields: {list(files.keys()) if files else None}")

        if res.status_code == 429:
            self._debug.log('Too many requests', f'({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                self._debug.log('Pausing', 'Retrying in 30 seconds...')
                time.sleep(30)
                attempts += 1
                return self.request_multipart(method, path, files, data, attempts, **kwargs)
        elif res.status_code >= 400:
            self._debug.log('Request failed', f'({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5 and res.status_code not in [400, 401, 403, 412, 423]:
                self._debug.log('Retrying', f'Attempt #{attempts + 1} after 2 second delay...')
                time.sleep(2)
                attempts += 1
                return self.request_multipart(method, path, files, data, attempts, **kwargs)

        return res

    def request_delete(self, path, attempts=0, **kwargs):
        """Send DELETE API Request

        Arguments:
        path -- API endpoint path
                Can be an endpoint on platform.synack.com or a full URL
        attempts -- Number of times the request has been attempted
        """
        base = '' if path.startswith('http') else f'https://platform.{self._state.synack_domain}/api/'
        url = f'{base}{path}'

        verify = False
        warnings.filterwarnings('ignore')

        proxies = self._state.proxies if self._state.use_proxies else None

        headers = {
            'Authorization': f'Bearer {self._state.api_token}',
            'user_id': self._state.user_id
        }
        if kwargs.get('headers'):
            headers.update(kwargs.get('headers', {}))

        res = self._state.session.delete(url,
                                         headers=headers,
                                         proxies=proxies,
                                         verify=verify)

        self._debug.log("Network Request",
                        f"{res.status_code} -- DELETE -- {url}" +
                        f"\n\tHeaders: {headers}")

        if res.status_code == 429:
            self._debug.log('Too many requests', f'({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                self._debug.log('Pausing', 'Retrying in 30 seconds...')
                time.sleep(30)
                attempts += 1
                return self.request_delete(path, attempts, **kwargs)
        elif res.status_code >= 400 and res.status_code not in [204, 400, 401, 403, 404]:
            self._debug.log('Request failed', f'({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                self._debug.log('Retrying', f'Attempt #{attempts + 1} after 2 second delay...')
                time.sleep(2)
                attempts += 1
                return self.request_delete(path, attempts, **kwargs)

        return res
