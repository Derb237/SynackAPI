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
                                          headers=headers,
                                          proxies=proxies,
                                          params=data,
                                          verify=verify)

        self._debug.log("Network Request",
                        f"{res.status_code} -- {method.upper()} -- {url}" +
                        f"\n\tHeaders: {headers}" +
                        f"\n\tQuery: {query}" +
                        f"\n\tData: {data}" +
                        f"\n\tContent: {res.content}")

        if res.status_code in [ 400, 401, 403 ]:
            print('Request failed... Bailing!')
            print(f'\t({res.status_code} - {res.reason}) {res.url}')
        elif res.status_code == 429:
            print('Too many requests! Slow down there, cowpoke!')
            print(f'\t({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                attempts += 1
                print('\tRetrying in 30 seconds...')
                time.sleep(30)
                return self.request(method, path, attempts, **kwargs)
        elif res.status_code >= 400:
            print(f'Request failed...')
            print(f'\t({res.status_code} - {res.reason}) {res.url}')
            if attempts < 5:
                print(f'\tRetry attempt #{attempts + 1}')
                attempts += 1
                return self.request(method, path, attempts, **kwargs)

        return res
