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
            setattr(self, plugin.lower(), self.registry.get(plugin)(self.state))

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
            base = 'https://login.synack.com/api/'
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
            base = 'https://notifications.synack.com/api/v2/'
        url = f'{base}{path}'

        if not kwargs.get('headers'):
            kwargs['headers'] = dict()
        auth = "Bearer " + self.state.notifications_token
        kwargs['headers']['Authorization'] = auth

        res = self.request(method, url, **kwargs)
        if res.status_code == 422:
            self.db.notifications_token = ''
            self.state.notifications_token = ''
        return res

    def request(self, method, path, include_std_headers=True, attempt=0, **kwargs):
        """Send API Request

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
            base = 'https://platform.synack.com/api/'
        url = f'{base}{path}'

        warnings.filterwarnings("ignore")
        verify = False
        proxies = self.state.proxies if self.state.use_proxies else None

        if include_std_headers:
            headers = {
                'Authorization': f'Bearer {self.state.api_token}',
                'user_id': self.state.user_id
            }
        else:
            headers = dict()
        if kwargs.get('headers'):
            headers.update(kwargs.get('headers', {}))
        query = kwargs.get('query')
        data = kwargs.get('data')

        if method.upper() == 'GET':
            res = self.state.session.get(url,
                                         headers=headers,
                                         proxies=proxies,
                                         params=query,
                                         verify=verify)
        elif method.upper() == 'HEAD':
            res = self.state.session.head(url,
                                          headers=headers,
                                          proxies=proxies,
                                          params=query,
                                          verify=verify)
        elif method.upper() == 'PATCH':
            res = self.state.session.patch(url,
                                           json=data,
                                           headers=headers,
                                           proxies=proxies,
                                           verify=verify)
        elif method.upper() == 'POST':
            if 'urlencoded' in headers.get('Content-Type', ''):
                res = self.state.session.post(url,
                                              data=data,
                                              headers=headers,
                                              proxies=proxies,
                                              verify=verify)
            else:
                res = self.state.session.post(url,
                                              json=data,
                                              headers=headers,
                                              proxies=proxies,
                                              verify=verify)
        elif method.upper() == 'PUT':
            res = self.state.session.put(url,
                                         headers=headers,
                                         proxies=proxies,
                                         params=data,
                                         verify=verify)

        self.debug.log("Network Request",
                       f"{res.status_code} -- {method.upper()} -- {url}" +
                       f"\n\tHeaders: {headers}" +
                       f"\n\tQuery: {query}" +
                       f"\n\tData: {data}" +
                       f"\n\tContent: {res.content}")

        if res.status_code == 429:
            attempts = kwargs.get('attempts', 0)
            if attempts < 5:
                time.sleep(30)
                attempts += 1
                return self.request(method, path, include_std_headers, attempts, **kwargs)
        return res
