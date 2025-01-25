"""plugins/utils.py

Defines utility methods used in other plugins
"""

from .base import Plugin

import re

class Utils(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in []:
            setattr(self,
                    '_'+plugin.lower(),
                    self._registry.get(plugin)(self._state))

    @staticmethod
    def get_html_tag_value(field, text):
        match = re.search(f'<[^>]*name=.{field}.[^>]*value=.([^"\']*)', text)
        if match.group is None:
            match = re.search(f'<[^>]*value=.([^"\']*)[^>]*name=.{field}', text)
        return match.group(1) if match else ''
