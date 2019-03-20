from typing import Tuple, Dict

from aiohttp import ClientSession, hdrs
from aioresponses import aioresponses
import json as json_util


class Mocker(aioresponses):

    def __init__(self):
        super(Mocker, self).__init__()
        self.request_history = []

    def register_uri(self, method='GET', url='', status_code=200, json=None, **kwargs):
        if json:
            json = json_util.dumps(json)
        else:
            json = ''
        self.add(url, method=method.upper(), status=status_code, body=json, **kwargs)

    async def _request_mock(self, orig_self: ClientSession,
                            method: str, url: 'Union[URL, str]',
                            *args: Tuple,
                            **kwargs: Dict) -> 'ClientResponse':
        """Return mocked response object or raise connection error."""
        while True:
            self.request_history.append(HistoryItem(url))
            resp = await super(Mocker, self)._request_mock(orig_self, method, url, *args, **kwargs)
            if resp.status in (301, 302, 303, 307, 308):
                url = resp.headers.get(hdrs.LOCATION)
                continue
            break

        return resp


class HistoryItem(object):

    def __init__(self, url):
        self.url = url


mock = Mocker
