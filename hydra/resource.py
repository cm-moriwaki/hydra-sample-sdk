import base64
import requests


class Resource():
    def __init__(self, hydra_url, client_id, client_secret):
        self.hydra_url = hydra_url
        self.client_id = client_id
        self.client_secret = client_secret

    def introspect(self, token):
        auth_code = base64.b64encode('{}:{}'.format(
            self.client_id, self.client_secret).encode()).decode('utf-8')
        headers = {
            "Authorization": 'Basic {}'.format(auth_code),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = dict(
            token=token,
        )
        resp = requests.post('{}/oauth2/introspect'.format(self.hydra_url),
                             data=data, headers=headers)
        if not resp:
            raise Exception(resp)

        return resp.json()
