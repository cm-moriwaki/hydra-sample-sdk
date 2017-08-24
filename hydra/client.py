import requests
import base64


class Client():
    def __init__(self, hydra_url, client_id, client_secret):
        self.hydra_url = hydra_url
        self.client_id = client_id
        self.client_secret = client_secret

    def get_access_token(self, code):
        auth_code = base64.b64encode('{}:{}'.format(
            self.client_id, self.client_secret).encode()).decode('utf-8')
        headers = {
            "Authorization": 'Basic {}'.format(auth_code),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = dict(
            grant_type="authorization_code",
            client_id=self.client_id,
            code=code,
            scope="pi",
        )
        resp = requests.post('{}/oauth2/token'.format(self.hydra_url), data=data, headers=headers)
        if not resp:
            raise Exception(resp)

        return resp.json()
