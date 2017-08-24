import requests
import base64
from jose import jwt
from datetime import datetime
from Crypto.PublicKey import RSA


class Consent():
    def __init__(self, hydra_url, client_id, client_secret):
        self.hydra_url = hydra_url
        self.client_id = client_id
        self.client_secret = client_secret

    def _get_access_token(self):
        auth_code = base64.b64encode('{}:{}'.format(
            self.client_id, self.client_secret).encode()).decode('utf-8')
        headers = {
            "Authorization": 'Basic {}'.format(auth_code),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = dict(
            grant_type="client_credentials",
            scope="hydra.keys.get",
        )
        resp = requests.post('{}/oauth2/token'.format(self.hydra_url), data=data, headers=headers)
        if not resp:
            raise Exception(resp)

        token = resp.json()['access_token']
        return token

    def _get_challenge_public_key(self, token=None):
        return self._get_key("/keys/hydra.consent.challenge/public", token)

    def _get_response_private_key(self, token=None):
        return self._get_key("/keys/hydra.consent.response/private", token)

    def _to_pem(self, vecort_private_key):
        def decode_rsa_element(i):
            i += '=' * (-len(i) % 4)
            b = base64.urlsafe_b64decode(i)
            d = int.from_bytes(b, byteorder='big')
            return d

        key_raw = (vecort_private_key['n'], vecort_private_key['e'],
                   vecort_private_key['d'], vecort_private_key['p'], vecort_private_key['q'])
        keys = (decode_rsa_element(i) for i in key_raw)
        private_key = RSA.construct(keys)
        return private_key.exportKey().decode('utf-8')

    def _get_key(self, path, token=None):
        t = token if token else self._get_access_token()
        headers = {
            "Authorization": "Bearer {}".format(t),
        }

        resp = requests.get(
            '{}{}'.format(self.hydra_url, path), headers=headers)
        if not resp:
            raise Exception(resp)
        data = resp.json()
        rsa_key = data['keys'][0]
        return rsa_key

    def get_claims(self, challenge):
        rsa_key = self._get_challenge_public_key()
        # FIXME jose jwtでaudの値をvalidateする
        # consent-appではaud判定をしたくない(がhydraがaudをclient_idで付与してくる)ので
        # 一時しのぎ的な処理を追加する。

        def _validate_aud(claims, audience=None):
            return
        jwt._validate_aud = _validate_aud
        decoded = jwt.decode(challenge, rsa_key, algorithms=['RS256', ])
        self.claims = decoded
        print("@@@ claims.", decoded)
        return decoded

    def _create_response_token(self, challenge_claims=None):
        claims = challenge_claims if challenge_claims else self.claims
        now_unixtime = int(datetime.now().timestamp())
        response_raw = dict(
            jti=claims['jti'],
            aud=claims['aud'],
            exp=now_unixtime + 300,  # 5 min later
            scp=claims['scp'],
            sub='CONSENT_APP_SUB',
            iat=now_unixtime,
        )
        print("@@@ response_raw.", response_raw)
        # get consent app private key(とりあえずhydraから取得する)
        rsa_key = self._to_pem(self._get_response_private_key())
        encoded = jwt.encode(response_raw, rsa_key, algorithm='RS256')
        print("@@ encoded response", encoded, type(encoded))
        return encoded

    def get_success_response(self):
        redir = self.claims['redir']
        return '{}&consent={}'.format(redir, self._create_response_token())

    def get_deny_response(self):
        redir = self.claims['redir']
        return '{}&consent=denied'.format(redir)
