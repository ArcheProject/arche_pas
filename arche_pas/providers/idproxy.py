from requests_oauthlib import OAuth2Session

from arche_pas.models import PASProvider
from arche_pas import _


class IDProxy(PASProvider):
    name = "idproxy"
    title = _("VoteIT IDProxy")
    id_key = 'identity_id'
    paster_config_ns = __name__
    default_settings = {
        "scope":["identity","email"],
    }
    trust_email = True

    def begin(self):
        auth_session = OAuth2Session(
            client_id=self.settings['client_id'],
            scope=self.settings['scope'],
            redirect_uri=self.callback_url()
        )
        authorization_url, state = auth_session.authorization_url(
            self.settings['auth_uri'],
        )
        return authorization_url

    def callback(self):
        auth_session = OAuth2Session(
            client_id=self.settings['client_id'],
            redirect_uri=self.callback_url()
        )
        res = auth_session.fetch_token(
            self.settings['token_uri'],
            code=self.request.GET.get('code', ''),
            client_secret=self.settings['client_secret'],
        )
        profile_response = auth_session.get(self.settings['profile_uri'])
        if profile_response.ok:
            return profile_response.json()
        raise profile_response.raise_for_status()


    def get_email(self, response, validated=False):
        user_data = response.get("user_data", None)
        if user_data is not None:
            for item in user_data:
                if item["scope"] == "email":
                    return item['data']

    def registration_appstruct(self, response):
        email = self.get_email(response)
        if not email:
            email = ''
        return dict(
            first_name = response.get('given_name',''),
            last_name = response.get('family_name',''),
            email = email,
        )


def includeme(config):
    config.add_pas(IDProxy)
