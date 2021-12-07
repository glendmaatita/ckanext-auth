import ckan.logic as logic
import ckan.lib.authenticator as authenticator
import ckan.lib.api_token as api_token
from ckan.plugins import toolkit as tk
from ckan.common import _
from ckan.model import ApiToken

_check_access = logic.check_access

def user_login(context, data_dict):
    # Adapted from  https://github.com/ckan/ckan/blob/master/ckan/views/user.py#L203-L211
    generic_error_message = {
        u'errors': {
            u'auth': [_(u'Username or password entered was incorrect')]
        },
        u'error_summary': {_(u'auth'): _(u'Incorrect username or password')}
    }
    model = context['model']
    user = model.User.get(data_dict['id'])
    if not user:
        return generic_error_message

    user = user.as_dict()

    token_obj = ApiToken(data_dict['id'])
    token_data = {
        u'jti': token_obj.id,
        u'iat': api_token.into_seconds(token_obj.created_at)
    }
    token = api_token.encode(token_data)

    user['token'] = token

    if data_dict[u'password']:
        identity = {
            u'login': user['name'],
            u'password': data_dict[u'password']
        }

        auth = authenticator.UsernamePasswordAuthenticator()
        authUser = auth.authenticate(context, identity)

        if authUser != user['name']:
            return generic_error_message
        else:
            return user
