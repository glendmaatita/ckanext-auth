import ckan.logic as logic
import ckan.lib.authenticator as authenticator
import ckan.lib.api_token as api_token
import ckan.lib.dictization.model_save as model_save
import ckan.model as model
from ckan.plugins import toolkit as tk
from ckan.common import _

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
    user = model.User.get(data_dict['name'])
    if not user:
        site_user = logic.get_action(u'get_site_user')({
            u'model': model,
            u'ignore_auth': True},
            {}
        )
        context = {
            u'model': model,
            u'session': model.Session,
            u'ignore_auth': True,
            u'user': site_user['name'],
        }
        user = logic.get_action(u'user_create')(context, data_dict)
    else:
        user = user.as_dict()

    # get token if exists
    token = model.Session.query(model.ApiToken).filter(
        model.ApiToken.user_id == user['id']
    ).first()

    print(token, flush=True)

    if not token:
        token_obj = model_save.api_token_save(
            {u'user': user['id'], u'name': user['name']}, context
        )
    else:
        token_obj = token

    model.Session.commit()
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
