import logging

from functools import partial
from typing import Optional
from urllib.parse import urlparse

from django.utils import timezone
from keycloak import KeycloakOpenID, KeycloakAdmin, KeycloakUMA, KeycloakOpenIDConnection

from django_keycloak.services.exceptions import TokensExpired

import django_keycloak.services.oidc_profile
from django_keycloak.models import Client
from django_keycloak.services.realm import get_connection

logger = logging.getLogger(__name__)


def get_keycloak_id(client):
    """
    Get internal Keycloak id for client configured in Realm
    :param django_keycloak.models.Realm realm:
    :return:
    """
    keycloak_clients = client.admin_api_client.realms.by_name(
        name=client.realm.name).clients.all()
    for keycloak_client in keycloak_clients:
        if keycloak_client['clientId'] == client.client_id:
            return keycloak_client['id']

    return None


def get_authz_api_client(client: Client) -> Optional[KeycloakOpenID]:
    """
    :param django_keycloak.models.Client client:
    :rtype: keycloak.authz.KeycloakAuthz
    """
    return client.realm.realm_api_client


def get_openid_client(client: Client) -> Optional[KeycloakOpenID]:
    """
    :param django_keycloak.models.Client client:
    :rtype: keycloak.openid_connect.KeycloakOpenidConnect
    """

    return client.realm.realm_api_client


def get_uma1_client(client: Client) -> Optional[KeycloakUMA]:
    """
    :type client: django_keycloak.models.Client
    :rtype: keycloak.KeycloakUMA
    """

    return KeycloakUMA(connection=get_connection(realm=client.realm))


def get_admin_client(client: Client) -> Optional[KeycloakAdmin]:
    """
    Get the Keycloak admin client configured for given realm.

    :param django_keycloak.models.Client client:
    :rtype: keycloak.KeycloakAdmin
    """
    token = get_access_token(client)

    return KeycloakAdmin(connection=get_connection(client.realm), token=token)


def get_service_account_profile(client: Client):
    """
    Get service account for given client.

    :param django_keycloak.models.Client client:
    :rtype: django_keycloak.models.OpenIdConnectProfile
    """

    if client.service_account_profile:
        return client.service_account_profile

    token_response, initiate_time = get_new_access_token(client=client)

    oidc_profile = django_keycloak.services.oidc_profile._update_or_create(
        client=client,
        token_response=token_response,
        initiate_time=initiate_time,
        service_account=True,
    )

    client.service_account_profile = oidc_profile
    client.save(update_fields=['service_account_profile'])

    return oidc_profile


def get_new_access_token(client: Client):
    """
    Get client access_token

    :param django_keycloak.models.Client client:
    :rtype: str
    """
    scope = 'manage-users'

    initiate_time = timezone.now()
    token_response = client.openid_api_client.token(
        username=f'service-account-{client.client_id}',
        password=client.secret,
        grant_type='client_credentials',
        scope=scope,
    )

    return token_response, initiate_time


def get_access_token(client: Client):
    """
    Get access token from client's service account.
    :param django_keycloak.models.Client client:
    :rtype: str
    """

    oidc_profile = get_service_account_profile(client=client)

    try:
        return django_keycloak.services.oidc_profile.get_active_access_token(
            oidc_profile=oidc_profile)
    except TokensExpired:
        token_reponse, initiate_time = get_new_access_token(client=client)
        oidc_profile = django_keycloak.services.oidc_profile.update_tokens(
            token_model=oidc_profile,
            token_response=token_reponse,
            initiate_time=initiate_time,
            service_account=True,
        )
        return oidc_profile.access_token
