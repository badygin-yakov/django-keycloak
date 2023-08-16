import mock

from datetime import datetime

import requests
from django.test import TestCase
from keycloak.openid_connection import KeycloakOpenID, ConnectionManager

from django_keycloak.factories import OpenIdConnectProfileFactory
from django_keycloak.tests.mixins import MockTestCaseMixin

import django_keycloak.services.oidc_profile


@mock.patch('requests.post', mock.Mock(
    side_effect=lambda k: {'realms/call-nor-miss/protocol/openid-connect/token': '{"access_token": "RPT_VALUE"}'}.get(
        k)))
class ServicesKeycloakOpenIDProfileGetActiveAccessTokenTestCase(
    MockTestCaseMixin, TestCase):

    def setUp(self):
        self.mocked_get_active_access_token = self.setup_mock(
            'django_keycloak.services.oidc_profile'
            '.get_active_access_token'
        )

        self.oidc_profile = OpenIdConnectProfileFactory(
            access_token='access-token',
            expires_before=datetime(2018, 3, 5, 1, 0, 0),
            refresh_token='refresh-token'
        )
        self.oidc_profile.realm.client.openid_api_client = mock.MagicMock(
            spec_set=KeycloakOpenID)
        self.oidc_profile.realm.client.openid_api_client.connection = mock.MagicMock(spec_set=ConnectionManager)
        self.oidc_profile.realm.client.openid_api_client.connection.raw_post. \
            return_value = mock.MagicMock(
                status_code=200,
                json=mock.MagicMock(return_value={'access_token': 'RPT_VALUE'}))

        self.oidc_profile.realm.certs = {'cert': 'cert-value'}

    # @mock.patch("requests.Response.status_code", new_callable=mock.PropertyMock, return_value=200)
    def test(self):
        django_keycloak.services.oidc_profile.get_entitlement(
            oidc_profile=self.oidc_profile
        )
        self.oidc_profile.realm.client.openid_api_client.connection.raw_post \
            .assert_called_once_with(
            path=f'realms/{self.oidc_profile.realm.name}/protocol/openid-connect/token',
            data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
                'audience': self.oidc_profile.realm.client.client_id,
            },
        )
        self.oidc_profile.realm.client.openid_api_client.decode_token \
            .assert_called_once_with(
            token='RPT_VALUE',
            key=self.oidc_profile.realm.certs,
            options={
                'verify_signature': True,
                'exp': True,
                'iat': True,
                'aud': True
            }
        )
