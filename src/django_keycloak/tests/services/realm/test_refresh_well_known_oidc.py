import mock

from django.test import TestCase

from django_keycloak.factories import RealmFactory, ClientFactory
from django_keycloak.tests.mixins import MockTestCaseMixin

import django_keycloak.services.realm


class ServicesRealmRefreshWellKnownOIDCTestCase(
        MockTestCaseMixin, TestCase):

    def setUp(self):
        client = ClientFactory(client_id='test-client', secret='test-secret')
        client.realm._well_known_oidc = 'empty'
        self.realm = client.realm

        self.setup_mock('keycloak.keycloak_openid.KeycloakOpenID.certs',
                        return_value={'key': 'value'})

    def test_refresh_well_known_oidc(self):
        """
        Case: An update is requested for the .well-known for a specified realm.
        Expected: The .well-known is updated.
        """
        self.assertEqual(self.realm._well_known_oidc, 'empty')

        django_keycloak.services.realm.refresh_well_known_oidc(
            realm=self.realm
        )

        self.assertEqual(self.realm._well_known_oidc, '{"key": "value"}')
