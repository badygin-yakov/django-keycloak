from __future__ import unicode_literals

import logging

from django.core.management.base import BaseCommand
from django.db import transaction

from django_keycloak.models import Realm

import django_keycloak.services.users
import django_keycloak.services.oidc_profile
from django_keycloak.services.client import get_admin_client

logger = logging.getLogger(__name__)


def realm(name):
    try:
        return Realm.objects.get(name=name)
    except Realm.DoesNotExist:
        raise TypeError('Realm does not exist')



class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument('--realm', type=realm, required=True)

    def handle(self, *args, **options):
        realm: Realm = options['realm']
        admin_client = get_admin_client(realm.client)

        users = admin_client.get_users()

        for user in users:
            with transaction.atomic():
                user_info = {
                    'preferred_username': user['username'],
                    'email': user['email'],
                    'sub': user['id'],
                }
                django_keycloak.services.oidc_profile.update_or_create_user_and_oidc_profile(realm.client, user_info)


