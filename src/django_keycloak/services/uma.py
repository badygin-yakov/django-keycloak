from django.apps.registry import apps
from django.utils.text import slugify

from keycloak.exceptions import KeycloakError

import django_keycloak.services.client


def synchronize_client(client):
    """
    Synchronize all models as resources for a client.

    :type client: django_keycloak.models.Client
    """
    for app_config in apps.get_app_configs():
        synchronize_resources(
            client=client,
            app_config=app_config
        )


def synchronize_resources(client, app_config):
    """
    Synchronize all resources (models) to the Keycloak server for given client
    and Django App.

    :type client: django_keycloak.models.Client
    :type app_config: django.apps.config.AppConfig
    """

    if not app_config.models_module:
        return

    uma1_client = client.uma1_api_client

    access_token = django_keycloak.services.client.get_access_token(
        client=client
    )

    for klass in app_config.get_models():
        scopes = _get_all_permissions(klass._meta)
        payload = dict(
            name=klass._meta.label_lower,
            type=f'urn:{slugify(client.client_id)}:resources:{klass._meta.label_lower}',
            scopes=scopes or []
        )

        try:
            uma1_client.resource_set_create(
                payload=payload,
            )
        except KeycloakError as e:
            if e.response_code != 409:
                raise


def _get_all_permissions(meta):
    """
    :type meta: django.db.models.options.Options
    :rtype: list
    """
    return meta.default_permissions
