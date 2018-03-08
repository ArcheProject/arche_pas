from logging import getLogger
from string import whitespace

from pyramid.i18n import TranslationStringFactory
from pyramid.settings import asbool


logger = getLogger(__name__)
_ = TranslationStringFactory('arche_pas')


DEFAULTS = {
    #Allow HTTP? Good for debug reasons, not good for anything else
    'arche_pas.insecure_transport': False,
}


def format_providers(txt):
    """ Read configuration option at arche_pas.providers, which should look something like:
        arche_pas.providers.googe_oauth2 /path/to/config.json
        someotherprovider /path/that/config.json
    """
    results = {}
    for row in txt.splitlines():
        row = row.strip()
        if row:
            package_name, file_name = row.split(None, 1)
            results[package_name] = file_name.strip()
    return results


def includeme(config):
    bools = ('arche_pas.insecure_transport',)
    settings = config.registry.settings
    for (k, v) in DEFAULTS.items():
        if k not in settings:
            settings[k] = v
    for k in bools:
        settings[k] = asbool(settings[k])
    if settings['arche_pas.insecure_transport']:
        import os
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    config.include('.models')
    config.include('.catalog')
    config.include('.views')
    config.include('.schemas')
    config.include('.registration_cases')
    #Check for providers and include them
    settings['arche_pas.providers'] = providers = format_providers(settings.get('arche_pas.providers', ''))
    for provider_name in providers:
        config.include(provider_name)
    if not providers:
        logger.warn("arche_pas.providers isn't set so skipping inclusion of arche_pas")
    #Translations
    config.add_translation_dirs('arche_pas:locale/')
