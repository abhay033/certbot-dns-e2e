"""DNS Authenticator for E2EConfig."""
import json
import logging
import time
import requests

from e2e_client.manager import Manager
from e2e_client.domain import Domain
from e2e_client.exceptions import TokenException, DomainException
from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for E2EConfig

    This Authenticator uses the E2EConfig Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using E2EConfig for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=20
        )
        add("credentials", help="E2E credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the E2E-Client."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "E2E credentials INI file",
            {
                "api_key": "Api key for Remote API.",
                "api_token": "Api token for Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_e2econfig_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_e2econfig_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_e2econfig_client(self):
        return _E2EConfigClient(
            self.credentials.conf("api_key"),
            self.credentials.conf("api_token"),
        )


class _E2EConfigClient(object):
    """
    Encapsulates all communication with the E2EConfig Remote REST API.
    """

    def __init__(self, api_key, api_token):
        logger.debug("creating e2econfigclient")
        self.api_key = api_key
        self.api_token = api_token


    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the e2e_client API
        """
        if not domain.endswith('.'):
            domain += '.'
        record_content = '"' + record_content + '"'   
        record_name = record_name + '.' 
        try:
            Manager(api_key=self.api_key, api_token=self.api_token).check_token()
        except TokenException as e:
            hint = 'Did you provide a valid API token?'  
            
            logger.debug('Error finding domain using the e2e_client API')
            raise errors.PluginError('Error finding domain using the e2e_client API: {0}'
                                     .format(e))

        try:
            Domain(domain_name=domain, zone_name=domain, record_name=record_name, record_ttl=record_ttl, record_type='TXT', content=record_content, api_key=self.api_key, api_token=self.api_token).check_domain_valid()
            self._find_managed_zone_id(domain_name=domain, zone_name=domain, record_name=record_name, record_ttl=record_ttl, record_type='TXT', content=record_content, api_key=self.api_key, api_token=self.api_token)
        except DomainException as e: 
            hint = 'Did you provide a correct Domain Name?'  
            
            logger.debug('Error finding domain using the e2e_client API')
            raise errors.PluginError('Error finding domain using the e2e_client API: {0}'
                                     .format(e)) 

        try:
            result = Domain(domain_name=domain, zone_name=domain, record_name=record_name, record_ttl=record_ttl, record_type='TXT', content=f'{record_content}', api_key=self.api_key, api_token=self.api_token).add_record() 
            result_message = result['message']
            logger.debug('Successfully added TXT record with id: %s', result_message)
        except:
            logger.debug('Error adding TXT record using the e2e_client API')
            raise errors.PluginError('Error adding TXT record using the e2e API')

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the e2eConfig API
        """
        if not domain.endswith('.'):
            domain += '.'

        record_content = '"' + record_content + '"'
        record_name = record_name + '.'

        
        try:
            domain = self._find_managed_zone_id(domain_name=domain, zone_name=domain, record_name=record_name, record_ttl=record_ttl, record_type='TXT', content=record_content, api_key=self.api_key, api_token=self.api_token)
        except errors as e:
            logger.debug('Error finding domain using the E2E_Client API: %s', e)
            return
        
        try:
            records = Domain(domain_name=domain, zone_name=domain, record_name=record_name, record_ttl=record_ttl, record_type='TXT', content=record_content, api_key=self.api_key, api_token=self.api_token).check_domin_valid()
            domain_records = records['domain']['rrsets'] 

            matching_records = [record for record in domain_records
                                if record['type'] == 'TXT'
                                and record['name'] == record_name
                                and record['records'][0]['content']== f'{record_content}']
        except:
            logger.debug('Error getting DNS records using the e2e API')
            return
        record_content = record_content.strip('"')
        for record in matching_records:
            try:
                logger.debug('Removing TXT record with id')
                Domain(domain_name=domain, zone_name=domain, record_name=record_name, record_ttl=record_ttl, record_type='TXT', content=record_content, api_key=self.api_key, api_token=self.api_token).delete_record()
            except:
                logger.warning('Error deleting TXT record %s using the e2e API')                      

    def _find_managed_zone_id(self, domain_name, zone_name, record_name, record_ttl, record_type, content, api_key, api_token):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """

        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain_name)
        domains = Domain(domain_name=domain_name, zone_name=zone_name, record_name=record_name, record_ttl=record_ttl, record_type=record_type, content=content, api_key=api_key, api_token=api_token).get_all_domain()

        for zone_name in zone_dns_name_guesses:
            # get the zone id
                logger.debug("looking for zone: %s", zone_name)
                matches = [domain for domain in domains if domain['domain_name'] == zone_name]

                if matches:
                    domain = matches[0]
                    logger.debug('Found base domain for %s using name %s', domain_name, zone_name)
                    return domain      
        raise errors.PluginError(f'Unable to determine base domain for {domain_name} using names: '
                                 f'{zone_dns_name_guesses}.')
    
        