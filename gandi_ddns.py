#!/usr/bin/env python3

"""Update DNS entry using Gandi.net API.
"""

import argparse
import configparser
import ipaddress
import requests
import sys
import xmlrpc.client


def find_public_ipv4_address():
    # TODO: Use a provider which uses TLS and update the logic.
    response = requests.get('http://ipv4.myexternalip.com/raw')
    assert response.status_code == 200

    public_ipv4 = ipaddress.ip_address(response.text.strip())
    assert public_ipv4.version == 4
    assert not public_ipv4.is_multicast
    assert not public_ipv4.is_private
    assert not public_ipv4.is_reserved
    assert not public_ipv4.is_loopback
    assert not public_ipv4.is_link_local
    return public_ipv4


class GandiProxy:
    def __init__(self, key, url, domain):
        self.key = key
        self.api = xmlrpc.client.ServerProxy(url)
        self.domain = domain
        self._zone_id = None

    def zone_id(self):
        if self._zone_id is None:
            self._zone_id = self.api.domain.info(self.key, self.domain)['zone_id']
            assert self._zone_id
        return self._zone_id

    def current_ipv4_address(self, hostname):
        records = self.api.domain.zone.record.list(self.key, self.zone_id(), 0, {'name': hostname, 'type': 'A'})
        assert len(records) == 1
        return ipaddress.ip_address(records[0]['value'])

    def _update_record(self, record):
        new_zone_version = self.api.zone.version.new(self.key, self.zone_id())
        self.api.zone.record.delete(self.key, self.zone_id(), new_zone_version, {'type': 'A', 'name': record['name']})
        self.api.zone.record.add(self.key, self.zone_id(), new_zone_version, record)
        self.api.domain.zone.version.set(self.key, self.zone_id(), new_zone_version)

    def update_record(self, hostname, ipv4, ttl):
        new_record = {
            'type': 'A',
            'name': hostname,
            'value': str(public_ipv4),
            'ttl': ttl}
        self._update_record(new_record)


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', '-c', type=str, default='gandi_ddns.cfg', help='Configuration filename.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Turn on debug output.')
    return parser.parse_args(args=argv)


def read_configuration(filename):
    configuration = configparser.SafeConfigParser()
    configuration.read(filename)
    return configuration['DEFAULT']


def main(argv):
    try:
        args = parse_args(argv)
        configuration = read_configuration(args.configuration)
        public_ipv4 = find_public_ipv4_address()
        if args.verbose:
            print('Public IPv4 address: {}'.format(public_ipv4))

        proxy = GandiProxy(
                configuration['gandi.api.key'],
                configuration['gandi.api.endpoint'],
                configuration['domain'])
        hostname = configuration['hostname']
        ttl = configuration.getint('ttl')
        current_ipv4 = proxy.current_ipv4_address(hostname)
        if args.verbose:
            print('Configured IPv4 address: {}'.format(current_ipv4))
        if current_ipv4 != public_ipv4:
            proxy.update_record(hostname, public_ipv4, ttl)
            if args.verbose:
                print('Updated')

        return 0
    except Exception as e:
        print('Error: {}'.format(e), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

