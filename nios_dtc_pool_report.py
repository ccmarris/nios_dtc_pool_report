#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Report on NIOS DTC pool configuration and flag potential
    misconfigurations:
      - Pools using the ALL_AVAILABLE load balancing method with a
        mixture of IP based and FQDN based servers
      - Pools not associated with any LBDN

 Requirements:
   Python 3.10+

 Author: Chris Marrison

 Date Last Updated: 20261021

 Todo:

 Copyright (c) 2026 Chris Marrison / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

'''
__version__ = '0.1.0'
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'
__license__ = 'BSD'

import argparse
import configparser
import csv
import ipaddress
import json
import logging
import requests

logger = logging.getLogger(__name__)

POOL_FIELDS = ('name,comment,disable,availability,quorum,'
               'lb_preferred_method,lb_alternate_method,'
               'servers,monitors,consolidated_monitors,health,ttl,use_ttl')
SERVER_FIELDS = 'name,host,disable,monitors,use_sni_hostname,health'
LBDN_FIELDS = 'name,disable,pools,lb_method,patterns,auth_zones'

ALL_AVAILABLE = 'ALL_AVAILABLE'

# Pool 'availability' field: how monitor results are combined
AVAILABILITY_LABELS = {'ALL': 'All monitors up', 'ANY': 'Any monitor up',
                       'QUORUM': 'Quorum of monitors up'}

# Severity and description of each finding type
FINDINGS = {
    'ALL_AVAILABLE_MIXED_SERVER_TYPES': ('HIGH',
        'Pool uses the ALL_AVAILABLE LB method with a mix of IP and '
        'FQDN servers'),
    'POOL_HEALTH_RED': ('HIGH',
        'Pool health is RED'),
    'POOL_HEALTH_YELLOW': ('MEDIUM',
        'Pool health is YELLOW'),
    'MIXED_SERVER_TYPES': ('LOW',
        'Pool has a mix of IP and FQDN servers (other LB method)'),
    'POOL_NO_SERVERS': ('LOW',
        'Pool has no servers assigned'),
    'SERVER_NOT_FOUND': ('LOW',
        'Pool references a server that was not returned by the Grid'),
    'POOL_NOT_IN_LBDN': ('INFO',
        'Pool is not associated with any LBDN'),
    'POOL_HEALTH_UNKNOWN': ('INFO',
        'Pool health is not GREEN, YELLOW or RED (e.g. GRAY/NONE)'),
    'POOL_DISABLED': ('INFO',
        'Pool is disabled'),
}

# Summary wording by finding type: (singular, plural) following the count
SUMMARY = {
    'ALL_AVAILABLE_MIXED_SERVER_TYPES': (
        'pool uses the ALL_AVAILABLE LB method with a mix of IP and '
        'FQDN servers',
        'pools use the ALL_AVAILABLE LB method with a mix of IP and '
        'FQDN servers'),
    'POOL_HEALTH_RED': (
        'pool has RED health',
        'pools have RED health'),
    'POOL_HEALTH_YELLOW': (
        'pool has YELLOW health',
        'pools have YELLOW health'),
    'MIXED_SERVER_TYPES': (
        'pool has a mix of IP and FQDN servers (other LB method)',
        'pools have a mix of IP and FQDN servers (other LB method)'),
    'POOL_NO_SERVERS': (
        'pool has no servers assigned',
        'pools have no servers assigned'),
    'SERVER_NOT_FOUND': (
        'pool references a server that was not returned by the Grid',
        'pools reference servers that were not returned by the Grid'),
    'POOL_NOT_IN_LBDN': (
        'pool is not associated with any LBDN',
        'pools are not associated with any LBDN'),
    'POOL_HEALTH_UNKNOWN': (
        'pool has health that is not GREEN, YELLOW or RED (e.g. GRAY/NONE)',
        'pools have health that is not GREEN, YELLOW or RED (e.g. GRAY/NONE)'),
    'POOL_DISABLED': (
        'pool is disabled',
        'pools are disabled'),
}


def parseargs():
    '''
    Parse Arguments Using argparse

    Parameters:
        None

    Returns:
        Returns parsed arguments
    '''
    description = 'Report on NIOS DTC pool configuration and misconfigurations'
    parse = argparse.ArgumentParser(description=description)
    parse.add_argument('-c', '--config', type=str, default='gm.ini',
                       help='Override ini file')
    parse.add_argument('-o', '--output', type=str, default='',
                       help='Output file prefix; writes <prefix>_pools.csv, '
                            '<prefix>_findings.csv and <prefix>.json')
    parse.add_argument('--findings-only', action='store_true',
                       help='Only print pools with findings')
    parse.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug messages')

    return parse.parse_args()


def read_ini(ini_filename: str) -> dict:
    '''
    Open and parse ini file

    Parameters:
        ini_filename (str): name of inifile

    Returns:
        dict: NIOS configuration elements
    '''
    cfg = configparser.ConfigParser()
    config = {}
    ini_keys = ['gm', 'api_version', 'valid_cert', 'user', 'pass']

    try:
        cfg.read(ini_filename)
    except configparser.Error as err:
        logger.error(err)

    if 'NIOS' in cfg:
        for key in ini_keys:
            if key in cfg['NIOS']:
                config[key] = cfg['NIOS'][key].strip("'\"")
                logger.debug(f'Key {key} found in {ini_filename}')
            else:
                logger.warning(f'Key {key} not found in NIOS section.')
                config[key] = ''
    else:
        logger.error(f'No NIOS section in config file: {ini_filename}')

    return config


def setup_logging(debug: bool = False):
    '''
    Set up logging

    Parameters:
        debug (bool): True or False.

    Returns:
        None.
    '''
    if debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')

    return


def classify_host(host: str) -> str:
    '''
    Classify a DTC server host value

    Parameters:
        host (str): IP address or FQDN

    Returns:
        str: 'IP' or 'FQDN' ('' if host is empty)
    '''
    host_type = ''

    if host:
        try:
            ipaddress.ip_address(host.strip())
            host_type = 'IP'
        except ValueError:
            host_type = 'FQDN'

    return host_type


def ref_name(ref: str) -> str:
    '''
    Extract the object name from a WAPI _ref
    (e.g. dtc:pool/ZG5z...:my_pool -> my_pool)

    Parameters:
        ref (str): object reference (or plain name)

    Returns:
        str: object name
    '''
    name = ''

    if ref:
        name = ref.rsplit(':', 1)[-1] if ':' in ref else ref

    return name


def analyse(pools: list, servers: list, lbdns: list) -> list:
    '''
    Analyse DTC pools and produce per pool records with findings

    Parameters:
        pools (list): dtc:pool objects
        servers (list): dtc:server objects
        lbdns (list): dtc:lbdn objects

    Returns:
        list: one dict per pool, including 'servers', 'lbdns', 'findings'
    '''
    server_by_ref = {s.get('_ref'): s for s in servers}
    server_by_name = {s.get('name'): s for s in servers}

    # Map pool name -> LBDN names
    pool_lbdns = {}
    for lbdn in lbdns:
        for entry in lbdn.get('pools', []):
            pname = ref_name(entry.get('pool', ''))
            pool_lbdns.setdefault(pname, []).append(lbdn.get('name'))

    records = []
    for pool in pools:
        name = pool.get('name')
        availability_requirements = pool.get('availability', '')
        preferred = pool.get('lb_preferred_method', '')
        alternate = pool.get('lb_alternate_method', '')
        findings = []
        pool_servers = []

        for entry in pool.get('servers', []):
            sref = entry.get('server', '')
            srv = server_by_ref.get(sref) or server_by_name.get(ref_name(sref))
            if srv:
                host = srv.get('host', '')
                pool_servers.append({'name': srv.get('name'),
                                     'host': host,
                                     'type': classify_host(host),
                                     'ratio': entry.get('ratio'),
                                     'disable': srv.get('disable', False),
                                     'health': (srv.get('health') or {}).get(
                                         'availability', '')})
            else:
                logger.warning(f'Pool {name}: server {sref} not found')
                pool_servers.append({'name': ref_name(sref), 'host': '',
                                     'type': '', 'ratio': entry.get('ratio'),
                                     'disable': False, 'health': ''})
                findings.append(('SERVER_NOT_FOUND', ref_name(sref)))

        types = {s['type'] for s in pool_servers if s['type']}
        if types == {'IP', 'FQDN'}:
            n_ip = sum(1 for s in pool_servers if s['type'] == 'IP')
            n_fqdn = sum(1 for s in pool_servers if s['type'] == 'FQDN')
            detail = f'{n_ip} IP / {n_fqdn} FQDN'
            if ALL_AVAILABLE in (preferred, alternate):
                findings.append(('ALL_AVAILABLE_MIXED_SERVER_TYPES', detail))
            else:
                findings.append(('MIXED_SERVER_TYPES', detail))

        if name not in pool_lbdns:
            findings.append(('POOL_NOT_IN_LBDN', ''))

        if not pool_servers:
            findings.append(('POOL_NO_SERVERS', ''))

        health = ((pool.get('health') or {}).get('availability') or '').upper()
        health_detail = (pool.get('health') or {}).get('description', '')
        if health == 'RED':
            findings.append(('POOL_HEALTH_RED', health_detail))
        elif health == 'YELLOW':
            findings.append(('POOL_HEALTH_YELLOW', health_detail))
        elif health != 'GREEN':
            findings.append(('POOL_HEALTH_UNKNOWN', health or 'NONE'))

        if pool.get('disable', False):
            findings.append(('POOL_DISABLED', ''))

        records.append({'name': name,
                        'comment': pool.get('comment', ''),
                        'disable': pool.get('disable', False),
                        'availability_requirements': availability_requirements,
                        'quorum': pool.get('quorum', 0),
                        'lb_preferred_method': preferred,
                        'lb_alternate_method': alternate,
                        'monitors': [ref_name(m) for m in pool.get('monitors', [])],
                        'health': (pool.get('health') or {}).get(
                            'availability', ''),
                        'health_description': (pool.get('health') or {}).get(
                            'description', ''),
                        'servers': pool_servers,
                        'lbdns': sorted(pool_lbdns.get(name, [])),
                        'findings': [{'type': t, 'severity': FINDINGS[t][0],
                                      'detail': d} for t, d in findings]})

    return records


class NIOSDTC:
    '''
    Retrieve DTC configuration from NIOS via WAPI
    '''

    def __init__(self, cfg: str = 'gm.ini') -> None:
        '''
        Initialise WAPI session

        Parameters:
            cfg (str): ini filename
        '''
        self.config = read_ini(cfg)
        self.gm = self.config.get('gm')
        self.wapi_version = self.config.get('api_version')
        self.base_url = f'https://{self.gm}/wapi/{self.wapi_version}'
        self.validate_cert = self.config.get('valid_cert') == 'true'

        if not self.validate_cert:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.session.auth = (self.config.get('user'), self.config.get('pass'))
        self.session.verify = self.validate_cert
        self.session.headers.update({'content-type': 'application/json'})

        return

    def get_objects(self, obj: str, return_fields: str) -> list | None:
        '''
        Retrieve all objects of a type, handling paging

        Parameters:
            obj (str): WAPI object type, e.g. dtc:pool
            return_fields (str): comma separated fields

        Returns:
            list: objects, or None on failure
        '''
        objects = []
        failed = False
        params = {'_return_fields+': return_fields, '_paging': 1,
                  '_max_results': 999, '_return_as_object': 1}
        url = f'{self.base_url}/{obj}'

        while url and not failed:
            logger.debug(f'GET {url} {params}')
            try:
                response = self.session.get(url, params=params, timeout=60)
                response.raise_for_status()
                data = response.json()
            except (requests.RequestException, ValueError) as err:
                logger.error(f'Failed to retrieve {obj}: {err}')
                failed = True
            else:
                objects += data.get('result', [])
                next_page = data.get('next_page_id')
                if next_page:
                    params = {'_page_id': next_page, '_paging': 1,
                              '_max_results': 999, '_return_as_object': 1}
                else:
                    url = None

        if failed:
            objects = None
        else:
            logger.info(f'Retrieved {len(objects)} {obj} objects')

        return objects


def print_report(records: list, findings_only: bool = False):
    '''
    Print the report to stdout

    Parameters:
        records (list): analysed pool records
        findings_only (bool): only show pools with findings

    Returns:
        None
    '''
    counts = {t: 0 for t in FINDINGS}
    for rec in records:
        for f in rec['findings']:
            counts[f['type']] += 1

    print('\nDTC Pool Configuration Report')
    print('=' * 29)
    print(f'Pools: {len(records)}\n')
    print('Findings summary:')
    for ftype, (sev, _) in FINDINGS.items():
        count = counts[ftype]
        text = SUMMARY[ftype][0 if count == 1 else 1]
        print(f'  [{sev:6}] {count:4}  {text}')
    print()

    health_counts = {}
    for rec in records:
        value = (rec['health'] or 'NONE').upper()
        if value != 'GREEN':
            health_counts[value] = health_counts.get(value, 0) + 1
    print('Non-GREEN pool health:')
    if health_counts:
        order = {'RED': 0, 'YELLOW': 1}
        for value in sorted(health_counts,
                            key=lambda v: (order.get(v, 2), v)):
            print(f'  {value:10} {health_counts[value]:4}')
    else:
        print('  None')
    print()

    for rec in records:
        if findings_only and not rec['findings']:
            continue
        rule = AVAILABILITY_LABELS.get(rec['availability_requirements'],
                                       rec['availability_requirements'])
        health = rec['health'] or '-'
        if rec['health_description']:
            health += f' ({rec["health_description"]})'
        state = ' (disabled)' if rec['disable'] else ''
        print(f'Pool: {rec["name"]}{state}')
        print(f'  {"LB method":26}: {rec["lb_preferred_method"]}'
              f' / {rec["lb_alternate_method"] or "-"}')
        print(f'  {"Monitors":26}: {", ".join(rec["monitors"]) or "-"}')
        print(f'  {"Availability Requirements":26}: {rule}')
        print(f'  {"Health":26}: {health}')
        print(f'  {"LBDNs":26}: {", ".join(rec["lbdns"]) or "-"}')
        print(f'  {"Servers":26}:')
        for s in rec['servers']:
            print(f'    - {s["name"]:30} {s["type"]:5} {s["host"]:30}'
                  f' {s["health"] or "-"}')
        for f in rec['findings']:
            detail = f' ({f["detail"]})' if f['detail'] else ''
            print(f'  ** [{f["severity"]}] {f["type"]}{detail}')
        print()

    return


def write_outputs(records: list, prefix: str):
    '''
    Write CSV and JSON outputs

    Parameters:
        records (list): analysed pool records
        prefix (str): output file prefix

    Returns:
        None
    '''
    pool_cols = ['name', 'comment', 'disable', 'availability_requirements', 'quorum',
                 'lb_preferred_method', 'lb_alternate_method', 'health',
                 'health_description',
                 'monitors', 'lbdns', 'servers', 'ip_servers',
                 'fqdn_servers', 'findings']
    try:
        with open(f'{prefix}_pools.csv', 'w', newline='') as fh:
            writer = csv.DictWriter(fh, fieldnames=pool_cols)
            writer.writeheader()
            for rec in records:
                row = {k: rec.get(k, '') for k in pool_cols}
                row['monitors'] = ';'.join(rec['monitors'])
                row['lbdns'] = ';'.join(rec['lbdns'])
                row['servers'] = ';'.join(
                    f'{s["name"]}={s["host"]}' for s in rec['servers'])
                row['ip_servers'] = sum(
                    1 for s in rec['servers'] if s['type'] == 'IP')
                row['fqdn_servers'] = sum(
                    1 for s in rec['servers'] if s['type'] == 'FQDN')
                row['findings'] = ';'.join(
                    f['type'] for f in rec['findings'])
                writer.writerow(row)

        with open(f'{prefix}_findings.csv', 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['pool', 'severity', 'finding', 'description',
                             'detail'])
            for rec in records:
                for f in rec['findings']:
                    writer.writerow([rec['name'], f['severity'], f['type'],
                                     FINDINGS[f['type']][1], f['detail']])

        with open(f'{prefix}.json', 'w') as fh:
            json.dump(records, fh, indent=2)
        logger.info(f'Wrote {prefix}_pools.csv, {prefix}_findings.csv '
                    f'and {prefix}.json')
    except OSError as err:
        logger.error(f'Failed to write output: {err}')

    return


def main() -> int:
    '''
    Core logic

    Returns:
        int: exit code
    '''
    exitcode = 0
    args = parseargs()
    setup_logging(args.debug)

    nios = NIOSDTC(args.config)
    pools = nios.get_objects('dtc:pool', POOL_FIELDS)
    servers = nios.get_objects('dtc:server', SERVER_FIELDS)
    lbdns = nios.get_objects('dtc:lbdn', LBDN_FIELDS)

    if pools is None or servers is None or lbdns is None:
        logger.error('Unable to retrieve DTC configuration')
        exitcode = 1
    else:
        records = analyse(pools, servers, lbdns)
        print_report(records, args.findings_only)
        if args.output:
            write_outputs(records, args.output)

    return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
