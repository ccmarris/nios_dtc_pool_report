#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''Unit tests for nios_dtc_pool_report.analyse using mocked WAPI data'''
import nios_dtc_pool_report as r

SERVERS = [
    {'_ref': 'dtc:server/a:web1', 'name': 'web1', 'host': '10.0.0.1'},
    {'_ref': 'dtc:server/b:web2', 'name': 'web2', 'host': 'web2.example.com'},
    {'_ref': 'dtc:server/c:web3', 'name': 'web3', 'host': '2001:db8::1'},
]


def srv(n):
    return {'server': f'dtc:server/x:{n}', 'ratio': 1}


POOLS = [
    {'name': 'mixed_all', 'availability': 'ALL', 'servers': [srv('web1'), srv('web2')]},
    {'name': 'mixed_any', 'availability': 'ANY', 'servers': [srv('web1'), srv('web2')]},
    {'name': 'ip_all', 'availability': 'ALL', 'servers': [srv('web1'), srv('web3')]},
    {'name': 'orphan', 'availability': 'ANY', 'servers': [srv('web1')]},
    {'name': 'empty', 'availability': 'ALL', 'servers': []},
    {'name': 'ghost', 'availability': 'ALL', 'servers': [srv('nope')]},
]
LBDNS = [{'name': 'lb1', 'pools': [
    {'pool': 'dtc:pool/p:mixed_all', 'ratio': 1},
    {'pool': 'dtc:pool/p:mixed_any', 'ratio': 1},
    {'pool': 'dtc:pool/p:ip_all', 'ratio': 1},
    {'pool': 'dtc:pool/p:ghost', 'ratio': 1}]}]


def types(rec):
    return {f['type'] for f in rec['findings']}


def test_analyse():
    recs = {x['name']: x for x in r.analyse(POOLS, SERVERS, LBDNS)}
    assert types(recs['mixed_all']) == {'ALL_MIXED_SERVER_TYPES'}
    assert types(recs['mixed_any']) == set()
    assert types(recs['ip_all']) == set()
    assert types(recs['orphan']) == {'POOL_NOT_IN_LBDN'}
    assert types(recs['empty']) == {'POOL_NOT_IN_LBDN', 'POOL_NO_SERVERS'}
    assert 'SERVER_NOT_FOUND' in types(recs['ghost'])
    assert recs['mixed_all']['lbdns'] == ['lb1']


def test_classify():
    assert r.classify_host('10.1.1.1') == 'IP'
    assert r.classify_host('2001:db8::1') == 'IP'
    assert r.classify_host('a.example.com') == 'FQDN'
    assert r.classify_host('') == ''
