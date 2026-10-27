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
    {'name': 'mixed_all', 'lb_preferred_method': 'ALL_AVAILABLE',
     'servers': [srv('web1'), srv('web2')]},
    {'name': 'mixed_alt_all', 'lb_preferred_method': 'ROUND_ROBIN',
     'lb_alternate_method': 'ALL_AVAILABLE',
     'servers': [srv('web1'), srv('web2')]},
    {'name': 'mixed_ga', 'availability': 'ALL',
     'health': {'availability': 'GREEN', 'description': 'OK'},
     'lb_preferred_method': 'GLOBAL_AVAILABILITY',
     'servers': [srv('web1'), srv('web2')]},
    {'name': 'ip_all', 'lb_preferred_method': 'ALL_AVAILABLE',
     'servers': [srv('web1'), srv('web3')]},
    {'name': 'orphan', 'lb_preferred_method': 'ROUND_ROBIN',
     'servers': [srv('web1')]},
    {'name': 'empty', 'lb_preferred_method': 'ALL_AVAILABLE', 'servers': []},
    {'name': 'ghost', 'lb_preferred_method': 'ALL_AVAILABLE',
     'servers': [srv('nope')]},
]
for _p in POOLS:
    _p.setdefault('health', {'availability': 'GREEN'})
LBDNS = [{'name': 'lb1', 'pools': [
    {'pool': 'dtc:pool/p:mixed_all', 'ratio': 1},
    {'pool': 'dtc:pool/p:mixed_alt_all', 'ratio': 1},
    {'pool': 'dtc:pool/p:mixed_ga', 'ratio': 1},
    {'pool': 'dtc:pool/p:ip_all', 'ratio': 1},
    {'pool': 'dtc:pool/p:ghost', 'ratio': 1}]}]


def types(rec):
    return {f['type'] for f in rec['findings']}


def test_analyse():
    recs = {x['name']: x for x in r.analyse(POOLS, SERVERS, LBDNS)}
    assert types(recs['mixed_all']) == {'ALL_AVAILABLE_MIXED_SERVER_TYPES'}
    assert types(recs['mixed_alt_all']) == {'ALL_AVAILABLE_MIXED_SERVER_TYPES'}
    assert types(recs['mixed_ga']) == {'MIXED_SERVER_TYPES'}
    assert recs['mixed_ga']['availability_requirements'] == 'ALL'
    assert types(recs['ip_all']) == set()
    assert types(recs['orphan']) == {'POOL_NOT_IN_LBDN'}
    assert types(recs['empty']) == {'POOL_NOT_IN_LBDN', 'POOL_NO_SERVERS'}
    assert 'SERVER_NOT_FOUND' in types(recs['ghost'])
    assert recs['mixed_all']['lbdns'] == ['lb1']


def test_health_findings():
    def pool(name, **kw):
        return dict({'name': name, 'servers': [srv('web1')]}, **kw)
    pools = [pool('red', health={'availability': 'RED', 'description': 'down'}),
             pool('yellow', health={'availability': 'YELLOW'}),
             pool('gray', health={'availability': 'GRAY'}),
             pool('none'),
             pool('off', disable=True, health={'availability': 'GREEN'}),
             pool('ok', health={'availability': 'GREEN'})]
    lbdns = [{'name': 'lb', 'pools': [
        {'pool': f'dtc:pool/p:{p["name"]}'} for p in pools]}]
    recs = {x['name']: x for x in r.analyse(pools, SERVERS, lbdns)}
    assert types(recs['red']) == {'POOL_HEALTH_RED'}
    assert recs['red']['findings'][0]['severity'] == 'HIGH'
    assert types(recs['yellow']) == {'POOL_HEALTH_YELLOW'}
    assert recs['yellow']['findings'][0]['severity'] == 'MEDIUM'
    assert types(recs['gray']) == {'POOL_HEALTH_UNKNOWN'}
    assert types(recs['none']) == {'POOL_HEALTH_UNKNOWN'}
    assert recs['gray']['findings'][0]['severity'] == 'INFO'
    assert types(recs['off']) == {'POOL_DISABLED'}
    assert types(recs['ok']) == set()


def test_classify():
    assert r.classify_host('10.1.1.1') == 'IP'
    assert r.classify_host('2001:db8::1') == 'IP'
    assert r.classify_host('a.example.com') == 'FQDN'
    assert r.classify_host('') == ''


def test_summary_plurals(capsys):
    recs = r.analyse(POOLS, SERVERS, LBDNS)
    r.print_report(recs)
    out = capsys.readouterr().out
    assert '   2  pools use the ALL_AVAILABLE' in out
    assert '   1  pool has a mix of IP and FQDN servers' in out
    assert '   2  pools are not associated with any LBDN' in out
    assert '   1  pool is not associated' not in out


def test_health_summary(capsys):
    pools = [{'name': n, 'servers': [], 'health': {'availability': h}}
             for n, h in [('a', 'RED'), ('b', 'RED'), ('c', 'YELLOW'),
                          ('d', 'DARKGRAY'), ('e', 'GREEN'), ('f', 'GREEN'),
                          ('g', 'GREEN')]]
    pools.append({'name': 'h', 'servers': []})
    r.print_report(r.analyse(pools, SERVERS, []))
    out = capsys.readouterr().out
    summary = out.split('Pool health summary:')[1].split('Pool:')[0]
    lines = [ln.split() for ln in summary.strip().splitlines()]
    assert lines == [['RED', '2'], ['YELLOW', '1'], ['DARKGRAY', '1'],
                     ['NONE', '1'], ['GREEN', '3']]
