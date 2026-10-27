# nios_dtc_pool_report

Reports on NIOS DTC pool configuration via WAPI and flags potential
misconfigurations and unhealthy pools. The tool is read-only: it only issues
WAPI GET requests for `dtc:pool`, `dtc:server` and `dtc:lbdn`.

## Requirements

* Python 3.10+
* `requests` (`pip install -r requirements.txt`)
* A NIOS Grid Master account with read access to DTC objects

## Configuration

```
cp gm.ini.example gm.ini      # edit credentials
```

```ini
[NIOS]
gm = '192.168.1.2'
api_version = 'v2.12'
valid_cert = 'false'
user = 'admin'
pass = 'infoblox'
```

`gm.ini` is git-ignored. Use `-c` to point at a different ini file.

## Usage

```
./nios_dtc_pool_report.py                       # report to stdout
./nios_dtc_pool_report.py --findings-only       # only pools with findings
./nios_dtc_pool_report.py -o dtc_report         # also write CSV + JSON
./nios_dtc_pool_report.py -c ~/configs/emea.ini -d
```

| Option | Description |
|---|---|
| `-c`, `--config` | ini file (default `gm.ini`) |
| `-o`, `--output PREFIX` | also write `PREFIX_pools.csv`, `PREFIX_findings.csv` and `PREFIX.json` |
| `--findings-only` | only print pools that have findings |
| `-d`, `--debug` | debug logging |

Exit code is 1 if the DTC objects could not be retrieved.

## Findings

| Finding | Severity | Meaning |
|---|---|---|
| `ALL_AVAILABLE_MIXED_SERVER_TYPES` | HIGH | Preferred or alternate LB method is `ALL_AVAILABLE` and the servers are a mix of IP and FQDN hosts |
| `POOL_HEALTH_RED` | HIGH | Pool health is RED |
| `POOL_HEALTH_YELLOW` | MEDIUM | Pool health is YELLOW |
| `MIXED_SERVER_TYPES` | LOW | Mix of IP and FQDN servers with any other LB method |
| `POOL_NO_SERVERS` | LOW | Pool has no servers |
| `SERVER_NOT_FOUND` | LOW | Pool references a server not returned by the Grid |
| `POOL_NOT_IN_LBDN` | INFO | Pool is not referenced by any LBDN |
| `POOL_HEALTH_UNKNOWN` | INFO | Pool health is anything other than GREEN, YELLOW or RED (e.g. GRAY, DARKGRAY, NONE or not returned) |
| `POOL_DISABLED` | INFO | Pool is disabled |

Pool health GREEN produces no finding. A host is treated as an IP if it parses
as an IPv4 or IPv6 address, otherwise as an FQDN.

## Report

1. **Findings summary**: a count per finding type, ordered by severity, with
   singular/plural wording.
2. **Pool health summary**: the count of pools in every health state,
   including GREEN (RED, YELLOW, other values such as DARKGRAY or NONE, then
   GREEN). This is in addition to the findings above.
3. **Per pool detail**:

   | Field | Source |
   |---|---|
   | LB method | preferred / alternate (`lb_preferred_method`, `lb_alternate_method`) |
   | Monitors | assigned monitors |
   | Availability Requirements | the pool `availability` field: `ALL` (all monitors up), `ANY` (any monitor up) or `QUORUM` (quorum of monitors up). This is **not** the `ALL_AVAILABLE` LB method |
   | Health | pool health with its description |
   | LBDNs | LBDNs that reference the pool |
   | Servers | name, IP/FQDN type, host and server health |
   | Findings | any findings for the pool |

## Output files

With `-o PREFIX`:

* `PREFIX_pools.csv`: one row per pool (`name`, `comment`, `disable`,
  `availability_requirements`, `quorum`, `lb_preferred_method`,
  `lb_alternate_method`, `health`, `health_description`, `monitors`, `lbdns`,
  `servers`, `ip_servers`, `fqdn_servers`, `findings`). Multi-valued columns are
  `;` separated and `availability_requirements` holds the raw `ALL`/`ANY`/`QUORUM`.
* `PREFIX_findings.csv`: one row per finding (`pool`, `severity`, `finding`,
  `description`, `detail`).
* `PREFIX.json`: the full analysed data.

## Tests

```
python3 -m pytest test_analyse.py
```

The tests use mocked WAPI data and do not need a Grid.
