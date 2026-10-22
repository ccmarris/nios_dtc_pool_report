# nios_dtc_pool_report

Reports on NIOS DTC pool configuration via WAPI and flags potential misconfigurations.

## Checks

| Finding | Severity | Meaning |
|---|---|---|
| `ALL_MIXED_SERVER_TYPES` | HIGH | Pool availability is "All available" (`ALL`) and its servers are a mix of IP and FQDN hosts |
| `POOL_NOT_IN_LBDN` | MEDIUM | Pool is not referenced by any LBDN |
| `POOL_NO_SERVERS` | LOW | Pool has no servers |
| `SERVER_NOT_FOUND` | LOW | Pool references a server not returned by the Grid |

## Usage

```
cp gm.ini.example gm.ini      # edit credentials
./nios_dtc_pool_report.py                       # report to stdout
./nios_dtc_pool_report.py --findings-only       # only pools with findings
./nios_dtc_pool_report.py -o dtc_report         # also write CSV + JSON
./nios_dtc_pool_report.py -c ~/configs/emea.ini -d
```

`-o PREFIX` writes `PREFIX_pools.csv` (full config), `PREFIX_findings.csv` and `PREFIX.json`.
Exit code is 1 if DTC objects could not be retrieved.

## Tests

```
python3 -m pytest test_analyse.py
```
