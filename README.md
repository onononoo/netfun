# netfun

local network scanner. python 3.9+, no dependencies.

scan only networks you own or may test.

## install

```bash
pip install -e .
netfun update-oui
```

or `python -m netfun <command>`.

## commands

```
scan [cidr]        scan and save. --html/--csv/--json file
watch -i 300       rescan on an interval, print changes
show [n]           print a saved scan (-1 = latest)
history            list saved scans
diff [old] [new]   compare two scans
report [n] -f fmt  export html, csv, json
ports host         port scan one host
label mac name     name a device
vendor mac         mac vendor lookup
wake mac|label     wake-on-lan
update-oui         download vendor db
info               local network info
```

## data

`~/.netfun` (or `NETFUN_HOME`): `oui.csv`, `scans/`, `labels.json`.

## tests

```bash
python -m unittest discover tests
```
