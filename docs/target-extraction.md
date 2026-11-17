# Target extraction

The most common failure mode of a scope gate is not missing an out-of-scope
host. It is flagging so many false positives that the operator learns to click
through every prompt. Once that happens the gate no longer protects anything.

This gate therefore extracts targets only from contexts where a network target
actually appears.

## Inspected contexts

| Context | Pattern | Example |
|---|---|---|
| URL | `https?://host` | `curl https://example.com/x` |
| Network tool argument | host after a known tool | `nmap example.com` |
| Host flag | `-Host`, `-ComputerName`, `-Uri`, `-Url`, `-Server`, `-Target`, `-Address` | `Test-Connection -ComputerName example.com` |

Network tools recognized out of the box:

```
nmap masscan curl wget ping ping6 tracert traceroute
nslookup dig host whois ssh scp sftp ftp nc netcat telnet
Test-Connection Test-NetConnection Resolve-DnsName
Invoke-WebRequest Invoke-RestMethod iwr irm
```

## Deliberately ignored contexts

| Input | Why it is ignored |
|---|---|
| `json.loads(s)`, `urllib.request`, `re.findall` | Dotted identifiers are not domains |
| `sample.bin`, `report.pdf` | File names are not hosts |
| `search_web` query text | Searching for a domain does not contact it |
| `10.0.0.5` (default) | Private addresses are lab noise |
| Comments, prose, documentation | No network context |

A search query is only inspected for URLs. Searching for `example.com` does not
touch `example.com`; opening `https://example.com` does.

## Noise list

`hooks/noise.json` is a JSON array of domains that are never targets:

```json
[
  "medium.com",
  "stackoverflow.com",
  "abuse.ch",
  "nvd.nist.gov"
]
```

A host is skipped when it equals an entry or is a subdomain of one. The list
covers documentation, social platforms, package registries, and malware-sample
or CVE-reference sources.

The list is explicit and operator-maintained. It is not learned from traffic.
A gate that authorizes whatever it has already seen is equivalent to no gate:
one malicious page or one injected instruction is enough to authorize the host
it points at.

## Private addresses

Private, loopback, and link-local addresses are skipped by default, because
they are the normal targets of a local lab. Set `BTG_GATE_PRIVATE_IPS=1` to
gate them. When that flag is set, the shipped `lab.md` still authorizes the
RFC 1918 ranges, so lab work does not prompt.

## Priority order

For each candidate host:

1. Reject if it looks like a file name (known extension).
2. Reject if it is in the noise list.
3. Reject if it is private and private gating is disabled.
4. Check the scope registry.

Step 4 is the only step that can prompt.
