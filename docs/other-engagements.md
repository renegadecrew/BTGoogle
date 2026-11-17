# Using BTGoogle for other engagements

The gate is scope-agnostic. It does not know whether the target is a bug-bounty
program, an internal network, a CTF, a cloud account, or a malware lab. It only
knows the assets in the program files you give it.

Most people never need to edit the Python. They edit four things:

| Knob | File / variable | What it controls |
|---|---|---|
| Programs | `hooks/programs/*.md` | What is authorized |
| Noise | `hooks/noise.json` | What is a reference, never a target |
| Lab TLDs | `BTG_LAB_TLDS` | Single-label wildcards your lab uses |
| Policy | `BTG_OUT_OF_SCOPE`, `BTG_GATE_PRIVATE_IPS` | When to prompt |

## Recipes

### Web application or bug-bounty program

```markdown
# Program: acme
expires: 2027-06-30

## In-scope

*.acme.example
acme.example

## Out-of-scope

legacy.acme.example
```

Add each asset with `scope_add.py` if you prefer not to edit the file:

```powershell
python scripts/scope_add.py --program hooks/programs/acme.md api.acme.example
```

### Internal network or Active Directory

```markdown
# Program: corp

## In-scope

10.0.0.0/8
172.16.0.0/12
*.corp.local
*.corp.internal

## Out-of-scope
```

`*.corp` and `*.internal` are not in the default lab TLD list. Enable them:

```powershell
setx BTG_LAB_TLDS "corp,internal"
```

### CTF or hosted lab platform

```markdown
# Program: ctf

## In-scope

10.129.0.0/16
*.htb
```

The shipped `lab.md` already contains the RFC 1918 ranges and `*.htb`.

### Cloud account

Wildcards on shared cloud domains are dangerous. `*.amazonaws.com` would
authorize every bucket on the platform. List the specific assets instead:

```markdown
# Program: cloud

## In-scope

my-bucket.s3.eu-central-1.amazonaws.com
203.0.113.0/24
```

### Malware or binary analysis

There is usually no network target. Local reversing commands contain no host,
so the gate allows them:

```
objdump -d sample.exe
strings -n 8 sample.bin
radare2 -A sample.bin
python -c "import capstone; ..."
```

Add the sources you download samples or reports from to `noise.json`:

```json
["abuse.ch", "virustotal.com", "hybrid-analysis.com", "malshare.com"]
```

The gate still cannot see what a sample does at runtime. Isolate untrusted
binaries at the network layer.

### CVE or vendor research

Running a local PoC against a local build does not touch the vendor. Add the
reference sites to `noise.json`:

```json
["nvd.nist.gov", "cve.org", "mitre.org", "first.org"]
```

Add the vendor's own assets only when you are authorized to test them live.

## Adding a lab TLD

By default only `htb`, `local`, `lab`, `test`, and `internal` are accepted as
single-label wildcards. For any other lab TLD:

```powershell
setx BTG_LAB_TLDS "corp,vuln,devlab"
```

Then `*.corp`, `*.vuln`, and `*.devlab` are accepted in program files. `*.com`
remains rejected, because it would authorize a large part of the public
Internet.

`BTG_LAB_TLDS` is read by both `hooks/scope_gate.py` and
`scripts/scope_add.py`.

## Choosing the decision policy

| Situation | Setting |
|---|---|
| Contractual scope, no tolerance for mistakes | `force_ask` (default) |
| Personal lab, cached approvals acceptable | `BTG_OUT_OF_SCOPE=ask` |
| Private lab addresses should always pass | leave `BTG_GATE_PRIVATE_IPS` unset |
| Private addresses should be checked against the registry | `BTG_GATE_PRIVATE_IPS=1` |

## Starting from zero

1. Create a program file with the assets you are authorized to touch.
2. Run `python scripts/scope_add.py --program <file> <asset>` for anything you
   prefer to add from the shell.
3. Add documentation, social, registry, and sample sources to `noise.json`.
4. Run `python tests/test_gate.py` to confirm the gate still behaves.
5. Register the hook in `hooks.json` and reload Antigravity.

If a legitimate target prompts, the gate is telling you it is not in the
registry. Add it. Do not switch the decision to `allow`.
