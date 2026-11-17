# Scope model

Authorization is derived from files. There is no hidden state and no database:
the gate reads every `*.md` file in the programs directory on each invocation.

## Program files

A program is a Markdown file with an `## In-scope` section and an optional
`## Out-of-scope` section:

```markdown
# Program: example-public-program
expires: 2027-01-31

## In-scope

*.example.org
example.org
10.0.0.0/8

## Out-of-scope

legacy.example.org
```

Rules:

- Lines under `## In-scope` and `## Out-of-scope` are assets.
- Assets cannot contain spaces or tabs. Prose is ignored.
- The `## Out-of-scope` section is optional.
- `expires:` is optional. After that date the program is ignored.
- The file name is the program slug.

## Asset syntax

| Form | Example | Matches |
|---|---|---|
| Exact host | `example.org` | `example.org` only |
| Wildcard | `*.example.org` | `a.example.org`, `a.b.example.org` |
| IPv4 | `203.0.113.10` | That address |
| CIDR | `10.0.0.0/8` | Any address in the range |

A wildcard does **not** cover its own apex. `*.example.org` matches
`www.example.org` but not `example.org`. That is deliberate: a program that
lists only a wildcard has not authorized the apex.

Single-label wildcards are accepted only for lab-style TLDs:

```
htb  local  lab  test  internal
```

`*.htb` is valid. `*.com` is rejected at load time, because it would authorize
a large part of the public Internet.

## Matching precedence

For a given host, each program is evaluated independently:

1. If the host matches an out-of-scope asset, the program **excludes** it.
2. Otherwise, if the host matches an in-scope asset, the program **authorizes** it.
3. Otherwise, the program says nothing.

Across programs:

- Any authorization wins, unless a program explicitly excludes the host.
- Exclusion is checked before authorization within the same program.

Example:

```markdown
## In-scope
*.example.org

## Out-of-scope
legacy.example.org
```

`legacy.example.org` is excluded even though the wildcard covers it. An explicit
exclusion always carves out.

## Lab ranges

Private, loopback, and link-local addresses are treated as lab noise by
default: the gate does not extract them, so they never prompt. The shipped
`lab.md` also authorizes the RFC 1918 ranges explicitly, so the gate still
recognizes them when private-IP gating is enabled with
`BTG_GATE_PRIVATE_IPS=1`.

`lab.md` also authorizes `*.htb` and `*.local`, which covers the hostnames used
by common lab platforms.

## What this model does not do

- It does not resolve DNS. Matching is purely textual against the asset list.
- It does not track WHOIS or certificate ownership.
- It does not infer scope from chat history. A program must be added explicitly.
- It does not expire assets individually. Expiry is per program file.

Those omissions are intentional: every inference is a place where an
out-of-scope host could be authorized by accident.
