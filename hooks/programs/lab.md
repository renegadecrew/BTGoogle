# Program: lab

Local and lab ranges. Private addresses are lab noise by default; the CIDRs
below make authorization explicit so the gate still recognizes them when
private-IP gating is enabled.

## In-scope

10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
*.htb
*.local

## Out-of-scope

