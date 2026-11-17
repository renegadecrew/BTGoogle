# Test payloads

Each file is a complete `PreToolUse` stdin payload. Pipe one into the gate:

```powershell
Get-Content tests/payloads/ask-out-of-scope.json -Raw | python hooks/scope_gate.py
```

| File | Expected decision |
|---|---|
| `allow-in-scope.json` | `allow` |
| `ask-out-of-scope.json` | `force_ask` |
| `deny-destructive.json` | `deny` |

These three files are examples only. The full matrix lives in
`tests/test_gate.py`.
