# Run IMMUNEX locally

From PowerShell in this folder, run:

```powershell
.\start_local.ps1
```

Open http://127.0.0.1:8000 in a browser. The script builds the React interface when needed, then starts its local backend. No Docker, Ollama, WireGuard, remote PC, or peer connection is required.

Use `Ctrl+C` to stop the foreground server, or run `./stop_local.ps1` from a second PowerShell window.

The local runtime is intentionally simulation-only. It preserves the frontend/API workflow and records alerts in memory, but it does not perform containment actions or claim to load the unavailable model artifacts.
