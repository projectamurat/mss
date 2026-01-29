# mss — macOS Socket Statistics

A small CLI for socket statistics on macOS, similar in spirit to Linux `ss`. Uses `netstat -an` and libproc (process ↔ socket mapping).

## Build & Install

```bash
make
make install          # installs to /usr/local/bin (override with PREFIX=...)
make clean
```

## Usage

```text
mss [options]
  -t    TCP only
  -u    UDP only
  -l    Listening sockets only
  -n    Numeric (no resolution) [default]
  -p    Show PID/process (partial; may require privileges)
  -h    Help
```

## Examples

```bash
mss              # all sockets (numeric)
mss -t           # TCP only
mss -u           # UDP only
mss -l           # listening only
mss -t -l        # TCP listening
mss -p           # with PID/process column
```

## Data Sources

- **Socket list:** `netstat -an`
- **PID/process (-p):** libproc (`proc_listallpids`, `PROC_PIDLISTFDS`, `PROC_PIDFDSOCKETINFO`)

## Limitations (macOS)

- No TCP state internals (e.g. Linux `ss -i`)
- No BPF socket introspection
- No exact perf counters
- **-p** is partial: only processes you can inspect get a PID/name; others show `-`

## License

MIT — Copyright (c) 2026 Murat Kaan Tekeli. See [LICENSE](LICENSE).
