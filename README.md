# mustardwatch

Run a command, tracing it to detect files it uses (or might use), and watch
those files for changes. When a file changes, rerun the command.

`mustardwatch` is implemented using the Linux `ptrace` API (like `strace`). It
currently only supports x86-64 Linux.

## Building

Run `./make` and then use or install `./build/mustardwatch`.

## Documentation

See `mustardwatch --help`:

```
Usage: mustardwatch [OPTION...] COMMAND [ARG...]
Run a command, tracing it to detect files it uses (or might use), and watch
those files for changes. When a file changes, rerun the command.

File events generated while the command is running are ignored, as are events
in common directories (/bin, /dev, /etc, /lib, /proc, /sys, /tmp, /usr).

Files used by subprocesses are also tracked (but note that all subprocesses
are killed when the main process exits).

Options:
  -c, --clear        clear screen before running program
  -d, --directories  watch directories as well as regular files
  -o, --out=FILE     rather than respawning the process when files change, write
                       out a list of watched files to a file, then exit
  -v, --verbose      show verbose output (watched files and events)
                       (use multiple times for more verbose output)
      --help         print this message
```

For more details, see the comments in `mustardwatch.c`.
