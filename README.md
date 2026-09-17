# Guard
This Project is dedicated for the implementation of the Guard - a directory monitoring tool that monitors a particular directory in real time and commits changes on the Database along with the timestamp using Python.

<br>
Alias - Guard.

File integrity monitoring for a directory tree.

Guard watches a folder, works out what actually changed, decides how much that
change matters, and writes it to an append-only log you can query later. It
also spots patterns no single event reveals — like a few hundred files all
turning into ciphertext at once.

![The live dashboard](docs/dashboard.png)

[![CI](https://github.com/YOUR-USERNAME/guard/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platforms](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## The problem this solves

A naive directory watcher is unusable, and it fails in a specific way. The
operating system reports that a file "was modified" constantly — every save,
every backup sweep, every metadata poke, usually several times for one edit.
Log all of it and you get thousands of lines a day that nobody reads.

Guard treats the OS notification as a **hint**, not a fact. When one arrives it
waits for the flurry to stop, re-reads the file, hashes it, and compares against
what it recorded last time. Only a real difference becomes an event.

```
$ touch README.md          # the OS reports a modification
                           # Guard records nothing — the bytes are identical
```

That one decision is the difference between an audit log and a firehose.

---

## What it does

### Watches, and explains itself

```
$ guard watch ./project

  Guard 2.0.0
  File integrity monitoring
  ──────────────────────────────────────────────────────

  No baseline yet — taking one first so changes can be compared.
  Fingerprinted 5 files.

  Watching /home/you/project
  Tracking 5 files. Press Ctrl+C to stop.

16:52:07  · modified    src/server.py   −3 B  78303cf96e98
16:52:07  + modified    config/app.yaml   −1 B  f867fe538171
16:52:08  ! created     install.sh   a8076d3d28d2
             created an executable file
16:52:09  ! deleted     src/auth.py
             file removed
16:52:10  ✕ modified    .env   −6 B  538507d218f3
             modified under a path holding credentials or access control
```

A `touch README.md` happened in the middle of that run. It produced no line,
because nothing changed.

Every event carries a severity and a reason. An alert you cannot interpret is
not much better than no alert, so the rules always say what they saw:

| | When | Example |
|---|---|---|
| `✕` critical | credentials touched, a file gained the execute bit, contents became unreadable | `permissions changed to executable (rw-r--r-- → rwxr-xr-x)` |
| `!` warning | a binary changed, a file was deleted or truncated | `shrank from 48.2 KB to 12 B` |
| `+` notice | a config file, a new file, a rename | `created a configuration file` |
| `·` info | everything else | `contents changed` |

### Catches what happened while it was off

A live watcher cannot see changes made before it started. `baseline` records a
known-good fingerprint of the whole tree, and `audit` compares the tree against
it whenever you like — after a restart, in a cron job, or as a CI step.

```
$ guard audit ./project

  Comparing /home/you/project against the baseline from 2026-09-17T16:51:54+00:00

  + added     .env  15 B
  ~ changed   README.md  rw-r--r-- → rwxr-xr-x
  ~ changed   src/auth.py  7882354b8f7b → 72edb449bfc5
  − removed   src/models.py  was 31 B

  1 added, 2 changed, 1 removed.
```

Note the second line: same bytes, different permissions. A tool that only
compared hashes would have missed it. `audit` exits non-zero when anything
differs, so cron and CI notice without anyone reading the output.

### Notices ransomware

Any one file becoming unreadable is unremarkable. Two hundred files becoming
unreadable in thirty seconds is an attack in progress. That shape does not
exist in any single event, so Guard keeps a short memory across them.

The test is built on **entropy**. Shannon entropy measures how unpredictable a
file's bytes are, from 0 to 8 bits per byte. English prose sits near 4.5.
Encrypted or compressed data is close to 8, because every byte value is equally
likely. So when a document goes from 4.2 to 7.9, something encrypted it — and
when twenty documents do it inside half a minute, Guard says so:

```
✕ alert   20 files became unreadable within 30 seconds —
          this is what ransomware encrypting a folder looks like
```

### Shows it live

`guard watch ./project --dashboard` also serves a local web page on port 8420.
The page is one HTML file with no build step and no framework; it polls two
JSON endpoints once a second. Click a severity to filter; scroll up and it
stops following so you can read.

---

## How it works

The five ideas worth reading the source for.

**A fingerprint, not an event.** Each file is reduced to size, SHA-256,
permission bits, modification time and entropy. Comparing two fingerprints
answers every question the tool asks: did the content change, did the
permissions change, did the content become unreadable. Section 2 of `guard.py`.

**Debouncing.** Saving a file in most editors writes a temporary file, renames
it over the original, then updates the timestamp — three to five notifications
for one save. Guard collects notifications and only examines a path once it has
been quiet for 400 ms. One save, one event. Section 6.

**Ignoring its own tail.** Guard's database lives on disk, often inside the
folder being watched. Without an explicit skip, writing an event causes a file
change, which causes an event, which causes a write. The default ignore list
exists for churn from editors and build tools, but `guard.db` is on it for this
reason specifically.

**Entropy jumps, not volume.** The ransomware check counts one thing: files
that were readable and now are not. An earlier version counted every busy file
and asked what fraction looked encrypted — that fails twice over, because a
compile writes hundreds of files and drowns the signal, and the fraction test
does no real work anyway since build output is ordinary readable text. Files
that were *already* near-random (`.zip`, `.jpg`, `.mp4`) are excluded entirely,
so copying a photo library in is not an incident. Section 5.

**One connection, one lock.** Three threads touch SQLite: the watchdog
observer, the processing loop, and the dashboard's web server. Guard holds a
single connection with a lock around every use of it, in write-ahead logging
mode so the dashboard can read while the watcher writes. One connection per
thread would be marginally faster and considerably harder to be sure about.

---

## Running it

```bash
git clone https://github.com/YOUR-USERNAME/guard.git
cd guard
pip install -r requirements.txt

python guard.py watch ./some-folder --dashboard
```

Python 3.10 or newer. One dependency: `watchdog`. Everything else — the
database, the web server, the hashing — is the standard library.

```bash
python guard.py watch ./project                    # watch and log
python guard.py watch ./project --dashboard        # ... and serve the live page
python guard.py watch ./project -m warning         # only show warnings and above
python guard.py watch ./project -i '*.log'         # skip an extra pattern

python guard.py baseline ./project                 # record a known-good state
python guard.py audit ./project                    # compare against it

python guard.py history ./project -n 50            # recent events
python guard.py history ./project -p src/ -m warning
python guard.py stats ./project                    # a summary
```

### As a scheduled integrity check

`audit` exits `1` when anything differs, so it drops into cron or CI as-is:

```bash
0 3 * * *  cd /srv/app && guard audit . -d /var/lib/guard.db || mail -s "app changed" me@example.com
```

---

## Layout

Two files do the work.

```
guard.py          the whole engine — 9 numbered sections, in the order data flows
dashboard.html    the live page: no build step, no framework
test_guard.py     74 tests
```

`guard.py` is one file on purpose. It reads top to bottom:

| Section | What lives there |
|---|---|
| 1. Settings | what to watch, what to skip, how sensitive to be |
| 2. Fingerprints | size, hash, permissions, entropy |
| 3. Storage | the SQLite schema and every query in one place |
| 4. Judgement | the severity rules, most serious first |
| 5. Burst detection | the ransomware heuristic |
| 6. The watcher | raw OS events in, verified changes out |
| 7. Terminal output | what you see while it runs |
| 8. Dashboard | the HTTP server and its two JSON endpoints |
| 9. Commands | the command line |

---

## Tests

```bash
pip install pytest ruff
pytest
ruff check guard.py test_guard.py
```

74 tests, about 2.5 seconds, no network and no browser. CI runs them on
Windows, macOS and Linux against Python 3.10 and 3.12.

Most of them cover the noise filter, the severity rules, the burst heuristic
and the offline audit. Only two start a real watchdog observer, because
filesystem notifications are inherently racy — the logic they cover is tested
directly elsewhere.

Three tests exist because they caught real bugs, and they say so in their
docstrings:

- `test_the_first_alert_is_never_swallowed_by_the_cooldown` — the cooldown used
  `0.0` as a "never alerted yet" marker. On Linux `time.monotonic()` counts from
  system boot, so `0.0` is a real timestamp, and during the first minute of
  uptime the very first ransomware alert was silently suppressed.
- `test_ordinary_activity_beforehand_cannot_mask_a_sweep` — nine innocent edits
  just before an attack pushed the old fraction test under its threshold and the
  alert never fired. That test is what forced the redesign described above.
- `test_permission_change_alone_is_still_reported` — the noise filter drops
  anything whose hash is unchanged, which would have silently swallowed
  `chmod +x`, the single most security-relevant change a file can undergo.

---

## Limits worth knowing

- **Guard sees what changed, not who changed it.** Attributing a write to a
  process needs audit subsystem hooks — `auditd`, ETW, or FSEvents with
  elevation — which is a much larger piece of work.
- **The ransomware check is a heuristic**, and heuristics are wrong sometimes.
  Encrypting a folder of your own files on purpose will trigger it. It is a
  smoke alarm, not a verdict.
- **Very large trees cost memory on first baseline.** A fingerprint per file is
  small, but a million files is a million rows.
- **Symbolic links are not followed**, so a link into a watched folder from
  outside is invisible.

---

## Where it came from

v1 was a 90-line script that logged every raw watchdog event — including all the
duplicates — to a table with three columns, and printed them. v2 keeps the
shape of that idea and adds the verification step that makes the log worth
reading, plus severities, baselines, offline auditing, burst detection, a
dashboard and a test suite.

## Ideas not yet built

- Process attribution via `auditd` / ETW
- Signed log segments, so the audit trail can prove it was not edited
- Watching several folders in one run
- Desktop notifications on critical events
- A `guard diff <path>` showing what changed inside a text file, not just that
  it did

## License

MIT. See [LICENSE](LICENSE).
