# 06 — Directory Listing Exposure

## What it is

Directory listing (sometimes called "directory indexing" or "autoindexing") is a web server
feature that, when no index file (`index.html`, `index.php`, etc.) is present in a requested
directory, automatically generates and returns an HTML page listing every file and subdirectory
at that path — instead of returning a 403/404.

As PortSwigger's own documentation on this topic notes: directory listing by itself is not
necessarily a vulnerability. The actual security issue is what it **exposes** combined with the
*absence of proper access control* on the files it reveals — backup files, configuration files,
old/unlinked admin scripts, temporary files, and crash dumps that were never meant to be
discoverable.

## Why it happens

- Default web server configuration. Apache's `Options +Indexes` directive (or its equivalent
  default behavior on certain distros/configs) and IIS's "Directory Browsing" feature are both
  **off by default in modern hardened configs but historically on by default** in many out-of-the
  -box installs, and are frequently re-enabled accidentally during troubleshooting and never
  turned back off.
- Static asset directories (uploads, exports, backups, logs) are served directly by the web
  server without an explicit deny-by-default rule.
- Developers leave temporary editor backup files (`.bak`, `~`-suffixed files) inside web-served
  directories, and listing makes them trivially discoverable even without guessing filenames.

## How to test, piece by piece

### Step 1 — Check `robots.txt` and `sitemap.xml` first

```bash
curl -s https://target.example.com/robots.txt
```

- `curl -s` — silent mode HTTP GET request.
- These files are not directly evidence of directory listing, but they often **name** sensitive
  directories the site owner wanted crawlers to skip (e.g., `Disallow: /backup/`) — which tells
  you exactly where to point your directory-listing check next, since a disallowed path in
  `robots.txt` is a strong hint of something the owner considered sensitive.

### Step 2 — Directly request a likely directory path with a trailing slash

```bash
curl -s https://target.example.com/backup/ | grep -iE "index of|directory listing"
```

- `https://target.example.com/backup/` — requesting the bare directory path (trailing slash) is
  what triggers autoindexing if it's enabled and no index file exists there.
- `grep -iE "index of|directory listing"` — Apache's autoindex output conventionally starts with
  the literal text "Index of /backup/", and IIS's equivalent often contains "Directory Listing
  Denied" (negative) or simply renders a table of links (positive) — this grep is a quick
  heuristic to confirm the response is in fact an autoindex page rather than a normal page or a
  403 error.

### Step 3 — Use content discovery to find listing-enabled directories you haven't guessed

```bash
gobuster dir -u https://target.example.com -w /usr/share/wordlists/dirb/common.txt -x bak,old,zip,tar.gz -t 40
```

- `gobuster dir` — runs Gobuster in directory/file brute-force mode.
- `-u https://target.example.com` — the target base URL.
- `-w /usr/share/wordlists/dirb/common.txt` — the wordlist of candidate directory/file names to
  try (a standard, commonly pre-installed wordlist on Kali).
- `-x bak,old,zip,tar.gz` — append each of these extensions to every wordlist entry as additional
  guesses (e.g., trying both `/config` and `/config.bak`), since backup-file naming conventions
  are exactly what you're hunting for in this sub-category.
- `-t 40` — use 40 concurrent threads, balancing speed against the risk of overwhelming the
  target or tripping a WAF/rate-limit.

### Step 4 — If listing is confirmed, manually enumerate and pull every interesting file

```bash
wget -r -np -nH --cut-dirs=1 https://target.example.com/backup/
```

- `wget -r` — recursive download, following links found on the listing page.
- `-np` — "no parent": don't ascend above the starting directory (stops `wget` wandering outside
  `/backup/` into unrelated parts of the site).
- `-nH` — "no host directories": don't create a local folder named after the target hostname,
  keeping the downloaded structure flatter.
- `--cut-dirs=1` — strip the first directory level (`backup`) from the local save path, so files
  land directly in your working directory instead of inside a nested `backup/` folder.
- `https://target.example.com/backup/` — the listing-enabled directory to mirror locally for
  offline review.

## Cross-reference: source code disclosure via backup files (PortSwigger lab mapping)

This file directly corresponds to PortSwigger's **Information disclosure** topic lab
**"Source code disclosure via backup files"**: the lab's intended solve path is exactly
Steps 1→2 above — checking `robots.txt`, finding a `/backup` directory it references, finding
listing enabled (or simply guessable filenames) there, and pulling a `.bak` file containing a
hard-coded database password from the leaked source code.

It also relates to PortSwigger's **"Information disclosure in version control history"** lab,
which is the same underlying concept (an unintentionally exposed directory — in that case `.git`)
but exploited via Git tooling rather than simple file download:

```bash
wget -r https://target.example.com/.git/
cd target.example.com
git log --oneline
git diff <commit-hash>
```

- `wget -r https://target.example.com/.git/` — recursively mirror the exposed `.git` metadata
  folder (same `wget -r` concept as Step 4 above, simplified here without the path-flattening
  flags since you want the real `.git` folder structure preserved for Git to recognize it).
- `git log --oneline` — once inside the downloaded `.git` repository, list the commit history in
  a condensed one-line-per-commit format, to scan for suspicious commit messages (e.g.
  "Remove admin password from config").
- `git diff <commit-hash>` — show the exact line-by-line changes introduced by a specific commit;
  this is how you recover a password that was removed in a later commit but still exists in the
  diff/history of an earlier one — deleting a secret from the current file does **not** delete it
  from version-control history.

## Real-world notes

- Directory listing exposure on object storage (S3/GCS) buckets is functionally the same concept
  applied to cloud storage rather than a web server filesystem — see file `07` for the dedicated
  cloud-storage treatment and the **S3Scanner** tool, which essentially automates Step 2/3 above
  but against cloud bucket naming conventions instead of local web paths.
- In real engagements, directory listing on a *static asset* folder (images, CSS) is usually
  treated as informational/no-impact. Directory listing on a *backup, log, config, or upload*
  folder is routinely escalated to high severity because of what it predictably contains.
- Many CDNs and reverse proxies cache directory listing pages just like any other content —
  meaning that even after the misconfiguration is fixed at the origin, a cached listing page can
  remain publicly accessible for a period of time, which is worth checking and reporting
  separately during remediation verification.

## What's next

Continue to `07_Cloud_Storage_and_Infrastructure_Misconfiguration.md`.
