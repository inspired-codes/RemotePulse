# Security policy

RemotePulse runs PowerShell on people's machines, so we take security reports seriously and are grateful for them.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately, in either of these ways:

- **GitHub:** use **Report a vulnerability** on the repository's [Security tab](https://github.com/inspired-codes/RemotePulse/security).
- **Email:** security@inspired.codes

Please include:
- what you found and which component it affects (App, Hub, Worker, installer, or the hosted service);
- steps to reproduce, or a proof of concept;
- the version (the Worker's local page and the App's header show it; the Hub reports it at `/api/pairing/status/health`);
- what an attacker could do with it, as you see it.

We'll confirm that we received your report, keep you updated while we work on a fix, and credit you when the fix is released, unless you'd rather stay anonymous.

## Supported versions

We fix security issues in the latest release of the App, the Hub and the Worker. Re-running the install one-liner, or the App's **Update Worker** button, updates a Worker.

## Testing against the hosted service

Good-faith research is welcome. When you test against psrun.inspired.codes:
- use only your own machines, accounts and pairings;
- don't access, change or delete other people's data;
- don't degrade the service for others (no load or denial-of-service testing).

## Scope and known limits

The [Security & Trust page](https://psrun.inspired.codes/security) describes the security model and the limits we already know about: for example, that the same server delivers the App and the Worker downloads. Reports that show those limits are worse than described there are in scope.
