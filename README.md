# RemotePulse

Run PowerShell scripts on your Windows and Linux machines from your phone, through a relay that can't read or forge your commands.

- **The App** is a Blazor WebAssembly PWA on your phone. It holds your keys and signs and encrypts every command.
- **The Hub** is a blind relay: an ASP.NET Core API that stores only ciphertext and verifies signatures.
- **The Worker** is a small service (Windows Service or systemd) on each machine. It polls the Hub over outbound HTTPS, so you open no ports, and it runs only commands signed by a phone it is paired with.

The hosted service runs at [psrun.inspired.codes](https://psrun.inspired.codes/).

## Security model

The full explanation, including what we don't protect against, is on the [Security & Trust page](https://psrun.inspired.codes/security). In short:

- **End-to-end encryption.** Scripts and results are encrypted between your phone and your machine. The Hub only ever handles ciphertext.
- **Signed commands.** A Worker runs only commands signed by a paired phone, and it rejects stale or replayed ones itself, so a compromised Hub can't send it commands.
- **Pairing that the Hub can't intercept.** You pair by scanning a QR code shown on the machine itself. The QR secret never leaves the two devices, each side checks the other's key, and both screens show the same 6-digit safety code. If anyone swaps a key on the way, pairing fails.

**Honest limits.** Today the same server that relays your commands also delivers the App and the Worker downloads, so you trust it at the moment you install or load them. Publishing this repository, with release builds you can verify, is the first step to closing that gap. Signed Worker updates are next. The Hub also sees metadata: which phone talks to which machine, when, how much, and from which IP address.

Design details: [docs/communication.md](docs/communication.md) (topology, wire format, flows), [docs/architecture.md](docs/architecture.md) (code layout) and [docs/specs/pairing-v2-key-binding-spec.md](docs/specs/pairing-v2-key-binding-spec.md).

## Verify a Worker download

Starting with the first public release, every Worker release on the [Releases page](https://github.com/inspired-codes/RemotePulse/releases) is built by the [Release workflow](.github/workflows/release.yml) from a tagged commit, with a signed build-provenance attestation. To check that a zip, whether from a Release or from a RemotePulse server, was built from this repository:

```bash
gh attestation verify RemotePulse-Worker-windows-x64.zip --repo inspired-codes/RemotePulse
```

Each Release also lists the SHA-256 of both zips.

## Build and test

You need the .NET SDK version pinned in [global.json](global.json). The tests need no database and no installed service.

```bash
dotnet build RemotePulse.slnx
dotnet test RemotePulse.slnx
```

To package the Worker zips locally (PowerShell 7):

```bash
pwsh ./deploy/Package-WorkerRelease.ps1
```

## Contributing

**Issues are welcome:** bug reports, questions and ideas. **We don't accept pull requests at the moment.** RemotePulse is offered under the AGPL and under a commercial license, which requires that inspired.codes holds the rights to all of the code.

**Security issues:** please don't open a public issue. See [SECURITY.md](SECURITY.md).

## License

RemotePulse is licensed under the [GNU Affero General Public License v3.0](LICENSE.txt). If you run a modified version as a network service, the AGPL requires you to offer its source to your users. For a commercial license, contact inspired.codes.

The name "RemotePulse" and the RemotePulse logo are not covered by the license.
