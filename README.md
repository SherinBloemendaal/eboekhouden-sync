# EB Sessions Sync

A small, self-hostable, end-to-end encrypted sync server for [EB Sessions](https://github.com/SherinBloemendaal/eboekhouden-extension), the Chrome extension for e-Boekhouden.

> Status: in development. The protocol is specified in [docs/SPEC.md](docs/SPEC.md) (draft, independently reviewed once). There is no code to deploy yet.

## What it will do

- Share extension data (groups, hidden lines, classifications, settings) between colleagues who work in the same e-Boekhouden administration, per profile.
- Teamwerk: see which page colleagues are on, their cursors and the line they have open, live.
- Everything is end-to-end encrypted. The server knows who you are and what you may access, but it cannot read your data.

## How it will run

A Cloudflare Worker with D1 and Durable Objects, plus a small dashboard for accounts, devices, profiles, members, the audit log, export and deletion. You host it yourself in your own Cloudflare account.

## License

MIT
