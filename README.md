> **Frozen 2026-10-12.** The TypeScript of this repository that socialweb-computer uses now lives in
> the socialweb-computer-kcp monorepo (https://github.com/publicdomainrelay/kcp-vm), under
> `ts/did-key-ingress-proxy/`, with its git history. That copy is the source of truth. Do not change these
> paths here, and do not sync changes back:
>
> `hono-did-key-ingress-proxy/`, `lexicons/`, `lib/` (except `lib/common/tunnel-subscriber-common`), `test/`. The tunnel CLIs stayed here.
>
> Make every change to them in socialweb-computer-kcp. Read its AGENTS.md first.

