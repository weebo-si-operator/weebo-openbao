# weebo-openbao

Kubernetes operator managing Openbao objects as CRDs, built on
[weebo-operator-kit](https://github.com/weebo-si-operator/weebo-operator-kit).

| Kind                  | What it does                                                                 |
| --------------------- | ---------------------------------------------------------------------------- |
| `OpenbaoInstance`     | The OpenBao server and the operator's login (Kubernetes auth, root)          |
| `OpenbaoNamespace`    | An OpenBao namespace: its KV v2 mounts (`orgs`, `users`) and auth backends   |
| `OpenbaoAccessLevel`  | A level of access (capabilities on data and metadata), shared by both models |
| `OpenbaoSpaceLayout`  | The human model: role → namespace → level, personal spaces, group aliases    |
| `OpenbaoOrganization` | An organization, its access following the layout                             |
| `OpenbaoAccessGrant`  | The machine model: ServiceAccounts, and the rules they get in a namespace    |

All cluster-scoped. Design: weebo-operator-kit RFC 0007 (declarative OpenBao
spaces). The reconcilers of the spaces' kinds are being written; only
`OpenbaoInstance` is reconciled today.

## Layout

Hexagonal, one crate per layer, same rules as every weebo operator:

| Crate               | Holds                                                                    |
| ------------------- | ------------------------------------------------------------------------ |
| `domain`            | the reason codes (`reason_codes!`), no dependency                        |
| `api`               | the CRD types (`#[derive(CustomResource)]`), the kit's shared field types |
| `application`       | the `SpaceAdmin` port and the `reconcile_*` use cases                    |
| `adapters-outbound` | `OpenbaoSpaceAdmin` on OpenBao's API (the kit's `VaultSession`), and the factory logging in per instance |
| `adapters-inbound`  | the controllers and the webhook router (health routes only for now)       |
| `operator`          | the binary: telemetry, leader election, webhook server, controllers      |
| `crdgen`            | writes `deploy/crd/` from `api` (CRDs, and `links.json` for the CRD IDE)  |
| `testkit`           | envtest and fakes for the integration tests                               |

`deploy/charts/weebo-openbao` is a thin chart on the kit's library
chart: `templates/_params.tpl` holds what is the operator's own (group,
kinds, env, egress), `values.yaml` follows the kit's values contract.

## First steps

The project is licensed `Apache-2.0` (`Cargo.toml`, the image's labels):
add the matching `LICENSE.md`.

```bash
task init     # toolchain (mise) and mise.lock — commit it, cog.toml from the kit, git hooks
task doctor   # envtest prerequisites
task recu     # CRDs (crdgen) and their copies in the chart
task test:all # unit, contract and envtest tests — creates Cargo.lock: commit it
```

## Tasks

```bash
task lint        # fmt --check, clippy -D warnings, actionlint, hadolint
task lint:helm   # helm lint + the kit's smoke renders
task test        # unit + contract tests
task test:all    # + envtest integration tests
task coverage    # cargo llvm-cov, fails under 85%
task audit       # cargo-deny + trivy + trivy config
task kit:sync TAG=vX.Y.Z  # move to another kit release (crates, tasks, CI, chart, cog.toml)
```

`lint`, `audit`, `coverage`, `doctor` and the chart tasks are the kit's
(`tasks/*.yaml`, included remotely and pinned by checksum); CI calls the
kit's reusable `checks.yml`.
