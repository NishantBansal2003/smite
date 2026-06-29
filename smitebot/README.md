# smitebot

`smitebot` is the Smite automation CLI. It is intended to orchestrate common fuzzing workflows and reduce manual setup/operations.

## Install

Install `smitebot` once from this repository:

```bash
cargo install --path smitebot
```

After install, run it directly:

```bash
smitebot doctor --aflpp-path ~/AFLplusplus
smitebot doctor campaign.toml
```

## Configuration

Campaign settings are stored in a TOML file. See [`sample-campaign.toml`](sample-campaign.toml) for a complete example.

| Field        | Required | Description                                                          |
| ------------ | -------- | -------------------------------------------------------------------- |
| `target`     | yes      | Lightning implementation to fuzz (`lnd`, `cln`, `ldk`, or `eclair`). |
| `scenario`   | yes      | Scenario binary selected by the workload Dockerfile.                 |
| `aflpp_path` | yes      | Path to the AFL++ source tree.                                       |
| `smite_dir`  | yes      | Path to the smite repository root.                                   |
| `runners`    | yes      | Number of parallel AFL++ instances to launch (must be at least 1).   |
| `seed_dir`   | no       | Directory containing seed inputs; omit to start from an empty corpus.|
| `output_dir` | yes      | AFL++ output directory for findings and stats.                       |
| `sharedir`   | yes      | Nyx shared directory path; created automatically by `smitebot start`.|
| `image`      | no       | Docker image tag override; defaults to `smite-<target>-<scenario>`.  |
| `afl_env`    | no       | Extra environment variables passed to AFL++ instances.               |
| `afl_flags`  | no       | Extra CLI flags appended to `afl-fuzz`.                              |

## Commands

### smitebot start

`smitebot start` launches a fuzzing campaign in the background. It builds the Docker image, sets up the Nyx sharedir, and spawns parallel AFL++ instances.

```bash
smitebot start campaign.toml
```

For IR scenarios (scenario names starting with `ir`), the required AFL++ custom mutator environment variables are injected automatically.

Campaign state is saved to `~/.smitebot/runs/<campaign-id>/state.json` for use by future `stop` and `status` commands.

### smitebot config

`smitebot config` validates a campaign configuration file, reports the resolved settings, and checks that referenced paths exist on disk.

```bash
smitebot config sample-campaign.toml
```

### smitebot build

`smitebot build` builds Smite workload Docker images. It can be used standalone with CLI flags or with a campaign config file. When a config file is provided, CLI flags override individual values.

```bash
smitebot build --target lnd --scenario encrypted_bytes
smitebot build campaign.toml
smitebot build campaign.toml --target cln
smitebot build campaign.toml --coverage --no-cache
```

Flags:

- `--target`: Target implementation to build. Required when no config file is provided.
- `--scenario`: Scenario binary for the workload Dockerfile. Required when no config file is provided.
- `--smite-dir`: Path to the smite repository root; defaults to `.` when no config file is provided.
- `--coverage`: Build a coverage-instrumented image.
- `--image`: Docker image tag; overrides the config value and the default smite naming convention.
- `--no-cache`: Perform a clean rebuild without using cached Docker layers.

By default, image tags follow the existing Smite convention:

```text
smite-<target>-<scenario>
smite-<target>-<scenario>-coverage
```

### smitebot doctor

`smitebot doctor` validates host prerequisites before running Smite campaigns. It can be used standalone with CLI flags or with a campaign config file. When a config file is provided, CLI flags override individual values.

```bash
smitebot doctor --aflpp-path ~/AFLplusplus
smitebot doctor campaign.toml
smitebot doctor campaign.toml --json
smitebot doctor campaign.toml --aflpp-path ~/other-aflpp
```

## Checks

- `x86_64` architecture
- CPU virtualization enabled (`vmx` or `svm`)
- `/dev/kvm` is present and openable
- Docker daemon is reachable (`docker version`)
- AFL++ built with Nyx support (`libnyx.so` under `--aflpp-path`)
- VMware backdoor is enabled
- AFL++ tools (`afl-fuzz`, `afl-cmin`, `afl-tmin`, `afl-whatsup`) are executable under `--aflpp-path`
- Required host tools (`bash`, `python`, `python3`)
- Required Smite scripts are present and executable
- Required workload Dockerfiles are present

## JSON output

By default, output is in a human readable format. The `--json` flag changes output to structured JSON:

```json
{
  "checks": [
    { "name": "x86_64 architecture", "passed": true },
    { "name": "Docker daemon reachable", "passed": false, "reason": "docker version: exit status: 1" }
  ],
  "overall": false
}
```
