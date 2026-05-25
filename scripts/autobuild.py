#!/usr/bin/env python3
"""Autobuild a Solidity project so knowdit can ingest it.

Detects whether the project uses Hardhat or Foundry (or both), then runs
the appropriate dep-install + compile so that on success the project has
either `artifacts/build-info/*.json` (Hardhat) or `out/...` (Foundry).

Default behavior: every CLI binary the script invokes (`npm`, `npx`,
`yarn`, `pnpm`, `forge`, `git`) is resolved via `$PATH`. Pass the
matching `--<name> <abs-path>` flag only when you need to override the
PATH default — typical reason: multiple node versions managed by nvm
where you want to pin one specific build.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# Substring solc / forge prints when the legacy codegen runs out of EVM
# stack slots. The fix is always to flip on solc's IR pipeline; if that
# also fails the source is genuinely too hairy and the user has to
# refactor. Matched verbatim against forge stderr.
FORGE_STACK_TOO_DEEP_MARKER = "Stack too deep"


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

class Backend(str, Enum):
    HARDHAT = "hardhat"
    FORGE = "forge"


HARDHAT_CONFIG_NAMES = ("hardhat.config.js", "hardhat.config.ts",
                        "hardhat.config.cjs", "hardhat.config.mjs")
FOUNDRY_CONFIG_NAMES = ("foundry.toml",)

# First-line marker written into auto-synthesized foundry.toml so the
# next autobuild run can distinguish "this is our shim, treat it as
# absent for backend detection and feel free to regenerate" from "this
# is a real hand-written Foundry config, leave it alone". Kept narrow
# and stable so users can grep for it.
FOUNDRY_SHIM_MARKER = "# knowdit-managed Hardhat→Foundry shim"


class NodePackageManager(str, Enum):
    """Which JS package manager the project uses. Auto-picked from the
    lockfile present at the project root, in this order of preference
    when multiple exist (more deliberate signals win over leftovers):
    `yarn.lock` → [`YARN`], `pnpm-lock.yaml` → [`PNPM`], else → [`NPM`]."""
    NPM = "npm"
    YARN = "yarn"
    PNPM = "pnpm"


@dataclass(frozen=True)
class ProjectLayout:
    """Static facts about a project: which build-system configs are
    present on disk. Pure inspection — no side effects, no subprocess."""

    root: Path

    @property
    def hardhat_config(self) -> Path | None:
        for name in HARDHAT_CONFIG_NAMES:
            p = self.root / name
            if p.is_file():
                return p
        return None

    @property
    def foundry_config(self) -> Path | None:
        """A `foundry.toml` we should defer to. Auto-synthesized shims
        (marked by [`FOUNDRY_SHIM_MARKER`] on the first line) are
        skipped — they don't represent the user's intent, so a re-run
        should still detect the project as Hardhat and rebuild the
        shim from the latest `artifacts/build-info`."""
        for name in FOUNDRY_CONFIG_NAMES:
            p = self.root / name
            if p.is_file() and not _is_knowdit_shim(p):
                return p
        return None

    @property
    def foundry_shim(self) -> Path | None:
        """The auto-synthesized `foundry.toml` if one exists. Used by
        the shim regeneration path to decide between overwrite (safe,
        we wrote it) and skip (hand-written, leave alone)."""
        for name in FOUNDRY_CONFIG_NAMES:
            p = self.root / name
            if p.is_file() and _is_knowdit_shim(p):
                return p
        return None

    @property
    def package_json(self) -> Path | None:
        p = self.root / "package.json"
        return p if p.is_file() else None

    @property
    def has_yarn_lock(self) -> bool:
        return (self.root / "yarn.lock").is_file()

    @property
    def has_pnpm_lock(self) -> bool:
        return (self.root / "pnpm-lock.yaml").is_file()

    @property
    def has_package_lock(self) -> bool:
        return (self.root / "package-lock.json").is_file()

    def detect_node_pm(self) -> NodePackageManager:
        """Pick the JS package manager based on which lockfile is on
        disk. `yarn.lock` → yarn; `pnpm-lock.yaml` → pnpm; otherwise
        npm. When multiple exist, yarn > pnpm > npm: lockfiles for the
        more involved managers are kept on purpose, while
        `package-lock.json` is often a stale npm-generated leftover."""
        if self.has_yarn_lock:
            return NodePackageManager.YARN
        if self.has_pnpm_lock:
            return NodePackageManager.PNPM
        return NodePackageManager.NPM

    def detect(self, prefer: Backend) -> Backend:
        """Pick a backend based on which configs exist. When both exist,
        defer to `prefer`. Raises when neither is present."""
        has_hh = self.hardhat_config is not None
        has_fd = self.foundry_config is not None
        if has_hh and has_fd:
            return prefer
        if has_hh:
            return Backend.HARDHAT
        if has_fd:
            return Backend.FORGE
        raise SystemExit(
            f"{self.root}: no hardhat.config.{{js,ts,cjs,mjs}} and no "
            "foundry.toml — nothing to build. (Auto-discovery of nested "
            "sub-projects is intentionally out of scope here.)"
        )


# ---------------------------------------------------------------------------
# Toolchain — every external CLI used, lazily required so a forge-only
# project doesn't need `npm`/`npx` resolved and vice versa.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Toolchain:
    """Optional explicit overrides for every CLI the script may invoke.
    `None` (the default) means "resolve from `$PATH` at the moment
    [`require`] is called". An explicit `Path` short-circuits the
    lookup — useful when nvm/asdf has several node toolchains
    installed and you want to pin one specific build."""

    npm: Path | None
    npx: Path | None
    yarn: Path | None
    pnpm: Path | None
    forge: Path | None
    git: Path | None

    # PATH-resolved binaries: each Toolchain attr maps to the bare name
    # used in `shutil.which`. Kept as a class-level constant so the
    # `require` lookup is unambiguous.
    _PATH_NAMES = {
        "npm": "npm",
        "npx": "npx",
        "yarn": "yarn",
        "pnpm": "pnpm",
        "forge": "forge",
        "git": "git",
    }

    def require(self, attr: str, flag: str, reason: str) -> Path:
        """Return the binary's absolute path. Explicit override wins;
        otherwise fall back to `$PATH`. Raises with the matching
        --<flag> hint when neither is available."""
        override: Path | None = getattr(self, attr)
        if override is not None:
            if not override.exists():
                raise SystemExit(f"--{flag} points at {override}, which does not exist.")
            return override
        bare = self._PATH_NAMES[attr]
        found = shutil.which(bare)
        if found is None:
            raise SystemExit(
                f"{reason}: no `{bare}` on $PATH and --{flag} not passed. "
                f"Either install `{bare}` or pass --{flag} <absolute-path>."
            )
        return Path(found)


# ---------------------------------------------------------------------------
# Subprocess runner — single place that prints + invokes + checks. Keeps
# stdout/stderr live so the user sees compile progress.
# ---------------------------------------------------------------------------

@dataclass
class StepRunner:
    cwd: Path

    def run(self, label: str, argv: list[str | Path], timeout: int | None = None) -> None:
        printable = " ".join(str(a) for a in argv)
        print(f"\n[autobuild] {label}\n  $ {printable}\n  (cwd: {self.cwd})", flush=True)
        result = subprocess.run(
            [str(a) for a in argv],
            cwd=str(self.cwd),
            timeout=timeout,
        )
        if result.returncode != 0:
            raise SystemExit(
                f"[autobuild] {label} failed with exit {result.returncode}"
            )


# ---------------------------------------------------------------------------
# Autobuild orchestrator
# ---------------------------------------------------------------------------

@dataclass
class Autobuild:
    layout: ProjectLayout
    toolchain: Toolchain
    prefer: Backend
    npm_install_timeout: int = 600
    compile_timeout: int = 900
    submodule_timeout: int = 300
    ignore_scripts: bool = True

    def run(self) -> Backend:
        backend = self.layout.detect(self.prefer)
        print(f"[autobuild] backend={backend.value}  project={self.layout.root}", flush=True)
        runner = StepRunner(cwd=self.layout.root)
        self._sync_git_submodules(runner)
        if backend is Backend.HARDHAT:
            self._run_hardhat(runner)
        else:
            self._run_forge(runner)
        return backend

    def _sync_git_submodules(self, runner: StepRunner) -> None:
        """If the project is a git checkout, fetch its submodules. Foundry
        projects keep deps as `lib/<sub>` submodules and a fresh `git clone`
        without `--recurse-submodules` leaves them empty, so `forge build`
        dies on missing imports. This is also a no-op for projects that
        don't use submodules. Failures here are warnings, not fatals: a
        partially-broken submodule shouldn't block downstream backends."""
        if not (self.layout.root / ".git").exists():
            return
        try:
            git = self.toolchain.require(
                "git", "git",
                "submodule sync needs git",
            )
        except SystemExit as e:
            print(f"[autobuild] {e}; skipping submodule sync.", flush=True)
            return
        argv: list[str | Path] = [git, "submodule", "update", "--init", "--recursive"]
        print(f"\n[autobuild] git submodule update --init --recursive\n  $ {' '.join(str(a) for a in argv)}\n  (cwd: {self.layout.root})", flush=True)
        result = subprocess.run(
            [str(a) for a in argv],
            cwd=str(self.layout.root),
            timeout=self.submodule_timeout,
        )
        if result.returncode != 0:
            print(
                f"[autobuild] git submodule sync exited {result.returncode} — "
                "continuing anyway; downstream backend may still fail on missing libs.",
                flush=True,
            )

    # ---- per-backend recipes -------------------------------------------

    def _run_hardhat(self, runner: StepRunner) -> None:
        npx = self.toolchain.require("npx", "npx",
                                     "Hardhat project needs npx to invoke hardhat")
        self._maybe_install_node_deps(runner, required=True)
        runner.run("npx hardhat compile",
                   [npx, "hardhat", "compile"],
                   timeout=self.compile_timeout)
        # knowdit's fuzz phase is Foundry-only — synthesize a foundry.toml
        # + remappings.txt so `forge test` can drive the same on-disk
        # sources Hardhat just compiled. Re-uses the project's own
        # `node_modules/` for deps (no re-install, no forge install).
        self._synthesize_foundry_shim()

    def _synthesize_foundry_shim(self) -> None:
        """Generate `foundry.toml` + `remappings.txt` + `.knowdit-forge-std/`
        in a Hardhat-only project so `forge test/coverage` operate against
        the same on-disk sources Hardhat just compiled. Idempotent: skips
        when the project already has a `foundry.toml` (we assume that's a
        real hand-written Foundry config we shouldn't touch).

        All compiler settings (solc version, optimizer runs, viaIR,
        evmVersion) come from the newest `artifacts/build-info/*.json`
        Hardhat just wrote, so the shim's compile graph stays in lockstep
        with Hardhat's. Remappings are derived by probing each unique
        import prefix against the project's `node_modules/` — both modern
        flat layouts (`node_modules/@oz/contracts/access/...`) and legacy
        nested ones (`node_modules/@oz/contracts/contracts/access/...`).
        """
        if self.layout.foundry_config is not None:
            print(
                "[autobuild] foundry.toml already present — skipping foundry shim "
                "(hand-written config wins)",
                flush=True,
            )
            return
        build_info = _newest_hardhat_build_info(self.layout.root)
        if build_info is None:
            print(
                "[autobuild] no usable artifacts/build-info JSON; skipping foundry shim",
                flush=True,
            )
            return
        self._ensure_forge_std_clone()

        # 1. solc settings from build-info.
        solc_version: str = build_info["solcVersion"]
        settings = build_info["input"].get("settings") or {}
        optimizer = settings.get("optimizer") or {}
        via_ir = bool(settings.get("viaIR", False))
        evm_version = settings.get("evmVersion")

        # 2. Source dir from hardhat.config paths.sources (best-effort
        #    regex); fallback to `src/` then `contracts/`.
        sources_dir = self._detect_hardhat_sources_dir()
        if sources_dir is None or not (self.layout.root / sources_dir).is_dir():
            for candidate in ("src", "contracts"):
                if (self.layout.root / candidate).is_dir():
                    sources_dir = candidate
                    break
        if sources_dir is None:
            raise SystemExit(
                "[autobuild] could not locate sources dir; neither hardhat.config "
                "paths.sources nor src/ nor contracts/ resolved."
            )

        # 3. Derive remappings from build-info source keys.
        source_paths = list(build_info["input"].get("sources", {}).keys())
        remappings = _resolve_node_modules_remappings(source_paths, self.layout.root)

        # 4. forge-std lives at `lib/forge-std/` (Foundry convention).
        #    Cloned by `_ensure_forge_std_clone` earlier in this method.
        remappings.append(("forge-std/", "lib/forge-std/src/"))

        # 5. Write foundry.toml. The `cache_path` / `out` use the
        #    `.knowdit-*` prefix so they don't collide with hardhat's
        #    own cache/artifacts dirs in the same project.
        toml_lines = [
            "# knowdit-managed Hardhat→Foundry shim — auto-generated by scripts/autobuild.py.",
            "# Safe to delete; will be regenerated on the next autobuild.",
            "# Replace with a hand-written foundry.toml to opt out of regeneration.",
            "",
            "[profile.default]",
            f'src = "{sources_dir}"',
            'out = ".knowdit-out"',
            'test = "knowdit_harness"',
            'cache_path = ".knowdit-cache"',
            f'solc = "{solc_version}"',
        ]
        if optimizer.get("enabled"):
            toml_lines.append("optimizer = true")
            if "runs" in optimizer:
                toml_lines.append(f"optimizer_runs = {int(optimizer['runs'])}")
        else:
            toml_lines.append("optimizer = false")
        if via_ir:
            toml_lines.append("via_ir = true")
        if evm_version:
            toml_lines.append(f'evm_version = "{evm_version}"')
        # libs intentionally empty — every dep is reached through
        # remappings.txt against the existing node_modules/ tree.
        toml_lines.append('libs = []')
        toml_lines.append("")
        (self.layout.root / "foundry.toml").write_text("\n".join(toml_lines))

        # 6. Write remappings.txt — one prefix per line, sorted for diff stability.
        (self.layout.root / "remappings.txt").write_text(
            "\n".join(f"{src}={dst}" for src, dst in remappings) + "\n"
        )

        print(
            f"[autobuild] foundry shim ready: solc={solc_version} "
            f"src={sources_dir} optimizer={optimizer.get('enabled', False)} "
            f"via_ir={via_ir} remappings={len(remappings)}",
            flush=True,
        )

    def _ensure_forge_std_clone(self) -> None:
        """Make sure `<project>/lib/forge-std/` is a usable forge-std
        checkout. Skips when one already exists with `src/Test.sol`;
        otherwise delegates to `forge install foundry-rs/forge-std
        --no-commit`, which on a non-git project is just a plain
        clone (no `.git` / `.gitmodules` side effects) but pinned to
        the latest forge-tested release tag instead of master HEAD —
        and is the Foundry-canonical way to land std. The clone lives
        inside the project root so docker bind-mounts pick it up
        automatically (same reason OZ deps stay under `node_modules/`).

        Network access — assumes the host has GitHub reachability. If
        you need offline builds, drop a forge-std checkout at
        `lib/forge-std/` by hand before running autobuild."""
        target = self.layout.root / "lib" / "forge-std"
        if (target / "src" / "Test.sol").is_file():
            print(f"[autobuild] lib/forge-std already present — skipping clone", flush=True)
            return
        forge = self.toolchain.require(
            "forge", "forge",
            "Hardhat shim needs `forge install foundry-rs/forge-std` to land "
            "forge-std under lib/ (our harnesses `import \"forge-std/Test.sol\"`)",
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        # `--root` pins the install to THIS project even when an
        # enclosing git tree (eg. testing under knowdit/eval_refactor)
        # would otherwise capture forge's auto-discovered root and
        # drop forge-std into the wrong `lib/`.
        # `--no-git`: don't register forge-std as a submodule of any
        # enclosing git tree. `--shallow` keeps the clone fast (forge-std
        # doesn't need its full history). We deliberately don't pass
        # `--no-commit` / `--commit` since the flag spelling flipped
        # between forge 1.x versions; either default behavior is "no
        # commit unless asked", which is what we want.
        argv: list[str | Path] = [
            forge, "install", "foundry-rs/forge-std",
            "--root", self.layout.root,
            "--no-git", "--shallow",
        ]
        print(
            f"\n[autobuild] forge install foundry-rs/forge-std\n"
            f"  $ {' '.join(str(a) for a in argv)}\n"
            f"  (cwd: {self.layout.root})",
            flush=True,
        )
        result = subprocess.run(
            [str(a) for a in argv],
            cwd=str(self.layout.root),
            timeout=self.submodule_timeout,
        )
        if result.returncode != 0:
            raise SystemExit(
                f"[autobuild] forge install forge-std exited {result.returncode}; "
                "either the host has no GitHub reachability, or forge misbehaved. "
                "Pre-populate lib/forge-std manually to skip this step."
            )

    def _detect_hardhat_sources_dir(self) -> str | None:
        """Best-effort regex pull of `paths.sources: './foo'` from the
        hardhat config (JavaScript module). Returns the bare directory
        name (no leading `./`), or None when unparseable — caller falls
        back to `src/` / `contracts/`."""
        cfg = self.layout.hardhat_config
        if cfg is None:
            return None
        text = cfg.read_text(errors="replace")
        # Match: sources: "./foo" / sources : 'foo' / sources:"foo"
        m = re.search(r"\bsources\b\s*:\s*[\"']\.?/?([^\"']+)[\"']", text)
        if not m:
            return None
        return m.group(1).strip("/")

    def _maybe_install_node_deps(self, runner: StepRunner, *, required: bool) -> None:
        """Install JS deps when there is a `package.json` and `node_modules/`
        is missing. Shared between the Hardhat and Foundry backends because
        many Foundry projects map `node_modules/@scope/...` into their
        `libs`/remappings (hybrid layout), so `forge build` only succeeds
        after the JS deps land on disk. `required=True` (Hardhat path)
        turns a missing `package.json` into a fatal error; for Foundry
        it's a benign no-op (pure-submodule projects don't need npm)."""
        if self.layout.package_json is None:
            if required:
                raise SystemExit(
                    f"{self.layout.root}: hardhat config exists but no "
                    "package.json — cannot install deps."
                )
            return
        if (self.layout.root / "node_modules").is_dir():
            print("[autobuild] node_modules/ already present — skipping install",
                  flush=True)
            return
        self._install_node_deps(runner)

    def _install_node_deps(self, runner: StepRunner) -> None:
        pm = self.layout.detect_node_pm()
        argv: list[str | Path]
        if pm is NodePackageManager.YARN:
            yarn = self.toolchain.require(
                "yarn", "yarn",
                f"{self.layout.root} has yarn.lock so this project uses yarn",
            )
            argv = [yarn, "install", "--frozen-lockfile"]
            if self.ignore_scripts:
                argv.append("--ignore-scripts")
            label = "yarn install"
        elif pm is NodePackageManager.PNPM:
            pnpm = self.toolchain.require(
                "pnpm", "pnpm",
                f"{self.layout.root} has pnpm-lock.yaml so this project uses pnpm",
            )
            argv = [pnpm, "install", "--frozen-lockfile"]
            if self.ignore_scripts:
                argv.append("--ignore-scripts")
            label = "pnpm install"
        else:
            npm = self.toolchain.require(
                "npm", "npm",
                "Hardhat project needs npm to install deps",
            )
            install_cmd = "ci" if self.layout.has_package_lock else "install"
            argv = [npm, install_cmd, "--no-audit", "--no-fund"]
            if self.ignore_scripts:
                argv.append("--ignore-scripts")
            label = f"npm {install_cmd}"
        runner.run(label, argv, timeout=self.npm_install_timeout)

    def _run_forge(self, runner: StepRunner) -> None:
        forge = self.toolchain.require("forge", "forge",
                                       "Foundry project needs forge to build")
        # Hybrid pattern: hosting project has a `package.json` and the
        # foundry.toml libs/remappings point at `node_modules/@scope/...`.
        # Skipped silently when no package.json is on disk (pure-submodule
        # Foundry projects don't touch npm). Install is best-effort for
        # forge: many forge sub-libraries ship a vestigial package.json
        # whose lockfile is years stale; `forge build` resolves their
        # actual deps via `lib/` submodules anyway. If install fails we
        # log it and still try the compile so we don't regress projects
        # that used to build without ever running install.
        try:
            self._maybe_install_node_deps(runner, required=False)
        except SystemExit as exc:
            print(
                f"[autobuild] node deps install failed for forge project "
                f"({exc}) — continuing to forge build anyway",
                flush=True,
            )
        rc, output = self._capture_forge_build(forge, via_ir=False)
        if rc == 0:
            return
        if FORGE_STACK_TOO_DEEP_MARKER in output:
            print(
                f"[autobuild] forge build hit '{FORGE_STACK_TOO_DEEP_MARKER}' — "
                "retrying with --via-ir",
                flush=True,
            )
            rc2, _ = self._capture_forge_build(forge, via_ir=True)
            if rc2 == 0:
                return
            raise SystemExit(
                f"[autobuild] forge build --via-ir also failed with exit {rc2}"
            )
        raise SystemExit(f"[autobuild] forge build failed with exit {rc}")

    def _capture_forge_build(self, forge: Path, *, via_ir: bool) -> tuple[int, str]:
        """Run forge with combined stdout/stderr captured so we can grep
        for the stack-too-deep marker. We still tee everything to the
        parent so the user sees the same output they'd see streaming.
        When `via_ir=True` we also enable the optimizer: solc's own
        stack-too-deep diagnostic recommends both ("Try compiling with
        `--via-ir` … while enabling the optimizer"), and passing them
        together is the recipe that actually unblocks the IR pipeline."""
        argv: list[str | Path] = [forge, "build"]
        if via_ir:
            argv.append("--via-ir")
            argv.append("--optimize")
        label = "forge build --via-ir --optimize" if via_ir else "forge build"
        printable = " ".join(str(a) for a in argv)
        print(
            f"\n[autobuild] {label}\n  $ {printable}\n  (cwd: {self.layout.root})",
            flush=True,
        )
        try:
            proc = subprocess.run(
                [str(a) for a in argv],
                cwd=str(self.layout.root),
                capture_output=True,
                text=True,
                timeout=self.compile_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            partial_stdout = exc.stdout or ""
            partial_stderr = exc.stderr or ""
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode(errors="replace")
            if isinstance(partial_stderr, bytes):
                partial_stderr = partial_stderr.decode(errors="replace")
            sys.stdout.write(partial_stdout)
            sys.stderr.write(partial_stderr)
            sys.stdout.flush()
            sys.stderr.flush()
            print(
                f"[autobuild] {label} timed out after {self.compile_timeout}s — "
                "treating as failure",
                flush=True,
            )
            # 124 matches the standard `timeout(1)` convention so the
            # outer shell wrapper can classify this uniformly with its
            # own outer timeout.
            return 124, partial_stdout + partial_stderr
        if proc.stdout:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()
        if proc.stderr:
            sys.stderr.write(proc.stderr)
            sys.stderr.flush()
        return proc.returncode, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Foundry-shim helpers — pure functions, no side effects.
# ---------------------------------------------------------------------------

def _is_knowdit_shim(foundry_toml: Path) -> bool:
    """True iff `foundry_toml`'s first line is the knowdit-shim
    marker. Cheap (single fs read of ~64 bytes); used by
    [`ProjectLayout.foundry_config`] to route around our own
    artifacts when re-detecting the backend."""
    try:
        with foundry_toml.open("r", errors="replace") as f:
            first = f.readline().strip()
    except OSError:
        return False
    return first.startswith(FOUNDRY_SHIM_MARKER)


def _newest_hardhat_build_info(root: Path) -> dict | None:
    """Pick the newest `artifacts/build-info/*.json` whose `_format`
    is `hh-sol-build-info-1`. Hardhat writes one of these per unique
    compile-input set, so for a project with single solc-config there
    is usually exactly one. Returns None if none parseable."""
    bi_dir = root / "artifacts" / "build-info"
    if not bi_dir.is_dir():
        return None
    candidates: list[tuple[float, dict]] = []
    for p in bi_dir.glob("*.json"):
        if not p.is_file():
            continue
        try:
            with p.open() as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("_format") != "hh-sol-build-info-1":
            continue
        candidates.append((p.stat().st_mtime, d))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[-1][1]


def _resolve_node_modules_remappings(
    source_paths: list[str], project_root: Path
) -> list[tuple[str, str]]:
    """For each unique `@scope/pkg/` or `pkg/` prefix appearing in
    `source_paths`, try to find the real file under `node_modules/`
    and emit a remapping line `<prefix>=node_modules/<...>`.

    Tries the modern flat layout first
    (`node_modules/<prefix>/<rest>`), then the legacy nested layout
    (`node_modules/<prefix>/contracts/<rest>`) which older OZ + many
    `hardhat-deploy` style packages use. Local paths (`./` / `../` /
    absolute) are skipped — solc resolves those relative to the
    importing file.

    Returned in sorted order for deterministic remappings.txt output."""
    node_modules = project_root / "node_modules"
    if not node_modules.is_dir():
        return []
    resolved: dict[str, str] = {}
    for path in source_paths:
        if path.startswith(("./", "../", "/")):
            continue
        parts = path.split("/")
        if path.startswith("@"):
            if len(parts) < 3:
                continue  # bare scope, no resolveable file
            prefix = f"{parts[0]}/{parts[1]}/"
            rest = "/".join(parts[2:])
        else:
            if len(parts) < 2:
                continue
            prefix = f"{parts[0]}/"
            rest = "/".join(parts[1:])
        if prefix in resolved:
            continue
        flat = node_modules / prefix.rstrip("/") / rest
        if flat.is_file():
            resolved[prefix] = f"node_modules/{prefix}"
            continue
        nested = node_modules / prefix.rstrip("/") / "contracts" / rest
        if nested.is_file():
            resolved[prefix] = f"node_modules/{prefix.rstrip('/')}/contracts/"
            continue
        # Couldn't probe — leave unresolved; user can add by hand.
    return sorted(resolved.items())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autobuild.py",
        description=(
            "Autobuild a Solidity project for knowdit ingestion. Detects "
            "Hardhat vs Foundry layout, then runs the matching install + "
            "compile steps. Binaries must be passed explicitly — no $PATH "
            "lookup is performed."
        ),
    )
    p.add_argument("project", type=Path,
                   help="Path to the project root (the directory holding "
                        "hardhat.config.* or foundry.toml).")
    p.add_argument("--npm", type=Path, default=None,
                   help="Override for the `npm` binary. Default: resolve "
                        "via $PATH.")
    p.add_argument("--npx", type=Path, default=None,
                   help="Override for the `npx` binary. Default: resolve "
                        "via $PATH.")
    p.add_argument("--yarn", type=Path, default=None,
                   help="Override for the `yarn` binary. Default: resolve "
                        "via $PATH (only invoked if the project ships a "
                        "yarn.lock).")
    p.add_argument("--pnpm", type=Path, default=None,
                   help="Override for the `pnpm` binary. Default: resolve "
                        "via $PATH (only invoked if the project ships a "
                        "pnpm-lock.yaml).")
    p.add_argument("--forge", type=Path, default=None,
                   help="Override for the `forge` binary. Default: resolve "
                        "via $PATH.")
    p.add_argument("--git", type=Path, default=None,
                   help="Override for the `git` binary. Default: resolve "
                        "via $PATH. Used for `git submodule update --init "
                        "--recursive` when the project is a git checkout.")
    p.add_argument("--prefer", choices=[b.value for b in Backend], default=Backend.FORGE.value,
                   help="When both hardhat.config.* and foundry.toml exist, "
                        "which backend to use. Default: forge (matches "
                        "knowdit's auto-detect for dual projects).")
    p.add_argument("--npm-install-timeout", type=int, default=600,
                   help="Per-run timeout in seconds for `npm install`. "
                        "Default: 600 (10 min).")
    p.add_argument("--compile-timeout", type=int, default=900,
                   help="Per-run timeout in seconds for the compile step "
                        "(hardhat compile or forge build). Default: 900 (15 min).")
    p.add_argument("--submodule-timeout", type=int, default=300,
                   help="Per-run timeout in seconds for the `git submodule "
                        "update --init --recursive` step. Default: 300 (5 min).")
    p.add_argument("--allow-npm-scripts", action="store_true",
                   help="Allow npm postinstall scripts to run. Default is "
                        "--ignore-scripts (safer for clones of untrusted repos).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    layout = ProjectLayout(root=args.project.resolve())
    if not layout.root.is_dir():
        raise SystemExit(f"{layout.root} is not a directory")
    toolchain = Toolchain(
        npm=args.npm, npx=args.npx, yarn=args.yarn, pnpm=args.pnpm,
        forge=args.forge, git=args.git,
    )
    autobuild = Autobuild(
        layout=layout,
        toolchain=toolchain,
        prefer=Backend(args.prefer),
        npm_install_timeout=args.npm_install_timeout,
        compile_timeout=args.compile_timeout,
        submodule_timeout=args.submodule_timeout,
        ignore_scripts=not args.allow_npm_scripts,
    )
    backend = autobuild.run()
    print(f"\n[autobuild] {backend.value} build finished OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
