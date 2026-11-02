# winecloak

Make Wine or GE-Proton look like an ordinary bare-metal Windows PC, so software that
refuses to run when it detects Wine, a VM, or a sandbox will run normally.

It's meant for lightweight malware triage on low-spec hardware — a Steam Deck or mini PC
where a full hardened Windows VM is too heavy. Wine runs at near-native cost, and on real
hardware it has no hypervisor bit, no VM timing gaps, and real SMBIOS/CPU/RAM to begin
with. winecloak fills in the parts Wine otherwise gives itself away on.

Not for getting past online-game anti-cheat. Don't use it for that.

## What it neutralizes

- `ntdll!wine_get_version` / `build_id` / `host_version` and the `kernel32` file-name exports
- the `HKCU/HKLM\Software\Wine` marker key (renamed to a random name, different per install)
- Wine's default `ProductId` / `InstallDate` / `RegisteredOwner`
- `winemenubuilder.exe`, cosmetic `wine*` apps, the `Z:` drive mapping to `/`
- missing ACPI tables / HPET (served from the host's real tables)
- `Win32_DiskDrive` = "Wine Disk Drive", and empty `Win32_Fan` / `TemperatureProbe` /
  `MSAcpi_ThermalZoneTemperature`
- the host machine-id leaking through the SMBIOS UUID (made unique per prefix)

It does **not** touch deeper behavioral tells (API stubs, timing, `KUSER_SHARED_DATA`) or
the structural `wine_server_*` exports and `winex11.drv`/`wineboot.exe` filenames. For an
evasion-aware sample, a hardened Windows VM is still the right tool.

## Two ways to use it

**Patch mode** rewrites an existing Wine/GE-Proton install in place. No compiler, a few
seconds. Covers the export, registry, identity, and filesystem tells.

**Build mode** compiles Wine from source with the firmware patches. Adds ACPI/HPET, the
disk/thermal/fan WMI classes, SKU sanitizing, and per-prefix machine-id. The same source
patches apply to a `proton-ge-custom` tree, though GE's build harness needs extra handling
(vklayers, pinned downloads, `-Werror`) — see `lib/patch_source.py` and `patch_smbios.py`.

## Requirements

- `python3` (the patchers)
- Build mode: a C toolchain, `mingw-w64`, and Wine's build deps. An Arch `distrobox` or
  `toolbox` is the easy path — `./configure --enable-archs=i386,x86_64` needs no 32-bit
  host libraries.
- `stage-acpi` needs `sudo` once (to read the root-only ACPI tables).

## Install

No install step — clone and run it by path:

```sh
git clone https://github.com/gaigelama/winecloak
cd winecloak
./winecloak --help
```

If you want it on your PATH:

```sh
ln -s "$PWD/winecloak" ~/.local/bin/winecloak
```

## Quick start

Patch an existing GE-Proton and harden a prefix (no compile):

```sh
./winecloak all ~/.steam/steam/compatibilitytools.d/GE-Proton9-20 ~/myprefix --keep-z
```

Or build a fully-cloaked Wine from source:

```sh
git clone --depth 1 https://gitlab.winehq.org/wine/wine.git /tmp/wine
./winecloak build /tmp/wine --out ~/wine-hidden
./winecloak stage-acpi          # one-time sudo; serves the real HPET table
```

Check what a detector would still see:

```sh
./winecloak probe ~/myprefix --runner ~/wine-hidden/bin/wine
```

## Using it in Steam / Lutris / ProtonUp-Qt

Package a cloaked runner:

```sh
./winecloak package ~/wine-hidden --name Wine-Hidden
./winecloak package ~/.steam/steam/compatibilitytools.d/GE-Proton-patched --name GE-Proton-Hidden
```

- **Steam** (GE-Proton builds only — they carry the `proton` wrapper): extract the tarball
  into `~/.steam/steam/compatibilitytools.d/` and restart Steam. Pick it per game under
  Properties > Compatibility.
- **Lutris**: extract into `~/.local/share/lutris/runners/wine/` (or the Flatpak data dir)
  and select it as the game's Wine version.
- **ProtonUp-Qt**: publish the tarball as a GitHub release and add a `ctmod` so it shows up
  in the Add-version list. `protonup-qt/ctmod_wine_hidden.py` is a template to adapt to your
  installed ProtonUp-Qt version.

## Commands

```
patch-runner <dir>            cloak an existing runner in place (no compile)
harden <prefix> [--keep-z]    drives, cosmetic files, identity in a prefix
prelaunch <prefix>            filesystem-only re-harden (for a Lutris pre-launch hook)
stage-acpi [--dir <cache>]    copy host ACPI tables somewhere wine can read them (sudo)
build <src> --out <dir>       apply source patches + compile Wine
smbios <prefix>               give a prefix a unique machine UUID + serials (build mode)
probe <prefix> --runner <w>   report remaining tells
package <dir> --name <N>      wrap a cloaked runner as a Steam/Lutris tarball
all <dir> <prefix>            patch-runner + harden + smbios + stage-acpi
```

## Layout

```
winecloak                 the CLI
lib/                      the patchers (exports, registry key, source, smbios)
patches/                  reference source patch
probes/                   detection probes, prebuilt so you can test without a compiler
protonup-qt/              ProtonUp-Qt ctmod template
```

## License

GPL-3.0. The source patches derive from Wine (LGPL-2.1+); treat that code accordingly.
