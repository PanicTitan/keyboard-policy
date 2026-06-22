# keyboard-policy, USB Keyboard Protection Tool

> **DISCLAIMER:** This tool modifies Windows registry policy keys under `HKLM\SOFTWARE\Policies`. Proceed at your own risk. Always verify the changes on your machine before relying on it in any critical environment. The author takes no responsibility for any unintended effects, loss of input, or system behavior resulting from its use.

A lightweight Windows CLI tool that blocks new USB keyboard installations using the built-in Windows Device Installation Restrictions policy, with no drivers, no kernel tricks, just registry-level Group Policy.

Designed to protect against **BadUSB / USB Rubber Ducky** attacks, where a malicious USB device masquerades as a keyboard and silently types commands to take over a PC.

> **Note:** This could have been written as a PowerShell script, since the registry operations involved are fully scriptable. It was intentionally built as a compiled C++ binary for a self-contained executable with no runtime dependencies and no execution policy concerns.

## How It Works

When protection is enabled, Windows is told to refuse the installation of any **new** keyboard-class device. Already-connected keyboards keep working normally (`Retroactive = 0`). If an attacker plugs in a USB Rubber Ducky or any other HID keyboard impersonator, Windows simply won't install it.

Everything is done through the standard Windows policy registry path:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions
```

No third-party libraries, no system services, no kernel modifications. It can be fully reversed with a single command.

## Requirements

- Windows 10 / 11 (64-bit)
- **Administrator privileges** (required to write to `HKLM\SOFTWARE\Policies`)
- Visual Studio to build from source (see note below)

> **Tested on:** Windows 11 Home. The registry keys used are expected to work on Pro and Enterprise editions as well, but this has not been verified.

> **Visual Studio:** Built and tested with Visual Studio 2022 (v143 toolset). Newer versions should work without changes, since the project uses only standard Win32 APIs and a straightforward console application configuration.

## Building

1. Open `keyboard-policy.sln` in Visual Studio.
2. Select your desired configuration (`Release | x64` or `Debug | x64`). For everyday use either works fine, the tool is simple enough that there is no meaningful difference.
3. Build (`Ctrl+Shift+B`).
4. The binary `keyboard-policy.exe` will be in `x64\Release\` or `x64\Debug\` depending on your choice.

> No pre-built binary is provided. Distributing a signed executable requires a code signing certificate to avoid Windows SmartScreen warnings, so building from source is the recommended approach.

## Usage

All commands must be run from an **elevated (Administrator) command prompt**, except `list-present`.

```
keyboard-policy status
keyboard-policy protect on|off
keyboard-policy allow add "<INSTANCE_ID>"
keyboard-policy allow remove "<INSTANCE_ID>"
keyboard-policy allow list
keyboard-policy deny add "<INSTANCE_ID>"
keyboard-policy deny remove "<INSTANCE_ID>"
keyboard-policy deny list
keyboard-policy list-present
keyboard-policy nuke --yes
```

### Commands

| Command | Description |
|---|---|
| `status` | Show current policy values and lists |
| `protect on` | Block all new keyboard installs (non-retroactive) |
| `protect off` | Disable protection (lists stay in registry but become inert) |
| `allow add "<ID>"` | Whitelist a specific device instance ID |
| `allow remove "<ID>"` | Remove a device from the allow list |
| `allow list` | Print the current allow list |
| `deny add "<ID>"` | Explicitly block a specific device instance ID |
| `deny remove "<ID>"` | Remove a device from the deny list |
| `deny list` | Print the current deny list |
| `list-present` | List instance IDs of all currently connected keyboards |
| `nuke --yes` | Delete the entire policy key, full rollback |

## Quick Start

### 1. Enable protection

```cmd
keyboard-policy protect on
```

This sets `DenyDeviceClasses = 1` for the keyboard setup class GUID (`{4d36e96b-e325-11ce-bfc1-08002be10318}`) without applying it retroactively, so your existing keyboard keeps working.

**A restart is recommended** for the policy to fully take effect.

### 2. Check current status

```cmd
keyboard-policy status
```

### 3. Whitelist a trusted keyboard (optional)

If you need to plug in a second keyboard that you trust:

```cmd
# First, find your device's instance ID
keyboard-policy list-present

# Then whitelist it before plugging in
keyboard-policy allow add "HID\VID_046D&PID_C31C\..."
```

### 4. Turn off protection

```cmd
keyboard-policy protect off
```

Lists remain in the registry but are disabled. Run `nuke --yes` to wipe everything.

### 5. Full rollback

```cmd
keyboard-policy nuke --yes
```

Recursively deletes `...\DeviceInstall\Restrictions` from the registry. Requires an explicit `--yes` flag to prevent accidental use.

## Safety Properties

- **Non-retroactive by design,** `DenyDeviceClassesRetroactive = 0` ensures your internal/existing keyboards are never affected.
- **Reversible,** `protect off` or `nuke --yes` cleanly removes all policy changes.
- **Layered evaluation,** `AllowDenyLayered = 1` is set so allow-list entries can coexist with deny rules (per Microsoft's documented evaluation order).
- **64-bit registry view,** all writes use `KEY_WOW64_64KEY` to target the correct policy path on 64-bit Windows.
- **No drivers,** this tool never touches kernel components or device drivers.

## Limitations

- This tool blocks **installation** of new keyboard devices. It does not block keystrokes from keyboards that are already installed and active.
- Does not protect against BadUSB attacks from non-keyboard device classes (e.g., network adapters, storage). This is keyboard-specific.
- Group Policy may be overridden by domain controllers on managed enterprise machines.
- Windows 11 Home does not have the Group Policy editor, but the underlying registry keys are still evaluated by Windows regardless.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Bad arguments / usage error |
| `2` | Failed to enable protection |
| `3` | Failed to update allow/deny list |
| `5` | Not running as Administrator |
| `6` | Nuke refused (missing `--yes`) |
| `7` | Nuke operation failed |

## License

MIT License, see [LICENSE](LICENSE) for details.
