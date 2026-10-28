# Pluma for desktop

Builds of the official Telegram Desktop app ([telegramdesktop/tdesktop](https://github.com/telegramdesktop/tdesktop)) for Linux, Windows and macOS, for a [Pluma](https://github.com/sckraaa/pluma) server, a self-hosted Telegram-compatible server. This project is not affiliated with Telegram.

The repository holds no copy of the app's code. CI fetches the upstream release pinned in [`upstream.env`](upstream.env) (tag `v7.0.9`, the last release of MTProto layer 228), patches it with [`ci/patch.py`](ci/patch.py) and builds it the way the upstream's own CI does. Every edit must match the upstream source exactly. If an update moves any of the edited places, the build fails; it never quietly produces a client that talks to Telegram.

## What the patch changes

- **Datacenter.** The client gets a single built-in datacenter, DC 1: the Pluma server (IPv4 address, optional IPv6 address, port). It is used for both the production and the test backend, and a fresh install starts on it.
- **Server key.** The server's RSA key replaces Telegram's production and test keys. Telegram's key for its "special config" (signed backup addresses) is replaced too, so no MTProto key of Telegram's is left in the client.
- **Fallbacks that reach Telegram, off.**
  - No backup addresses: no DNS-over-HTTPS queries at Google and Mozilla for Telegram's records, no Firebase Remote Config or Firestore.
  - No time from those servers' HTTP headers; the server's messages correct the clock as before.
  - Proxy host names resolve through the system resolver, not over DNS-over-HTTPS at Google and Mozilla.
  - No updater: it is compiled out (`TDESKTOP_DISABLE_AUTOUPDATE`), so the app never downloads Telegram's builds, which speak another layer and trust other keys.
  - No crash reports: compiled out (`TDESKTOP_DISABLE_CRASH_REPORTS`), so nothing is sent to `tdesktop.com`.

  The build passes the upstream's options `-D DESKTOP_APP_DISABLE_AUTOUPDATE=ON -D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON`. The patch also makes CMake define both macros unconditionally and stop when either option is off.
- **App identity.** Pluma lives next to an installed Telegram Desktop without sharing anything with it ([`config/app.env`](config/app.env)):
  - the name "Pluma", and with it the data folder: `%APPDATA%\Pluma` or a portable folder next to `Pluma.exe` on Windows, `~/Library/Application Support/Pluma` on macOS, `~/.local/share/Pluma` on Linux;
  - Pluma's `api_id` (10003) and `api_hash`, passed to CMake (`-D TDESKTOP_API_ID/TDESKTOP_API_HASH`);
  - macOS: the bundle ID `chat.pluma.desktop`;
  - Linux: the application ID `chat.pluma.desktop` (Wayland `app_id`, D-Bus name, the `.desktop` file), and no look into `~/.TelegramDesktop`, where an old Telegram Desktop kept its data;
  - Windows: the AppUserModelID `Pluma.PlumaDesktop` (taskbar, notifications), Pluma's own GUIDs for the single-instance lock, the COM class that notifications activate and the application, shortcuts named `Pluma.lnk` (Start menu, autostart, Send To), and "Pluma" in the file's version information.
- **Links.** `tg://` and `tonsite://` stay with Telegram Desktop installed on the same computer. Pluma does not register them at its first start, and its macOS bundle and Linux `.desktop` file do not declare them. Telegram's web links open Telegram, whose accounts they belong to. Typing `registertg` in Settings still takes the schemes over, under Pluma's own names.

- **Backports to the build scripts** (`BACKPORTS` in `ci/patch.py`), byte for byte as upstream made them later:
  - tdesktop `b244f1b3`: `prepare.py` takes the UCRT packages of MSYS2 (`mingw-w64-ucrt-x86_64-*`) and a newer MSYS2 installer. MSYS2 removed the msvcrt-based `mingw-w64-x86_64-*` packages that 7.0.9 asks for, and the Windows libraries could not be built.
- **Build script edits of Pluma's own** (`BUILD_EDITS`), each in the commands of one system, so the cached libraries of the other stay valid:
  - Windows: `prepare.py` does not build breakpad's `dump_syms`, which makes symbol files for Telegram's crash reports and needs ATL, missing from the image's MSVC 14.44 toolset. Pluma compiles crash reports out, and the upstream CI, building Debug only, never builds it either.
  - macOS: Qt and tg_owt (WebRTC) are built in their release variants alone, and Qt without `-force-debug-info`. The Release client links nothing else (cmake_helpers picks a library's variant by the configuration), and Qt's debug information serves symbol files for crash reports. These debug builds were the bulk of the 20 GB of macOS libraries (4.8 GB in the cache). Qt is installed into an emptied prefix, so a previous build leaves nothing behind there. The small debug builds of other stages stay as upstream has them.

After the edits, the result is checked again over all of `Telegram/SourceFiles`:
- no address in Telegram's published ranges and no MTProto key of Telegram's;
- the server key and nothing else (three copies);
- no code that constructs the classes asking Google, Mozilla or Firebase;
- the updater and the crash reports compiled out;
- the identity of every platform.

The check also covers the layer (`api.tl` says `LAYER 228`), the version, and the toolchain of `upstream.env` against the upstream's own build files.

What the patch leaves, and why:
- **Links** to `t.me`, `telegram.org`, `desktop.telegram.org` and the like in the interface (the FAQ, the terms, "Telegram Desktop" in the About box). Each opens only when clicked. They change together with the rest of the rebranding (the icon, the strings that say "Telegram").
- **Requests the user starts:** translation through a web provider, the address of a location being sent (Mapbox), payment forms (Stripe, Smartglocal), bot web apps and Instant View pages, files linked from messages. They reach the services the content names, as in any client.
- **Telegram's 1024-bit update keys** in `config.h`. They only verify update packages, and the updater is compiled out.
- **Connections made through MTProto** (emoji sets, spellchecker dictionaries, the language pack, calls) go to the Pluma server, which answers for them.

## Configuration

Set these in the repository's *Settings → Secrets and variables → Actions → Variables*:

| Variable | |
|---|---|
| `PLUMA_SERVER_IPV4` | The server's IPv4 address. The built-in datacenter takes an address, not a host name. |
| `PLUMA_SERVER_PORT` | The port of the server's MTProto gateway (gnetway). |
| `PLUMA_SERVER_IPV6` | Optional. The server's IPv6 address. |
| `PLUMA_RSA_PUBLIC_KEY` | The server key as a PKCS#1 PEM: `openssl rsa -in server_pkcs1.key -RSAPublicKey_out` |
| `PLUMA_AGE_RECIPIENT` | The owner's [age](https://age-encryption.org) public key (`age1...`); see [Builds for a server](#builds-for-a-server). |

None of these values is a secret: every build carries them. They have the same names as in `pluma-android` and `pluma-ios`.

- **No server variables set.** CI builds for the development server of [`config/dev`](config/dev).
- **All three set.** CI builds for that server. A manual run can still ask for a development build (*dev*).
- **Some but not all set.** The check job fails within seconds.

## Development build

Without the server variables, every run builds for the development server: `127.0.0.1:10443` with the development key of [`config/dev`](config/dev). The app reaches a server stack that runs on the same computer. Such a build carries no secret and stays plain in the artifacts of the run for seven days: `pluma-desktop-linux-dev`, `pluma-desktop-windows-dev`, `pluma-desktop-macos-dev`.

1. In the server repository, start the stack with the development key and the gateway on port 10443, and allow a phone number:
   ```sh
   E2E_SERVER_KEY=~/pluma-dev-secrets/server_pkcs1.key E2E_GATEWAY_PORT=10443 test/e2e/run.sh up
   test/e2e/run.sh admin allowlist add +79990000001
   ```
   On another computer than the one with the stack, forward the port first: `ssh -N -L 10443:127.0.0.1:10443 <the stack's computer>`.
2. Download the build of the run: `gh run download <run id> -R sckraaa/pluma-desktop -n pluma-desktop-macos-dev` (or `-linux-dev`, `-windows-dev`), and check it with `shasum -a 256 -c *.sha256`.
3. Start it:
   - **macOS** (Apple Silicon and Intel). The app is signed ad hoc, without a Developer ID, so Gatekeeper blocks it once:
     ```sh
     unzip pluma-desktop-*-macos-dev.zip
     xattr -dr com.apple.quarantine Pluma.app
     open Pluma.app
     ```
   - **Windows** (10 and 11, x64). Unzip to a folder of its own and run `Pluma\Pluma.exe`. SmartScreen warns about an unsigned app: *More info → Run anyway*. The data lives in that folder (`tdata`), or in `%APPDATA%\Pluma` if the folder is not writable.
   - **Linux** (x86-64, glibc 2.28 or newer):
     ```sh
     tar -xJf pluma-desktop-*-linux-dev.tar.xz
     ./Pluma/Pluma
     ```
     For a menu entry, put `Pluma` on the `PATH` (`~/.local/bin`) and `chat.pluma.desktop.desktop` into `~/.local/share/applications`.
4. Sign in with the number. Get the code with `test/e2e/run.sh admin login-code +79990000001`.
5. Take the stack down with `test/e2e/run.sh down`.

A second Pluma, say a second account, starts with its own data folder: `Pluma -workdir <folder>`.

## Builds for a server

Desktop builds are not code signed: there is no Windows code signing certificate and no Apple Developer ID. A build for a real server is the same build as the development one, for another address and key.

Anyone can read the workflow artifacts of a public repository. So a build for a real server leaves its job only encrypted with the owner's age key; the check job fails within seconds when `PLUMA_AGE_RECIPIENT` is not an age public key.

1. Create the age key once and back it up off-line. The key of `pluma-android` or `pluma-ios` works too.
   ```sh
   age-keygen -o pluma-desktop.agekey        # prints the public key, age1...
   gh variable set PLUMA_AGE_RECIPIENT -R sckraaa/pluma-desktop --body age1...
   ```
2. Set the server variables ([Configuration](#configuration)).

The builds are the artifacts `pluma-desktop-linux`, `pluma-desktop-windows` and `pluma-desktop-macos` of the run, kept for 30 days:

```sh
gh run download <run id> -R sckraaa/pluma-desktop -n pluma-desktop-macos
for f in pluma-desktop-*.age; do age -d -i pluma-desktop.agekey -o "${f%.age}" "$f"; done
shasum -a 256 -c pluma-desktop-*.sha256
```

Publishing to the server for download is a later step.

## When it builds

| Trigger | Builds | Artifacts |
|---|---|---|
| Push to `main` | Linux, Windows, macOS | yes: plain for development, encrypted for a server |
| Manual run (*Actions → desktop → Run workflow*) | the systems chosen; *dev* for a development build | yes |
| Pull request | Linux, Windows, macOS | no |
| Weekly canary | the pinned upstream for the development server, on fresh runner images | no |

Changes of Markdown files and of the license build nothing.

The jobs, and what a build takes:

| Job | Runner | First build | Repeat build |
|---|---|---|---|
| `check` | `ubuntu-24.04` | under a minute | under a minute |
| `linux-env` | `ubuntu-24.04` | 2–4 h, once for each version of the upstream's `centos_env` | a minute: the image is in the registry |
| `linux` | `ubuntu-24.04`, in that image | about 1.5 h | 15–25 min (ccache) |
| `windows` | `windows-2025`, MSVC toolset 14.44, SDK 10.0.26100.0, Qt 6.11.1 | 4–6 h: the libraries, then the client (2 h) | 20–40 min, estimated: the libraries and the client's compilations come from the caches |
| `macos` | `macos-26`, Xcode 26.6, Qt 6.11.1 | 4–6 h, possibly over two runs | 20–40 min, estimated: the same; the app is universal (arm64, x86-64) |

Every build is in the Release configuration. The upstream's CI builds Debug, which is faster but not fit for users. The libraries are therefore built in their release variant too (`prepare.py` without `skip-release`); on macOS, Qt and tg_owt in that variant alone ([What the patch changes](#what-the-patch-changes)).

The Linux build runs in the upstream's own build environment, `Telegram/build/docker/centos_env`: Rocky Linux 8 and every library, Qt included, built from source. `linux-env` builds that image and pushes it to `ghcr.io/sckraaa/pluma-desktop-linux-env`, tagged with the Git tree hash of the directory. The layers of every stage go to the `buildcache` tag, so an image for a changed `centos_env` rebuilds only the changed stages.

A job runs for at most six hours. The libraries step stops earlier (Windows 250 min, macOS 210 min) so that what it built is saved; a first build that needs longer finishes in a second run. A failed job on `main` continues where it stopped after *Re-run failed jobs*:
- the image's stages come from `buildcache`;
- the libraries of Windows and macOS are saved even when a stage fails, and `prepare.py` skips the stages built already;
- the compiler caches are saved even when the compilation fails.

With the caches, a change of the upstream or of the patch compiles again only what it touches; a development and a server build differ in two source files.

Since the repository is public, set *Settings → Actions → General → Fork pull request workflows* to require approval for all outside collaborators.

## Caches

The GitHub Actions cache of a repository holds 10 GB, and an entry nobody reads for seven days is deleted. The weekly canary reads all of them. Above 10 GB GitHub evicts the entries read least recently, whichever system's they are, so the entries keep to a budget ([`ci/cache-budget.sh`](ci/cache-budget.sh)) at every moment:
- each kind of entry has a cap, and the caps add up to 9 GB;
- before a job saves an entry, it measures it and deletes the entries of the kind that the new one supersedes, so a kind never has two entries, not even while one is saved. This takes `actions: write` in the build jobs; only that step gets the token;
- a ccache never grows past its cap (`CCACHE_MAXSIZE`). An entry over its cap is an error of the run, and is saved only where the cache cannot pass 10 GB by it: in place of entries that take as much or more, or when its overrun and those of the other entries fit in the 1 GB the caps leave free (entries of other branches count whole);
- only runs on `main` save entries. Pull requests and runs on other branches restore those of `main`.

| Entry | Cap | Size | |
|---|---|---|---|
| `linux-ccache-…` | 2000 MB | to be measured with ccache 4 | a full Release build |
| `windows-ccache-…` | 2500 MB | over 1.5 GB: a cap of 1500 MB evicted during a full build | the same |
| `macos-ccache-…` | 2250 MB | 1.6 GB: two architectures | the same |
| `windows-libs-…` | 1500 MB | 1.1 GB | the libraries, Qt and the tools of `prepare.py`, release and debug variants, trimmed as upstream does |
| `macos-libs-…` | 750 MB | 0.45 GB; 4.8 GB with the debug builds of Qt and tg_owt | the same, universal, with Qt and tg_owt in their release variants alone |

The `prune-caches` job deletes older entries of each kind on `main`, if any are left, and prints the usage, with a warning above 9 GB. The trim step of the libraries lists what each stage leaves. The image lives in the container registry, outside the cache.

The compiler caches are ccache of `upstream.env`, the version of the upstream's Linux CI, on every system. The log of a build shows their statistics (hits, misses, size), the sources that missed (`ci/ccache-stats.sh`, from ccache's stats log of the build) and how long the client took.
- Linux: the static build of that ccache, mounted in the image in place of the image's ccache 3.7.7 (EPEL 8). ccache 3 keeps each sixteenth of the cache within a sixteenth of the cap, so it evicted the precompiled headers as soon as it stored them, and 70% of the compilations of a rebuild missed; ccache 4.8 and newer clean by the size of the whole cache. Upstream's CI keeps the image's ccache, with the image's cap of 20 GB. The compiler is the image's, the same file in every run, so ccache's default check of it (its mtime and size) holds.
- Windows: CMake's compiler launcher for the Ninja generator (`CMAKE_C_COMPILER_LAUNCHER`, `CMAKE_CXX_COMPILER_LAUNCHER`). ccache caches MSVC's compilations with precompiled headers too (sloppiness `pch_defines,time_macros`), which the client's own targets use: sccache gives up on those, and the client does not build without them. The client has no debug information (`CMAKE_MSVC_DEBUG_INFORMATION_FORMAT=`, as in the upstream CI; no build ships a PDB), and rcc writes the upstream commit's date for its resources (`QT_RCC_SOURCE_DATE_OVERRIDE`) in place of each file's mtime, which every checkout changes. ccache knows the compiler by the full version of the toolset and its target (`VCToolsVersion` and `VSCMD_ARG_TGT_ARCH` of `vcvarsall.bat`), not by the mtime and size of `cl.exe` (its default check), which another image of the runner may change for the same compiler.
- macOS: Xcode's compiler launcher (`C_COMPILER_LAUNCHER`; CMake has none for the Xcode generator), for the compiles and the precompiled headers of both architectures. The precompiled headers leave out the mtimes of their headers (`-Xclang -fno-pch-timestamp`): Clang would refuse one from the cache after a fresh checkout. Xcode's stat cache of the SDK stays off (`SDK_STAT_CACHE_ENABLE=NO`): its path, in a folder of the runner's user, would be in every compile line (`-ivfsstatcache`) and in the names of the folders of the precompiled headers. ccache knows the compiler by the build of Xcode (`xcodebuild -version`): images of the runner install the same Xcode (26.6, build 17F113) with other mtimes, and by ccache's default check (the compiler's mtime and size) a build on an image other than the one that filled the cache missed every compile and rebuilt the client from scratch.

The paths are the same in every run (`D:\TBuild`, `/Users/runner/TBuild`, the workspace on Linux), so ccache needs no base directory, and no compile line holds a date or the ID of a run.

To give a kind more room, raise its cap and lower another's by as much, here and in `ci/cache-budget.sh` (a test compares the two). A ccache too small for a full build evicts during the build, and the next one finds fewer hits; libraries over their cap that are not saved are built again in every run. An entry is gone if its save fails after the old one was deleted, and the next run builds it again. Raising the repository's cache limit in *Settings → Actions → Caches* is paid above 10 GB (ADR 0010 of the server repository).

## Local build

The checks need Python 3, Git and Bash, on any system:

```sh
ci/fetch-upstream.sh sparse          # ./upstream, only the files the patch reads
python3 -m unittest discover -s ci -p '*_test.py'
ci/configure.sh dev
ci/lint.sh                           # shellcheck and actionlint
```

A build follows the upstream's instructions (`docs/building-*.md` of the tag) with these scripts:

```sh
ci/fetch-upstream.sh full            # set UPSTREAM_DIR for Windows and macOS, e.g. ~/TBuild/tdesktop
ci/configure.sh dev                  # the development server; set SERVER_IPV4, SERVER_PORT, RSA_PUBLIC_KEY and use server for another
ci/build-linux.sh <image>            # Linux, in Docker: ghcr.io/sckraaa/pluma-desktop-linux-env:<tag of ci/linux-env.sh ref>
ci/windows.sh libraries && ci/windows.sh client      # Windows, Visual Studio 2022 or 2026 with the 14.44 toolset, from Git Bash
ci/macos.sh setup && ci/macos.sh libraries && ci/macos.sh client
                                     # with CCACHE_DIR set, the client compiles through the ccache on the PATH
ci/package.sh linux|windows|macos dev  # out/pluma-desktop-<version>-<system>-dev.*
```

## Updating the upstream

1. Change `upstream.env`: the tag and its commit, the version, the layer, and the toolchain of the tag (Qt in `Telegram/build/qt_version.py`, the SDK and toolset in `docs/building-win.md`, ccache in `.github/workflows/linux.yml`, the default Xcode of the macOS image). The layer must be one the server speaks. A new ccache also needs the SHA-256 of its archives in `ci/setup.sh`: the static Linux build, macOS and Windows.
2. Run `ci/fetch-upstream.sh sparse` and the tests.
3. Remove the backports the new release already has: their edits no longer match.
4. Push. Where the upstream moved something, `ci/patch.py` names the file and the text it expected. A changed `centos_env` makes `linux-env` build a new image first.

## Setting up the repository

Once, by the owner:

1. After the first push, check that the first run of `desktop` passed its `check` job and started the builds. The first `linux-env` takes hours.
2. When `linux-env` has pushed the image, open the package `pluma-desktop-linux-env` (*Your profile → Packages*):
   - make it public (*Package settings → Change visibility*): public packages are free, and anyone can rebuild with it;
   - check that *Manage Actions access* lists `sckraaa/pluma-desktop`.
3. *Settings → Actions → General → Fork pull request workflows*: require approval for all outside collaborators.
4. For builds for a real server, once there is a server: [Builds for a server](#builds-for-a-server).

## License

Telegram Desktop is under the GNU GPL v3 with an OpenSSL exception ([LICENSE](LICENSE)). The scripts of this repository are under the same license. A build is GPL software too: its source is the pinned upstream commit together with this repository's patch.
