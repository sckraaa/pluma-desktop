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
- **Links.** Pluma's links are `plm://`: the app registers the scheme at its first start (the Windows registry; its macOS bundle and Linux `.desktop` file declare it), opens it, recognises it in texts, and creates it wherever Telegram Desktop creates `tg://`, the QR code of a sign-in (`plm://login?token=…`) and copied links included. `tg://` and `tonsite://` stay with Telegram Desktop installed on the same computer: Pluma neither registers nor declares them, and a `tg://` link in a message opens Telegram Desktop, if there is one. `t.me` links in messages still open inside Pluma, as Telegram Desktop opens them. Typing `registertg` in Settings registers `plm://` again. The QR sign-in between clients works when all of them use `plm://`.
- **Birthdays of contacts.** Pluma has no Premium and no gifts (the server sets `premium_purchase_blocked`).
  - The banner at the top of the chat list that a contact has a birthday today (`BIRTHDAY_BANNER` in `ci/patch.py`) shows without Premium; upstream shows it only to those who can buy Premium and opens the gift box from it. A click opens the chat with the contact or, for several, a box "Birthdays" with them, where a click opens the chat; its search filters them by name and asks the server nothing. The banner says "Send message" in place of "Send them a Gift.", and closing it, which dismisses it as before, no longer says that a gift can be sent later.
  - The chat it opens and the contact's profile offer no gift either (`BIRTHDAY_GIFTS`): upstream shows the gift button at the message field on a contact's birthday whatever Premium, and the birthday row of a profile opens the gift box on any day while Premium cannot be bought. Both now offer a gift only while Premium can be bought, as the gift button of a profile's top bar does.
  - The banner shows although it loads the birthdays first (`TOP_BAR_WRAP`): upstream hands the chat list a suggestion only when it is ready at once, and the banner, which waits for `contacts.getBirthdays`, stayed hidden.
  - The server provides `contacts.getBirthdays`, whose users carry the `contact` flag: the box lists the contacts the app knows. `BIRTHDAY_CONTACTS_TODAY` need not be among the pending suggestions of `help.getPromoData`.
- **Brand:** the name, the icons and the colours of Pluma ([Branding](#branding)).

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
- the identity of every platform;
- the brand: no text that names Telegram but what `LANG_KEEP` and `CODE_TELEGRAM` keep, no `tg://` link, Pluma's icons, no Telegram blue in the default themes but what `KEPT_BLUE` keeps, people's blue and cyan Pluma's in every theme and in the export.

The check also covers the layer (`api.tl` says `LAYER 228`), the version, and the toolchain of `upstream.env` against the upstream's own build files.

What the patch leaves, and why:
- **Links** to `t.me`, `telegram.org`, `fragment.com` and the like in the interface: the terms and the privacy policy, the Premium, Stars, ads and mini app pages, the source code and the changelog in the About box. Each opens only when clicked.
- **Requests the user starts:** translation through a web provider, the address of a location being sent (Mapbox), payment forms (Stripe, Smartglocal), bot web apps and Instant View pages, files linked from messages. They reach the services the content names, as in any client.
- **Telegram's 1024-bit update keys** in `config.h`. They only verify update packages, and the updater is compiled out.
- **Connections made through MTProto** (emoji sets, spellchecker dictionaries, the language pack, calls) go to the Pluma server, which answers for them.

## Branding

The brand of Pluma (task 017 of the server repository) comes from [`brand/`](brand), and the patch applies it as exact edits like the rest: a string, an icon or a colour of the upstream that differs from what the tables expect stops it.

- **Name.** What the user reads says Pluma, not Telegram:
  - the built-in English (`Telegram/Resources/langs/lang.strings`): the 321 strings that name Telegram, "Telegram Desktop", "Telegram Premium", "Telegram Stars" and the like included, pinned with their counts in [`brand/strings.txt`](brand/strings.txt);
  - the texts in the code (`CODE_NAMES` in `ci/patch.py`): the first screen, the window title, the About box, the main menu, notifications, the macOS app menu and title, the Linux menus, the Windows shortcuts, the ring around a round video being recorded, the title of a bot web app on Linux, the export's HTML, the shortcut files.

  What stays: the text of links (`telegram.org`, `t.me`: they open Telegram's pages), "Telegram API" credited in the About box, names in code, files and protocols nobody reads (`CODE_TELEGRAM`), the copyright notices. Other languages come from the server's language pack.
- **Icons**, rendered from the brand kit's SVG by [`brand/render.sh`](brand/render.sh) into `brand/tree`, at the paths of the upstream files they replace (`ASSETS`: each checked against the upstream's SHA-256):
  - Windows: the executable's icon (`icon256.ico`) and the window, taskbar and tray icon (`logo_256.png`, also Linux's);
  - macOS: the app icon (the Xcode asset catalog and the iconset), its round variant, the menu bar icon. macOS 26 draws an icon of that format on a grey plate, so `ci/package.sh` puts the Icon Composer icon [`brand/Icon.icon`](brand/Icon.icon) in its place (the mark on white, flat; actool also renders it for older systems);
  - Linux: the sizes `install()` puts in hicolor;
  - the monochrome tray icons, the mark in the centre of QR codes, and the mark on the intro screen in four layers (the ring and three feathers), which the palette colours.
- **Colours**, palette "graphite and sage": graphite for text and icons, sage as the one accent, no Telegram blue.
  - The default light theme, Classic: `colors.palette` of lib_ui, [`brand/palette-day.txt`](brand/palette-day.txt).
  - The default dark theme, which a fresh install opens on a dark system (Tinted): `night.tdesktop-theme`, [`brand/palette-night.txt`](brand/palette-night.txt). The patch writes the theme's zip again.
  - The theme tiles of Settings, the base colour of the accent picker, the circle in the centre of QR codes.
  - People's colours, the seven Telegram gives a user or a chat by its id for its letter avatar (a gradient), its name in groups and the bars of its replies and link previews, stay Telegram's, except blue and cyan (`IDENTITY_COLORS`): blue is the palette's sage (avatars #7fa082 to #5b7a5e, names #4f6e52, in the dark themes #9dbb9f), and cyan a teal without Telegram's blue (avatars #5bcbc4 to #2c9c98, names #1f8a80; the dark themes keep Telegram's cyan names, #62d4e3 in Tinted). So in every theme of the app: Classic and Tinted, Day and Night, whose own colours stay Telegram's (those they leave out come from Classic, and are Pluma's), and the bases of chat themes (`TELEGRAM_THEMES`). The accent picker leaves them as it does upstream. The HTML export draws a letter avatar in one colour, there the middle of the gradient (#6d8d70, #44b4ae). The colours from 7 up come from the server (`help.getPeerColors`) for names and bars, and stay; upstream draws their letter avatars in the slot of their number modulo 7. What draws the blue or cyan slot as a plain colour follows, and so do folder tags, in the second colour of their slot:
    - blue, now sage: the session icons of Settings → Devices for Windows, macOS and the rest, the placeholder of a photo to choose, the picture of a shared folder link, the icons of Contacts and Not archived among the chats of a folder, the giveaway icon and badge in the list of boosts; in Day, Night and the bases of chat themes, whose Saved Messages gradient refers to the blue slot, the avatars of Saved Messages, Replies and My Notes, of the currency of a gift transfer and of a search of posts in the history of Stars;
    - cyan, now teal: the session icons of iPhone and iPad, the App Store in the history of Stars, the icons of Non-contacts and Read among the chats of a folder, and what upstream draws in `colorIndexBlue`, which is cyan's id 4 despite its name: the tag "+N" of more folders, the rows of the list of boosts, the giveaway to chosen users, the bar of a sponsored message without a colour.

  Outgoing bubbles are one colour: Desktop draws gradient bubbles for cloud chat themes only. Blue stays where it means something else (`KEPT_BLUE`): file type colours, the Premium, statistics and group call palettes, and Telegram's cyan names of people in Tinted. The accent presets of the picker are Telegram's, and so are the Day and Night themes, for the user to pick, but for people's blue and cyan and the colours they leave out to Classic.
- **The service notifications account** is drawn as any user: by the photo the server gives it (`pluma-admin service-photo`), by its letter until that loads. Upstream draws its logo meanwhile, and the list of chats kept the logo over the photo.
- **Ways into Telegram's services**, gone: the FAQ, Telegram Features and Ask a Question in Settings (the server does not serve `help.getSupport`), the FAQ in the login screen's settings and in the About box, the link of the main menu's footer to desktop.telegram.org, the Help of a banned phone number (an e-mail to Telegram's support).

To change an icon, edit its SVG in `brand/svg` and run `brand/render.sh` (librsvg's `rsvg-convert` and ImageMagick 7); commit the SVG and the rendered files together. The palettes are tables of `key: upstream value -> Pluma value`; people's colours are one table for every theme, `IDENTITY_COLORS` in `ci/patch.py`, a line for each colour.

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

A build for a real server is the same build as the development one, for another address and key. The macOS app of it is also signed with Pluma's Developer ID and notarized ([Signing](#signing-macos)); the Windows one is not code signed (there is no certificate), and the development builds stay signed ad hoc.

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

### Signing (macOS)

The job `sign-macos` takes the macOS app of a build for the server and signs it with the Developer ID Application certificate, with the hardened runtime, a secure timestamp and upstream's entitlements (`ci/macos.entitlements`, a copy of `Telegram.entitlements` that the patch checks). Apple notarizes it, and the ticket is stapled into the app, so Gatekeeper opens it without a warning, offline too. The job runs in the environment `release`, which holds the keys and waits for the owner's approval (*Review deployments* in the run). Its artifact is `pluma-desktop-macos-signed`, encrypted like the others:

```sh
gh run download <run id> -R sckraaa/pluma-desktop -n pluma-desktop-macos-signed
```

Apple answers most submissions within minutes but may take longer, and keeps checking after `notarytool` stops waiting ([Apple](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)). The job waits half an hour. When Apple is not done by then, the job still succeeds: its artifact is `pluma-desktop-macos-notarizing`, the signed app without the ticket and the id of the submission (`<name>.notary-id`), and the run's summary says so. Later, the workflow `staple-macos` waits for Apple's answer, staples the ticket and leaves `pluma-desktop-macos-signed` in its own run; while Apple is still checking, it fails with a message, and re-running its job later is enough. It runs in `release` as well.

```sh
gh workflow run staple-macos.yml -R sckraaa/pluma-desktop -f run=<run id of desktop>
gh run download <run id of staple-macos> -R sckraaa/pluma-desktop -n pluma-desktop-macos-signed
```

The secrets of the environment `release`:
- `PLUMA_DEVELOPER_ID_P12`, `PLUMA_DEVELOPER_ID_PASSWORD`: the certificate with its key, a PKCS#12 file in base64, and its password. The key and the certificate request are made on a Mac, the certificate in the Apple Developer account (*Certificates*, *Developer ID Application*, by the Account Holder); `security import` takes a PKCS#12 written with LibreSSL (`/usr/bin/openssl pkcs12 -export`), not with OpenSSL 3's defaults.
- `PLUMA_NOTARY_KEY`, `PLUMA_NOTARY_KEY_ID`, `PLUMA_NOTARY_ISSUER_ID`: an App Store Connect API team key with the access *Developer* (the `.p8` file in base64), its key id and the issuer id.
- `PLUMA_AGE_IDENTITY`: the age key that decrypts the build.

Without `PLUMA_DEVELOPER_ID_P12` the job signs nothing and says so. The step `sign` of `ci/sign-macos.sh` runs on a GitHub runner only: it puts a keychain of its own on the user's search list. The step `staple` needs only the API key, so it works on any Mac too. `ci/sign_test.py` runs both steps against fakes of the macOS tools.

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
| `linux` | `ubuntu-24.04`, in that image | about 1.5 h | 10–15 min (ccache) |
| `windows` | `windows-2025`, MSVC toolset 14.44, SDK 10.0.26100.0, Qt 6.11.1 | 4–6 h: the libraries, then the client (2 h) | about 15 min: the libraries and the client's compilations come from the caches |
| `macos` | `macos-26`, Xcode 26.6, Qt 6.11.1 | 4–6 h, possibly over two runs | about 10 min: the same; the app is universal (arm64, x86-64) |

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
| `linux-ccache-…` | 2000 MB | 0.9 GB | a full Release build |
| `windows-ccache-…` | 2500 MB | 1.6 GB; a cap of 1500 MB evicted during a full build | the same |
| `macos-ccache-…` | 2250 MB | 1.6 GB: two architectures | the same |
| `windows-libs-…` | 1500 MB | 1.1 GB | the libraries, Qt and the tools of `prepare.py`, release and debug variants, trimmed as upstream does |
| `macos-libs-…` | 750 MB | 0.45 GB; 4.8 GB with the debug builds of Qt and tg_owt | the same, universal, with Qt and tg_owt in their release variants alone |

The `prune-caches` job deletes older entries of each kind on `main`, if any are left, and prints the usage, with a warning above 9 GB. The trim step of the libraries lists what each stage leaves. The image lives in the container registry, outside the cache.

The compiler caches are ccache of `upstream.env`, the version of the upstream's Linux CI, on every system. The log of a build shows their statistics (hits, misses, size), the sources that missed (`ci/ccache-stats.sh`, from ccache's stats log of the build) and how long the client took.
- Linux: the static build of that ccache, mounted in the image in place of the image's ccache 3.7.7 (EPEL 8). ccache 3 keeps each sixteenth of the cache within a sixteenth of the cap, so it evicted the precompiled headers as soon as it stored them, and 70% of the compilations of a rebuild missed; ccache 4.8 and newer clean by the size of the whole cache. Upstream's CI keeps the image's ccache, with the image's cap of 20 GB. The compiler is the image's, the same file in every run, so ccache's default check of it (its mtime and size) holds. About 70 compilations miss in every build: CMake's checks and the GObject introspection of the libraries compile in folders with random names. They take seconds, but every build saves the cache again (0.9 GB, under a minute).
- Windows: CMake's compiler launcher for the Ninja generator (`CMAKE_C_COMPILER_LAUNCHER`, `CMAKE_CXX_COMPILER_LAUNCHER`). ccache caches MSVC's compilations with precompiled headers too (sloppiness `pch_defines,time_macros`), which the client's own targets use: sccache gives up on those, and the client does not build without them. The client has no debug information (`CMAKE_MSVC_DEBUG_INFORMATION_FORMAT=`, as in the upstream CI; no build ships a PDB), and rcc writes the upstream commit's date for its resources (`QT_RCC_SOURCE_DATE_OVERRIDE`) in place of each file's mtime, which every checkout changes. ccache knows the compiler by the full version of the toolset and its target (`VCToolsVersion` and `VSCMD_ARG_TGT_ARCH` of `vcvarsall.bat`), not by the mtime and size of `cl.exe` (its default check), which another image of the runner may change for the same compiler.
- macOS: Xcode's compiler launcher (`C_COMPILER_LAUNCHER`; CMake has none for the Xcode generator), for the compiles and the precompiled headers of both architectures. The precompiled headers leave out the mtimes of their headers (`-Xclang -fno-pch-timestamp`): Clang would refuse one from the cache after a fresh checkout. Xcode's stat cache of the SDK stays off (`SDK_STAT_CACHE_ENABLE=NO`): its path, in a folder of the runner's user, would be in every compile line (`-ivfsstatcache`) and in the names of the folders of the precompiled headers. ccache knows the compiler by the build of Xcode (`xcodebuild -version`): images of the runner install the same Xcode (26.6, build 17F113) with other mtimes, and by ccache's default check (the compiler's mtime and size) a build on an image other than the one that filled the cache missed every compile and rebuilt the client from scratch. Known by the build of Xcode, it finds every compile on either image.

The paths are the same in every run (`D:\TBuild`, `/Users/runner/TBuild`, the workspace on Linux), so ccache needs no base directory, and no compile line holds a date or the ID of a run.

To give a kind more room, raise its cap and lower another's by as much, here and in `ci/cache-budget.sh` (a test compares the two). A ccache too small for a full build evicts during the build, and the next one finds fewer hits; libraries over their cap that are not saved are built again in every run. An entry is gone if its save fails after the old one was deleted, and the next run builds it again. Raising the repository's cache limit in *Settings → Actions → Caches* is paid above 10 GB (ADR 0010 of the server repository).

## Local build

The checks need Python 3, Git and Bash, on any system:

```sh
ci/fetch-upstream.sh sparse          # ./upstream, only the files the patch reads
python3 -m unittest discover -s ci -p '*_test.py'
ci/configure.sh dev
ci/lint.sh                           # shellcheck and actionlint
brand/render.sh                      # the icons, after a change of brand/svg
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
4. The brand: look at what the release changed in the strings, icons and default themes the patch names. `python3 ci/patch.py --strings upstream/Telegram/Resources/langs/lang.strings` prints the table of `brand/strings.txt`; `ASSETS` in `ci/patch.py` holds the SHA-256 of the icons it replaces; the palettes, the upstream value of each colour; `IDENTITY_THEMES`, Telegram's names of people's blue and cyan in each theme, and `TELEGRAM_THEMES`, the SHA-256 of the themes the patch changes for them alone.
5. Push. Where the upstream moved something, `ci/patch.py` names the file and the text it expected. A changed `centos_env` makes `linux-env` build a new image first.

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
