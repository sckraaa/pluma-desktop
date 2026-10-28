#!/usr/bin/env bash
# Builds on Windows (Git Bash), with the Visual Studio environment of the
# toolset and the SDK upstream.env names, as the upstream CI does:
#   windows.sh libraries  the libraries, with Telegram/build/prepare/prepare.py
#                         (Qt 6, the release and the debug builds) into
#                         ../Libraries/win64 and ../ThirdParty next to the
#                         checkout; a stage built already is skipped;
#   windows.sh trim       removes what the client build does not need from
#                         the libraries, before they are cached (as upstream);
#   windows.sh client     the client in the Release configuration, through
#                         ccache when CCACHE_DIR is set (CI):
#                         $UPSTREAM_DIR/out/Release/Telegram.exe.
# $UPSTREAM_DIR is the patched checkout (ci/configure.sh). The paths of the
# libraries end up in their cache keys, so CI keeps them the same from run to
# run.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
mode=${1:?usage: windows.sh libraries|trim|client}
dir=$(cd "${UPSTREAM_DIR:?UPSTREAM_DIR is not set}" && pwd)
root=$(dirname "$dir")
libs=$root/Libraries/win64

if [ ! -f "$dir/pluma-patch.txt" ]; then
	echo "windows: $dir is not patched (ci/configure.sh)" >&2
	exit 1
fi

# Runs the command lines given in a cmd.exe with the environment of
# vcvarsall.bat; each must succeed. The cmd.exe gets the environment of a
# "shell: cmd" step, as in the upstream CI: Git Bash's launcher puts its
# MinGW and MSYS directories in front of the PATH, and their find.exe,
# sort.exe and link.exe would shadow Windows' own (libwebp's Makefile.vc
# pipes cl through find). CI passes the PATH of a cmd step in
# PLUMA_CMD_PATH; elsewhere the launcher's directories are dropped.
in_vcvars() {
	local vswhere vs bat line path=$PATH cmd_path=${PLUMA_CMD_PATH:-}
	if [ -z "$cmd_path" ]; then
		while :; do
			case $path in
			"$HOME/bin:"* | /mingw64/bin:* | /usr/bin:* | /usr/local/bin:* | /bin:*) path=${path#*:} ;;
			*) break ;;
			esac
		done
		cmd_path=$(cygpath -w -p "$path")
	fi
	vswhere="$(cygpath -u "${ProgramFiles:-C:\\Program Files} (x86)")/Microsoft Visual Studio/Installer/vswhere.exe"
	vs=$("$vswhere" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
		-property installationPath | tr -d '\r')
	if [ -z "$vs" ]; then
		echo "windows: no Visual Studio with the C++ tools" >&2
		return 1
	fi
	bat=$(mktemp -d)/run.cmd
	{
		printf '@echo off\r\n'
		printf '%s\r\n' 'set "PATH=%PLUMA_CMD_PATH%"'
		printf 'call "%s\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 %s -vcvars_ver=%s\r\n' "$vs" "$WINDOWS_SDK" "$MSVC_TOOLSET"
		printf 'if errorlevel 1 exit /b 1\r\n'
		# Windows' find.exe must come first (see above).
		printf '%s\r\n' \
			"for /f \"delims=\" %%i in ('where find.exe') do (set \"PLUMA_FIND=%%i\" & goto found)" \
			':found' \
			'echo windows: find is %PLUMA_FIND%' \
			'if /i not "%PLUMA_FIND%"=="%SystemRoot%\System32\find.exe" (where find.exe & exit /b 1)'
		for line in "$@"; do
			printf '%s\r\n' "$line"
			printf 'if errorlevel 1 exit /b 1\r\n'
		done
	} >"$bat"
	# The launcher also sets MSYSTEM=MINGW64, which would make the MSYS2 login
	# shells of prepare.py (libvpx, ffmpeg) set up MinGW instead of MSYS. No
	# MSYS_NO_PATHCONV either: in those shells MSYS2 must turn paths into
	# Windows ones for native tools (perl), so the switches are written //d
	# //c for Git Bash instead.
	(
		unset MSYSTEM MSYS_NO_PATHCONV MSYS2_ARG_CONV_EXCL
		PLUMA_CMD_PATH=$cmd_path \
			"$(cygpath -u "${COMSPEC:-C:\\Windows\\System32\\cmd.exe}")" //d //c "$(cygpath -w "$bat")"
	)
}

windir=$(cygpath -w "$dir")
case $mode in
libraries)
	# Some stages commit their own patches.
	git config --global user.email "ci@pluma.invalid"
	git config --global user.name "Pluma CI"
	nuget sources Disable -Name "Microsoft Visual Studio Offline Packages" >/dev/null 2>&1 || true
	nuget sources Add -Source https://api.nuget.org/v3/index.json >/dev/null 2>&1 || true
	mkdir -p "$libs" "$root/ThirdParty"
	# As the upstream CI's "First set up": the Debug builds of the CMake-based
	# libraries (Qt among them) without debug information, whose PDBs would
	# fill the disk.
	# shellcheck disable=SC2016 # CMake's variables, not the shell's
	sed -i '/CMAKE_${lang}_FLAGS_DEBUG_INIT/s/${_Zi}//' "$PROGRAMFILES"/CMake/share/cmake*/Modules/Platform/Windows-MSVC.cmake
	df -h "$root"
	in_vcvars "cd /d \"$windir\"" \
		"call Telegram\\build\\prepare\\win.bat silent qt6"
	;;
trim)
	# The upstream CI's "Free up some disk space" step.
	find "$libs" '(' '(' ! '(' -name '*.lib' -o -name '*.a' -o -name '*.exe' -o -name '*.h' -o -name '*.hpp' \
		-o -name '*.inc' -o -name '*.cmake' -o -name '*.pc' -o -path '*/include/*' -o -path '*/objects-*' \
		-o -path '*/cache_keys/*' -o -path '*/patches/*' -o -path '*/nv-codec-headers/*' ')' -type f ')' \
		-o -empty ')' -delete
	du -sh "$libs" "$root/ThirdParty"
	df -h "$root"
	;;
client)
	# ccache is CMake's compiler launcher for the Ninja generator. It caches
	# MSVC's compilations with the precompiled headers of the client's own
	# targets too (sccache gives up on those, and the client does not build
	# without them). Without debug information, as in the upstream CI: no
	# build ships a PDB, and in every object it would only grow the cache.
	# rcc writes the upstream commit's date in place of each resource
	# file's mtime, so a fresh checkout yields the same resource sources.
	# ccache knows the compiler by the full version of the toolset and its
	# target, which vcvarsall.bat sets, not by the mtime and size of cl.exe
	# (its default check): another image of the runner may install the same
	# compiler with other mtimes, as the macOS images do with Xcode.
	cache=
	check=()
	if [ -n "${CCACHE_DIR:-}" ]; then
		if ! ccache=$(command -v ccache.exe); then
			echo "windows: CCACHE_DIR is set, but there is no ccache (ci/setup.sh ccache)" >&2
			exit 1
		fi
		ccache=$(cygpath -m "$ccache")
		cache="-D CMAKE_C_COMPILER_LAUNCHER=$ccache -D CMAKE_CXX_COMPILER_LAUNCHER=$ccache"
		check=('if not defined VCToolsVersion (echo windows: vcvarsall.bat set no VCToolsVersion & exit /b 1)'
			'if not defined VSCMD_ARG_TGT_ARCH (echo windows: vcvarsall.bat set no VSCMD_ARG_TGT_ARCH & exit /b 1)'
			'set "CCACHE_COMPILERCHECK=string:MSVC %VCToolsVersion% %VSCMD_ARG_TGT_ARCH%"'
			'echo windows: ccache knows the compiler as MSVC %VCToolsVersion% %VSCMD_ARG_TGT_ARCH%')
	fi
	QT_RCC_SOURCE_DATE_OVERRIDE=$(git -C "$dir" log -1 --format=%ct)
	export QT_RCC_SOURCE_DATE_OVERRIDE
	start=$(date +%s)
	in_vcvars ${check[@]+"${check[@]}"} "cd /d \"$windir\\Telegram\"" \
		"call configure.bat -G \"Ninja Multi-Config\" qt6 -D TDESKTOP_API_ID=$PLUMA_API_ID -D TDESKTOP_API_HASH=$PLUMA_API_HASH -D CMAKE_CONFIGURATION_TYPES=Release -D CMAKE_MSVC_DEBUG_INFORMATION_FORMAT= -D DESKTOP_APP_DISABLE_AUTOUPDATE=ON -D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON $cache" \
		"cmake --build ..\\out --config Release --parallel"
	echo "windows: the client took $((($(date +%s) - start) / 60)) min"
	exe="$dir/out/Release/Telegram.exe"
	if [ ! -f "$exe" ]; then
		echo "windows: no $exe" >&2
		exit 1
	fi
	echo "windows: $exe ($(du -h "$exe" | awk '{print $1}'))"
	;;
*)
	echo "usage: windows.sh libraries|trim|client" >&2
	exit 2
	;;
esac
