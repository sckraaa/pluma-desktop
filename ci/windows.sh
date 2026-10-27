#!/usr/bin/env bash
# Builds on Windows (Git Bash), with the Visual Studio environment of the
# toolset and the SDK upstream.env names, as the upstream CI does:
#   windows.sh free       makes room on C:, where the libraries are built:
#                         unused SDKs of the image go when less than
#                         PLUMA_MIN_FREE_GB (default 80) is free;
#   windows.sh libraries  the libraries, with Telegram/build/prepare/prepare.py
#                         (Qt 6, the release and the debug builds) into
#                         ../Libraries/win64 and ../ThirdParty next to the
#                         checkout; a stage built already is skipped;
#   windows.sh trim       removes what the client build does not need from
#                         the libraries, before they are cached (as upstream);
#   windows.sh client     the client in the Release configuration:
#                         $UPSTREAM_DIR/out/Release/Telegram.exe.
# $UPSTREAM_DIR is the patched checkout (ci/configure.sh). The paths of the
# libraries end up in their cache keys, so CI keeps them the same from run to
# run.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
. ./config/app.env
mode=${1:?usage: windows.sh free|libraries|trim|client}

if [ "$mode" = free ]; then
	free_gb() {
		df -k /c | awk 'NR == 2 {print int($4 / 1048576)}'
	}
	need=${PLUMA_MIN_FREE_GB:-80}
	df -h /c /d 2>/dev/null || true
	for d in /c/Android /c/hostedtoolcache/windows/CodeQL /c/ghcup /c/Miniconda /c/Julia; do
		if [ "$(free_gb)" -ge "$need" ]; then
			break
		fi
		if [ -d "$d" ]; then
			cmd.exe //d //c rmdir /s /q "$(cygpath -w "$d")" || true
			echo "windows: $(free_gb) GB free on C: without $d"
		fi
	done
	echo "windows: $(free_gb) GB free on C:, $need wanted"
	exit 0
fi

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
	df -h /c /d 2>/dev/null || true
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
	df -h /c /d 2>/dev/null || true
	;;
client)
	in_vcvars "cd /d \"$windir\\Telegram\"" \
		"call configure.bat -G \"Ninja Multi-Config\" qt6 -D TDESKTOP_API_ID=$PLUMA_API_ID -D TDESKTOP_API_HASH=$PLUMA_API_HASH -D CMAKE_CONFIGURATION_TYPES=Release -D DESKTOP_APP_DISABLE_AUTOUPDATE=ON -D DESKTOP_APP_DISABLE_CRASH_REPORTS=ON" \
		"cmake --build ..\\out --config Release --parallel"
	exe="$dir/out/Release/Telegram.exe"
	if [ ! -f "$exe" ]; then
		echo "windows: no $exe" >&2
		exit 1
	fi
	echo "windows: $exe ($(du -h "$exe" | awk '{print $1}'))"
	;;
*)
	echo "usage: windows.sh free|libraries|trim|client" >&2
	exit 2
	;;
esac
