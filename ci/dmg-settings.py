# The settings of dmgbuild for Pluma's DMG (ci/make-dmg.sh -D app=... -D
# background=...): the app and a link to /Applications in a window of the
# size of brand/dmg/background.png, the icons at the centres the background
# draws its arrow between (brand/dmg/background.html), no toolbar, sidebar or
# status bar. No hide_extensions: SetFile -a E puts Finder information on the
# bundle, which codesign --strict refuses; Finder hides .app itself. UDZO: read-only, zlib-compressed, the format Apple notarizes
# (hdiutil(1) marks dmgbuild's default UDBZ deprecated).
import os.path

app = defines["app"]  # noqa: F821 (dmgbuild's globals)
files = [app]
symlinks = {"Applications": "/Applications"}
format = "UDZO"
filesystem = "HFS+"
background = defines["background"]  # noqa: F821
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
window_rect = ((200, 120), (640, 400))
default_view = "icon-view"
icon_size = 128
text_size = 13
icon_locations = {os.path.basename(app): (170, 190), "Applications": (470, 190)}
