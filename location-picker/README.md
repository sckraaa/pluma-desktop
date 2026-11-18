# Location picker

The page of the app's location picker (`Ui::LocationPicker`), which `ci/patch.py` builds into the app in place of upstream's (task 112 of the server repository):

- `picker.js` replaces `Telegram/Resources/picker_html/picker.js`: MapLibre GL JS in place of Mapbox GL JS, the Pluma server's style, light or dark as the app's theme, in the language the app chooses (`MapsStyle` in `location_picker.cpp`).
- `maplibre-gl.js`, `maplibre-gl.css` and `maplibre-gl-LICENSE.txt` are MapLibre GL JS 5.24.0 (BSD-3-Clause) as npm publishes it: `dist/maplibre-gl.js`, `dist/maplibre-gl.css` and `LICENSE.txt` of `maplibre-gl-5.24.0.tgz` (`sha512-ALyFxgtd5R+65UqZ/++lOqwWcC0SNho9c27fYSyLmG7AfnAul2o46F05aDJGPbFU57wos9dgcIySHs0Xe6ia3A==`). The patch checks their SHA-256 (`MAPLIBRE_FILES`) and adds them to the resources of the picker (`picker.qrc`).

MapLibre GL JS 5 is the line whose single file carries its worker and starts it from a `blob:` URL, as Mapbox GL JS did on upstream's page. Version 6 is an ES module whose worker is another file, found next to the module only on an `http(s)` page, while macOS shows the picker on `desktopappresource://`.

To update MapLibre: take the newest 5.x release that is at least two weeks old, check the tarball against the `integrity` of the npm registry, copy the three files here, and change `MAPLIBRE_VERSION` and `MAPLIBRE_FILES` in `ci/patch.py`.
