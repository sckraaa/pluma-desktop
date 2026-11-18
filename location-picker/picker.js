var LocationPicker = {
	startZoom: 14,
	flySpeed: 2.4,
	// The server's data goes to zoom 15; above it the map is drawn larger,
	// up to the limit the Android client has too.
	maxZoom: 18,
	notify: function(message) {
		if (window.external && window.external.invoke) {
			window.external.invoke(JSON.stringify(message));
		}
	},
	frameKeyDown: function (e) {
		const keyW = (e.key === 'w')
			|| (e.code === 'KeyW')
			|| (e.keyCode === 87);
		const keyQ = (e.key === 'q')
			|| (e.code === 'KeyQ')
			|| (e.keyCode === 81);
		const keyM = (e.key === 'm')
			|| (e.code === 'KeyM')
			|| (e.keyCode === 77);
		if ((e.metaKey || e.ctrlKey) && (keyW || keyQ || keyM)) {
			e.preventDefault();
			LocationPicker.notify({
				event: 'keydown',
				modifier: e.ctrlKey ? 'ctrl' : 'cmd',
				key: keyW ? 'w' : keyQ ? 'q' : 'm',
			});
		} else if (e.key === 'Escape' || e.keyCode === 27) {
			e.preventDefault();
			LocationPicker.notify({
				event: 'keydown',
				key: 'escape',
			});
		}
	},
	isNight: function() {
		var html = document.getElementsByTagName('html')[0];
		return html.style.getPropertyValue('--td-night') == '1';
	},
	// The style of the Pluma server in the language of the labels, its dark
	// variant in a dark theme: <base>/styles/<language>[-dark]/style.json.
	styleUrl: function() {
		var id = LocationPicker.style + (LocationPicker.isNight() ? '-dark' : '');
		return LocationPicker.base
			+ '/styles/'
			+ encodeURIComponent(id)
			+ '/style.json';
	},
	updateStyles: function (styles) {
		if (LocationPicker.styles !== styles) {
			LocationPicker.styles = styles;
			document.getElementsByTagName('html')[0].style = styles;

			if (LocationPicker.map) {
				var url = LocationPicker.styleUrl();
				if (LocationPicker.styleShown !== url) {
					LocationPicker.styleShown = url;
					LocationPicker.map.setStyle(url);
				}
			}
		}
	},
	// On macOS and Linux the page is not at desktop-app-resource: there the
	// webview fetches the server for it at <page origin>/<host>/<path>
	// (lib_webview's dataRequestRedirectHost, the server's host), as for
	// upstream's page. Windows fetches the server itself.
	request: function(url) {
		var prefix = LocationPicker.server + '/';
		if (LocationPicker.proxy
			&& url.substring(0, prefix.length).toLowerCase() === prefix) {
			return {
				url: LocationPicker.proxy + url.substring('https://'.length),
			};
		}
		return { url: url };
	},
	// The page reaches its own origin and the server alone. A webview that
	// ignores a policy added by a script loads the map all the same.
	restrictNetwork: function(own) {
		var sources = own + ' ' + LocationPicker.server;
		var meta = document.createElement('meta');
		meta.httpEquiv = 'Content-Security-Policy';
		meta.content = 'connect-src ' + sources
			+ '; img-src ' + sources + ' data: blob:'
			+ '; worker-src blob:'
			+ '; child-src blob:';
		document.head.appendChild(meta);
	},
	init: function (params) {
		var base = String(params.base || '').replace(/\/+$/, '');
		var server = /^https:\/\/[^\/?#@:]+/i.exec(base);
		// A webview too old for MapLibre's script leaves maplibregl undefined.
		if (typeof maplibregl === 'undefined' || !server || !params.style) {
			LocationPicker.notify({ event: 'error' });
			return;
		}
		LocationPicker.base = base;
		LocationPicker.server = server[0].toLowerCase();
		LocationPicker.style = String(params.style);
		var own = location.protocol + '//' + location.host;
		if (location.hostname != 'desktop-app-resource') {
			LocationPicker.proxy = own + '/';
		}
		LocationPicker.restrictNetwork(own);

		LocationPicker.styleShown = LocationPicker.styleUrl();
		var options = {
			container: 'map',
			style: LocationPicker.styleShown,
			maxZoom: LocationPicker.maxZoom,
			transformRequest: LocationPicker.request,
			// The data of OpenStreetMap: its credit stays in full view (ODbL).
			attributionControl: { compact: false },
		};
		var center = params.center;
		if (center) {
			center = [center[1], center[0]];
			options.center = center;
			options.zoom = LocationPicker.startZoom;
		} else if (params.bounds) {
			options.bounds = params.bounds;
			center = new maplibregl.LngLatBounds(params.bounds).getCenter();
		} else {
			center = [0, 0];
		}
		try {
			LocationPicker.map = new maplibregl.Map(options);
		} catch (e) {
			// MapLibre GL JS needs WebGL 2.
			LocationPicker.notify({ event: 'error' });
			return;
		}
		LocationPicker.createMarker(center);
		LocationPicker.trackMovement();
	},
	marker: function() {
		return document.getElementById('marker_drop');
	},
	createMarker: function(center) {
		document.getElementById('marker').style.display = 'flex';
	},
	clearMovingTimer: function() {
		if (LocationPicker.clearMovingTimeoutId) {
			clearTimeout(LocationPicker.clearMovingTimeoutId);
			LocationPicker.clearMovingTimeoutId = 0;
		}
	},
	startMovingTimer: function(done) {
		LocationPicker.clearMovingTimer();
		LocationPicker.clearMovingTimeoutId = setTimeout(done, 500);
	},
	trackMovement: function() {
		LocationPicker.map.on('movestart', function() {
			LocationPicker.marker().classList.add('moving');
			LocationPicker.clearMovingTimer();
			LocationPicker.notify({ event: 'move_start' });
		});
		LocationPicker.map.on('moveend', function() {
			LocationPicker.startMovingTimer(function() {
				LocationPicker.marker().classList.remove('moving');
				LocationPicker.notify({
					event: 'move_end',
					latitude: LocationPicker.map.getCenter().lat,
					longitude: LocationPicker.map.getCenter().lng
				});
			});
		});
	},
	narrowTo: function (point) {
		if (!LocationPicker.map) {
			return;
		}
		LocationPicker.map.flyTo({
			center: [point[1], point[0]],
			zoom: LocationPicker.startZoom,
			speed: LocationPicker.flySpeed,
		});
	},
	send: function () {
		LocationPicker.notify({
			event: 'send',
			latitude: LocationPicker.map.getCenter().lat,
			longitude: LocationPicker.map.getCenter().lng
		});
	},
};
