libdir           = @plugindir@
lib_LTLIBRARIES  = steam.la

steam_la_CFLAGS  = $(BITLBEE_CFLAGS) $(GLIB_CFLAGS)
steam_la_LDFLAGS = -module -avoid-version
steam_la_SOURCES = steam.c steam-api.c steam-http.c steam-util.c
