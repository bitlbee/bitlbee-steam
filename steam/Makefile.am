libdir           = @plugindir@
lib_LTLIBRARIES  = steam.la

steam_la_CFLAGS  = $(BITLBEE_CFLAGS) $(GLIB_CFLAGS) -I../bitlbee
steam_la_LDFLAGS = -module -avoid-version @GMP_LIBS@
steam_la_SOURCES = \
	steam.c \
	steam-api.c \
	steam-auth.c \
	steam-glib.c \
	steam-http.c \
	steam-json.c
