libdir           = $(plugindir)
lib_LTLIBRARIES  = steam.la

steam_la_CFLAGS  = $(BITLBEE_CFLAGS) $(GLIB_CFLAGS) $(GMP_CFLAGS)
steam_la_LDFLAGS = $(BITLBEE_LIBS)   $(GLIB_LIBS)   $(GMP_LIBS)
steam_la_SOURCES = \
	steam.c \
	steam-api.c \
	steam-http.c \
	steam-json.c \
	steam-user.c \
	steam-util.c

# Build the library as a module
steam_la_LDFLAGS += -module -avoid-version
