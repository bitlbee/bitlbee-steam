libdir = $(plugindir)
lib_LTLIBRARIES = steam.la

steam_la_CFLAGS = \
	$(BITLBEE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

steam_la_LDFLAGS = \
	$(BITLBEE_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

steam_la_SOURCES = \
	steam.c \
	steam.h \
	steam-api.c \
	steam-api.h \
	steam-crypt.c \
	steam-crypt.h \
	steam-glib.h \
	steam-http.c \
	steam-http.h \
	steam-id.h \
	steam-json.c \
	steam-json.h \
	steam-user.c \
	steam-user.h \
	steam-util.c \
	steam-util.h

# Build the library as a module
steam_la_LDFLAGS += -module -avoid-version
