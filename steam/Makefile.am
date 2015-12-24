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
	steam-api.c \
	steam-crypt.c \
	steam-http.c \
	steam-json.c \
	steam-user.c \
	steam-util.c \
	steam.h \
	steam-api.h \
	steam-crypt.h \
	steam-http.h \
	steam-id.h \
	steam-json.h \
	steam-user.h \
	steam-util.h

# Build the library as a module
steam_la_LDFLAGS += -module -avoid-version
