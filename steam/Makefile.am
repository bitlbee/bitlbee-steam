lib_LTLIBRARIES  = steam.la
steamdir         = $(libdir)/bitlbee

steam_la_CFLAGS  = $(BITLBEE_CFLAGS)      $(GLIB_CFLAGS) $(JSON_CFLAGS)
steam_la_LDFLAGS = -module -avoid-version $(GLIB_LIBS)   $(JSON_LIBS)
steam_la_SOURCES = steam.c steam-api.c
