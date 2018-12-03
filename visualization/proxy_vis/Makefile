#gcc `pkg-config --cflags gtk+-3.0` -o example-3 example-3.c `pkg-config --libs gtk+-3.0`

CFLAGS_DBUS = $(shell pkg-config --cflags --libs dbus-1)
CFLAGS_DBUS_GLIB = $(shell pkg-config --cflags --libs dbus-glib-1 gio-unix-2.0)
CFLAGS_GIO  = $(shell pkg-config --cflags --libs gio-2.0)
CFLAGS_GTK = $(shell pkg-config --cflags gtk+-3.0 --libs gtk+-3.0)

DEPS = dbus_rcm_proxy_vis.h
OBJ = dbus_rcm_proxy_vis.o client_filter_window.o proxy_init_window.o main_window.o
HEADERS = $(shell find . -name '*.h')

CFLAGS = -g -Wall -Werror

# add dbus-test-server in all if you want to compile it with make
all: dbus_rcm_proxy_vis

%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS) $(CFLAGS_GIO) $(CFLAGS_GTK)

dbus_rcm_proxy_vis: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(CFLAGS_GIO) $(CFLAGS_GTK)

clean:
	rm -f dbus_rcm_proxy_vis
	rm -f dbus_rcm_proxy_vis.o
	rm -f client_filter_window.o
	rm -f proxy_init_window.o
	rm -f main_window.o

.PHONY: all clean
