# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2012-2018 ANSSI. All Rights Reserved.
# Copyright 2012 SGDSN/ANSSI
# Distributed under the terms of the GNU Lesser General Public License v2.1

CFLAGS+=-Wall -ansi -D_POSIX_C_SOURCE=201209L -fsigned-char -DLINE_MAX_SIZE=256


monitor_SRC:=smartcard_monitor.c
monitor_BIN:=smartcard_monitor

monitor_CFLAGS:=$(shell pkg-config --cflags libpcsclite) $(CFLAGS)
monitor_LDFLAGS:=$(shell pkg-config --libs libpcsclite) -lpthread $(LDFLAGS)



notifier_SRC:=smartcard_notifier.c
notifier_BIN:=smartcard_notifier

notifier_CFLAGS:=$(CFLAGS)
notifier_LDFLAGS:=$(LDFLAGS)

notifier_OBJ:=$(patsubst %.c,%.o,$(notifier_SRC))



list_SRC:=smartcard_list.c
list_BIN:=smartcard_list

list_CFLAGS:=$(CFLAGS)
list_LDFLAGS:=$(LDFLAGS)

list_OBJ:=$(patsubst %.c,%.o,$(list_SRC))


BINS:=monitor notifier list




################################



.PHONY: clean

default: $(BINS)





define ObjectMaker

$(1): $(patsubst %.o,%.c,$(1))
	$(CC) -c -o $(1) $$($(2)_CFLAGS) $$<

endef





define ExeMaker

$(1)_OBJ:=$$(patsubst %.c,%.o,$$($(1)_SRC))

$(1): $$($(1)_BIN)

$$($(1)_BIN): $$($(1)_OBJ)
	$(CC) -o $$($(1)_BIN) $$($(1)_CFLAGS) $$($(1)_LDFLAGS) $$($(1)_OBJ)

.PHONY: $(1) $(1)_clean

clean: $(1)_clean

$(1)_clean:
	$(RM) $$($(1)_BIN) $$($(1)_OBJ)

$$(eval $$(foreach o,$$($(1)_OBJ),$$(call ObjectMaker,$$(o),$(1))))

endef







$(eval $(foreach i,$(BINS),$(call ExeMaker,$(i))))





