#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2012-2018 ANSSI. All Rights Reserved.
# Copyright 2010 ANSSI
# Author: Benjamin Morin <clipos@ssi.gouv.fr>
# Distributed under the terms of the GNU Lesser General Public License v2.1

ACTION="${1}"
INFO="${2}"

export DISPLAY=:0
export XAUTHORITY=/home/user/.Xauthority

XSCREENSAVERCMD=/usr/local/bin/xscreensaver-command
XSCREENSAVERLOCK=/usr/local/bin/xscreensaver-lock.sh

function lock() {
        ${XSCREENSAVERCMD} -time | grep -q locked && exit 0

        ${XSCREENSAVERLOCK}

        for i in 1 2 3 4 5; do
                ${XSCREENSAVERCMD} -time | grep -q locked && exit 0
                sleep 0.5
        done

        # lock cancelled
        exit 1
}

function unlock() {
        ${XSCREENSAVERCMD} -deactivate
}


case "${ACTION}" in
        "remove")
                lock
                ;;
        "add")
                unlock
                ;;
        *)
                exit 1
                ;;
esac

