#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2012-2018 ANSSI. All Rights Reserved.
# Copyright 2010 ANSSI
# Author: Benjamin Morin <clipos@ssi.gouv.fr>
# Distributed under the terms of the GNU Lesser General Public License v2.1

LOGIN_CARDS=/home/user/.smartcards

[[ "${OBJECT}" != "card" ]] && exit 1

CURRENT_USER="$(last -w -f /var/run/utmp | awk '$2 ~ /^:0/ { print $1 }' | head -n 1)"
if [[ -n "${CURRENT_USER}" ]]; then
        CURRENT_UID=$(id -u ${CURRENT_USER})
fi

if [[ -n "${CURRENT_UID}" ]]; then
	if groups "${CURRENT_USER}" | grep -qw "pkauth"; then
		TRIGGER=true

		if [ -f "${LOGIN_CARDS}" ] ; then
			grep -q "${INFO}" "${LOGIN_CARDS}" || TRIGGER=false
		fi

		if ${TRIGGER} ; then
        		if vsctl user enter -u "${CURRENT_UID}" -- /bin/true; then
	                	# If there is a USER session active, lock it 
	                	vsctl user enter -u "${CURRENT_UID}" -- /usr/bin/xcardlock.sh "${ACTION}" "${INFO}" || exit 0
	        	fi
		fi
	fi
fi

