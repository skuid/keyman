#!/usr/bin/env bash

/etc/init.d/ssh start

tail -f /var/log/sshd.log
