#!/bin/bash
# This script cleans up your EC2 instance before baking a new AMI.

. ~/.aws/build/LivITy_common.sh

print_green 'Clean Apt'
${SUDO} apt-get -y -q=2 autoremove
${SUDO} apt-get -q=2 clean
${SUDO} apt-get -q=2 autoclean

print_green 'Remove SSH keys'
#[ -f /home/admin/.ssh/authorized_keys ] && ${SUDO} rm /home/admin/.ssh/authorized_keys
${SUDO} shred -u /etc/ssh/*_key /etc/ssh/*_key.pub > /dev/null 2>&1

print_green 'Cleaning history'
shred -u ~/.*history  > /dev/null 2>&1

print_green 'Cleanup log files'
${SUDO} find /var/log -type f | while read f; do echo -ne '' > ${SUDO} tee $f > /dev/null; done

print_green 'Cleanup bash history'
unset HISTFILE
[ -f /home/admin/.bash_history ] && rm /home/admin/.bash_history
> ~/.bash_history && history -cw

print_green 'AMI cleanup complete!'
