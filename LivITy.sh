#!/usr/bin/env bash

CLI53_BIN=/usr/local/bin/cli53
CLI53_SRC=https://github.com/barnybug/cli53/releases/download/0.8.12/cli53-linux-amd64

error_exit ()
{
	echo "$1" 1>&2
	exit 1
}

apt update
apt upgrade
apt install --assume-yes curl python-apt figlet

wget --output-document ${CLI53_BIN} ${CLI53_SRC}
chmod +x ${CLI53_BIN}

cd /home/admin
wget --output-document - "https://www.dropbox.com/download?plat=lnx.x86_64" | tar xzf -
chown -R admin:admin .dropbox-dist/

wget --output-document /usr/local/bin/dropbox "https://www.dropbox.com/download?dl=packages/dropbox.py"
chmod +x "/usr/local/bin/dropbox"

mkdir -p /etc/update-motd.d

cat > /etc/update-motd.d/00-header <<'EOF'
#!/usr/bin/env bash

DISTRIB_DESCRIPTION=`awk -F"[=\"]+" '/VERSION=/ {print $2}' /etc/os-release`

[[ -r /etc/lsb-release ]] && . /etc/lsb-release

if [[ -z $DISTRIB_DESCRIPTION ]] && [[ -x /usr/bin/lsb_release ]]; then
    # Fall back to using the very slow lsb_release utility
    DISTRIB_DESCRIPTION=$(lsb_release -s -d)
fi

figlet `hostname -f | cut -d '.' -f1`
printf "\n"

printf "Welcome to Debian %s (%s).\n" "$DISTRIB_DESCRIPTION" "$(uname -r)"
printf "\n"

EOF

cat > /etc/update-motd.d/10-sysinfo <<'EOF'
#!/usr/bin/env bash

date=`date`
load=`cat /proc/loadavg | awk '{print $1}'`
root_usage=`df -h / | awk '/\// {print $(NF-1)}'`
memory_usage=`free -m | awk '/Mem:/ { total=$2 } /buffers\/cache/ { used=$3 } END { printf("%3.1f%%", used/total*100)}'`
swap_usage=`free -m | awk '/Swap/ { printf("%3.1f%%", "exit !$2;$3/$2*100") }'`
users=`users | wc -w`
time=`uptime | grep -ohe 'up .*' | sed 's/,/\ hours/g' | awk '{ printf $2" "$3 }'`
cpu=Xen
processes=`ps aux | wc -l`
ip=`ifconfig $(route | grep default | awk '{ print $8 }') | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}'`
ipv4=`curl -s http://169.254.169.254/latest/meta-data/public-ipv4`

echo "System information as of: $date"
echo
printf "System load:\t%s\tPublic IP:\t%s\n" $load $ipv4
printf "Platform:\t%s\tPrivate IP:\t%s\n" $cpu $ip
printf "Memory usage:\t%s\tSystem uptime:\t%s\n" $memory_usage "$time"
printf "Usage on /:\t%s\tSwap usage:\t%s\n" $root_usage $swap_usage
printf "Local Users:\t%s\tProcesses:\t%s\n" $users $processes
echo

EOF

cat > /etc/update-motd.d/20-updates <<'EOF'
#!/usr/bin/python

import sys
import subprocess
import apt_pkg

DISTRO = subprocess.Popen(["lsb_release", "-c", "-s"],
                          stdout=subprocess.PIPE).communicate()[0].strip()

class OpNullProgress(object):
    '''apt progress handler which supresses any output.'''
    def update(self):
        pass
    def done(self):
        pass

def is_security_upgrade(pkg):
    '''
    Checks to see if a package comes from a DISTRO-security source.
    '''
    security_package_sources = [("Ubuntu", "%s-security" % DISTRO),
                               ("Debian", "%s-security" % DISTRO)]

    for (file, index) in pkg.file_list:
        for origin, archive in security_package_sources:
            if (file.archive == archive and file.origin == origin):
                return True
    return False

# init apt and config
apt_pkg.init()

# open the apt cache
try:
    cache = apt_pkg.Cache(OpNullProgress())
except SystemError, e:
    sys.stderr.write("Error: Opening the cache (%s)" % e)
    sys.exit(-1)

# setup a DepCache instance to interact with the repo
depcache = apt_pkg.DepCache(cache)

# take into account apt policies
depcache.read_pinfile()

# initialise it
depcache.init()

# give up if packages are broken
if depcache.broken_count > 0:
    sys.stderr.write("Error: Broken packages exist.")
    sys.exit(-1)

# mark possible packages
try:
    # run distro-upgrade
    depcache.upgrade(True)
    # reset if packages get marked as deleted -> we don't want to break anything
    if depcache.del_count > 0:
        depcache.init()

    # then a standard upgrade
    depcache.upgrade()
except SystemError, e:
    sys.stderr.write("Error: Couldn't mark the upgrade (%s)" % e)
    sys.exit(-1)

# run around the packages
upgrades = 0
security_upgrades = 0
for pkg in cache.packages:
    candidate = depcache.get_candidate_ver(pkg)
    current = pkg.current_ver

    # skip packages not marked as upgraded/installed
    if not (depcache.marked_install(pkg) or depcache.marked_upgrade(pkg)):
        continue

    # increment the upgrade counter
    upgrades += 1

    # keep another count for security upgrades
    if is_security_upgrade(candidate):
        security_upgrades += 1

    # double check for security upgrades masked by another package
    for version in pkg.version_list:
        if (current and apt_pkg.version_compare(version.ver_str, current.ver_str) <= 0):
            continue
        if is_security_upgrade(version):
            security_upgrades += 1
            break

print "%d updates to install." % upgrades
print "%d are security updates." % security_upgrades
print "" # leave a trailing blank line

EOF

cat > /etc/update-motd.d/30-livity <<'EOF'
#!/usr/bin/env bash
printf "************* FIRST BOOT ***************\n"
printf "Run the following commands, in the given orders\n"
printf "     1. ~/.dropbox-dist/dropboxd\n"
printf "     2. ~/LivITy.init\n"
printf "     3. history -cw && exit\n"
printf "****************************************\n\n"

EOF

cat > /etc/update-motd.d/99-footer <<'EOF'
#!/usr/bin/env bash

[[] -f /etc/motd.tail ]] && cat /etc/motd.tail || true

EOF

chmod a+x /etc/update-motd.d/*
rm -r /etc/motd
ln -s /var/run/motd /etc/motd

cat > /home/admin/LivITy.init <<'EOF'
#!/usr/bin/env bash

function print_green {
     echo -e "\e[32m${1}\e[0m"
}

print_green 'Starting & Configuring Dropbox'
dropbox start && sleep 5 && dropbox exclude add /home/admin/Dropbox/Apps /home/admin/Dropbox/misc

print_green 'Configuring Dropbox Service'
while [[ ! -f "/home/admin/Dropbox/dot_files/.aws/build/dropbox/dropbox.init" ]]
do
  sleep 2
done
sudo cp /home/admin/Dropbox/dot_files/.aws/build/dropbox/dropbox.init /etc/init.d/dropbox
sudo chmod +x "/etc/init.d/dropbox"

while [[ ! -f "/home/admin/Dropbox/dot_files/.aws/build/dropbox/dropbox.service" ]]
do
  sleep 2
done
sudo cp /home/admin/Dropbox/dot_files/.aws/build/dropbox/dropbox.service /etc/systemd/system/dropbox.service
sudo systemctl daemon-reload &> /dev/null && sudo systemctl enable dropbox.service &> /dev/null

print_green 'Configuring autoroute53 Service'
while [[ ! -f "/home/admin/Dropbox/dot_files/.aws/build/autoroute53/autoroute53.init" ]]
do
  sleep 2
done
sudo cp /home/admin/Dropbox/dot_files/.aws/build/autoroute53/autoroute53.init /etc/init.d/autoroute53
sudo chmod +x /etc/init.d/autoroute53

while [[ ! -f "/home/admin/Dropbox/dot_files/.aws/build/autoroute53/autoroute53.service" ]]
do
  sleep 2
done
sudo cp /home/admin/Dropbox/dot_files/.aws/build/autoroute53/autoroute53.service /etc/systemd/system/autoroute53.service
sudo systemctl daemon-reload &> /dev/null && sudo systemctl enable autoroute53.service &> /dev/null && sudo systemctl start autoroute53

print_green 'Linking Dot-Files'
ln -s /home/admin/Dropbox/dot_files/.aws /home/admin/.aws
rm -R /home/admin/.ssh && ln -s /home/admin/Dropbox/dot_files/.ssh /home/admin/.ssh

print_green 'Clean Apt'
sudo apt-get -y -q=2 autoremove
sudo apt-get -q=2 clean
sudo apt-get -q=2 autoclean

print_green 'Remove SSH keys'
[ -f /home/admin/.ssh/authorized_keys ] && sudo rm /home/admin/.ssh/authorized_keys
sudo shred -u /etc/ssh/*_key /etc/ssh/*_key.pub > /dev/null 2>&1

print_green 'Cleaning history'
shred -u ~/.*history  > /dev/null 2>&1

print_green 'Cleanup log files'
sudo find /var/log -type f | while read f; do echo -ne '' > $f; done

print_green 'Cleanup bash history'
unset HISTFILE
[ -f /home/admin/.bash_history ] && rm /home/admin/.bash_history
> ~/.bash_history && history -cw

sudo rm -r /etc/update-motd.d/30-livity

print_green 'LivITy AMI init complete!'

rm -r /home/admin/LivITy.init

EOF

chown admin:admin /home/admin/LivITy.init
chmod +x /home/admin/LivITy.init
