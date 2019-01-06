#!/usr/bin/env bash -e
HOSTNAME='db'
DOMAIN='kevinedwards.ca'
CODENAME=$(lsb_release -sc)
PUBLIC_IPV4=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

PHPVERSION='7.2'
DBSIGNKEY='F1656F24C74CD1D8'
DBVERSION='10.3'
DBUSER=kedwards
DBUSERPASSWORD=''
DBPASSWORD=''
DBSECURITYGROUPID='sg-b3fe22da'
PACKAGES="certbot mariadb-server-${DBVERSION}"

source ~/.aws/build/common

init ${HOSTNAME} ${DOMAIN}

# if ${SUDO} [ ! -e /etc/apt/sources.list.d/mariadb.list ]
# then
#     ${SUDO} apt install -q=2 -y software-properties-common dirmngr
#     ${SUDO} apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xF1656F24C74CD1D8 > /dev/null 2>&1
#     ${SUDO} add-apt-repository 'deb [arch=amd64,i386,ppc64el] http://mariadb.mirror.anstey.ca/repo/10.3/debian stretch main'sudo



#     ${SUDO} apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0x${DBSIGNKEY} > /dev/null 2>&1
#     ${SUDO} tee /etc/apt/sources.list.d/mariadb.list > /dev/null << EOF
# # MariaDB 10.3 repository list - created 2018-09-17 00:15 UTC
# # http://downloads.mariadb.org/mariadb/repositories/
# deb [arch=amd64,i386,ppc64el] http://mariadb.mirror.anstey.ca/repo/${DBVERSION}/debian ${CODENAME} main
# deb-src http://mariadb.mirror.anstey.ca/repo/${DBVERSION}/debian ${CODENAME} main
# EOF
#     if ! $(grep -q "deb \[arch=amd64,i386,ppc64el\] http://mariadb.mirror.anstey.ca/repo/${DBVERSION}/debian ${CODENAME} main" /etc/apt/sources.list.d/mariadb.list)
#     then
#         error_exit 'repository setup...failed'
#     fi
# fi

# echo "${DBVERSION} mysql-server/root_password password ${DBPASSWORD}" | ${SUDO} debconf-set-selections || error_exit 'debconf-set-selections...failed'
# echo "${DBVERSION} mysql-server/root_password_again password ${DBPASSWORD}" | ${SUDO} debconf-set-selections || error_exit 'debconf-set-selections...failed'

get_updates
get_packages ${PACKAGES}

if ! $(grep -q '^#bind-address\s*= 127.0.0.1$' /etc/mysql/my.cnf)
then
    ${SUDO} sed -Ei.bak 's|^bind-address\s*= 127.0.0.1$|#bind-address = 127.0.0.1|' /etc/mysql/my.cnf
    if ! $(grep -q '^#bind-address\s*= 127.0.0.1$' /etc/mysql/my.cnf)
    then
        error_exit 'configuring mariadb...failed'
    fi

    mysql -u root -p <<EOF
CREATE USER IF NOT EXISTS '${DBUSER}'@'localhost' IDENTIFIED BY '${DBUSERPASSWORD}';
GRANT ALL PRIVILEGES ON *.* to '${DBUSER}'@'localhost' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS '${DBUSER}'@'%' IDENTIFIED BY '${DBUSERPASSWORD}';
GRANT ALL PRIVILEGES ON *.* to '${DBUSER}'@'%' WITH GRANT OPTION;
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.db WHERE Db='test' OR Db='test_%';
FLUSH PRIVILEGES;
EOF
    [ $? -eq 1 ] && error_exit 'configuring mariadb...failed'
fi

cli53 rrcreate --replace ${DOMAIN} "${HOSTNAME} 60 A ${PUBLIC_IPV4}" > /dev/null
[ $? -eq 1 ] && error_exit "setting dns...failed"
