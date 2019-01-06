#!/bin/sh -e
HOSTNAME=www
DOMAIN=kevinedwards.ca
CODENAME=$(lsb_release -sc)
PUBLIC_IPV4=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PHPVERSION=7.2
PACKAGES="nginx certbot mariadb-client unzip git php${PHPVERSION}-imagick php${PHPVERSION}-fpm php${PHPVERSION}-cli php${PHPVERSION}-mbstring php${PHPVERSION}-mysql php${PHPVERSION}-imap php${PHPVERSION}-opcache php${PHPVERSION}-curl php${PHPVERSION}-xml php${PHPVERSION}-gd php${PHPVERSION}-zip php${PHPVERSION}-intl"
CRONCOMMAND='certbot renew --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx" --renew-hook "systemctl reload nginx" --quiet'
CRONJOB="@weekly ${CRONCOMMAND}"

. ~/.aws/build/LivITy_common.sh

init ${HOSTNAME}

if ${SUDO} [ ! -e /etc/apt/sources.list.d/deb.sury.list ]
then
    ${SUDO} wget -q -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
    echo "deb https://packages.sury.org/php/ ${CODENAME} main" | ${SUDO} tee /etc/apt/sources.list.d/deb.sury.list > /dev/null
    if ! $(grep -q "deb https://packages.sury.org/php/ ${CODENAME} main" "/etc/apt/sources.list.d/deb.sury.list")
    then
        error_exit "repository setup...failed"
    fi
fi

get_updates
get_packages ${PACKAGES}

###

if ${SUDO} [ ! -e "/etc/php/${PHPVERSION}/fpm/php.ini.bak" ]
then
    ${SUDO} sed -i.bak 's|;date.timezone =|date.timezone = America/Edmonton|' "/etc/php/${PHPVERSION}/fpm/php.ini"
    if  ! $(grep -q 'date.timezone = America/Edmonton' "/etc/php/${PHPVERSION}/fpm/php.ini")
    then
        error_exit 'configuring php...failed'
    fi
fi

if ${SUDO} [ ! -e /etc/ssl/certs/dhparam.pem ]
then
    ${SUDO} openssl dhparam -dsaparam -out /etc/ssl/certs/dhparam.pem 2048 > /dev/null 2>&1
    ${SUDO} [ ! -e /etc/ssl/certs/dhparam.pem ] && error_exit 'creating Diffie–Hellman key...failed'
fi

if ${SUDO} [ ! -e /etc/nginx/passwd ]
then
    printf "kedwards:`openssl passwd -apr1`\n" | ${SUDO} tee /etc/nginx/passwd > /dev/null
    if [ $? -eq 1 ]
    then
        error_exit 'creating http passwd...failed'
    else
        ${SUDO} chown www-data:www-data /etc/nginx/passwd
        ${SUDO} chmod 600 /etc/nginx/passwd
    fi
fi

###

set_vhost ${HOSTNAME} ${PHPVERSION}
web_root ${HOSTNAME}

${SUDO} systemctl stop nginx > /dev/null 2>&1
if [ $? -eq 1 ]; then
    error_exit "stopping nginx...failed"
fi

get_ssl ${HOSTNAME}

#aws route53 list-resource-record-sets --hosted-zone-id Z2K174UVVCW6BH --query "ResourceRecordSets[?Name == '_dmarc.kevinedwards.ca.']" | grep "rua=mailto:postmaster@kevinedwards.ca; ruf=mailto:postmaster@kevinedwards.ca;"
if ! aws route53 list-resource-record-sets --hosted-zone-id ${HOSTEDZONE} --query "ResourceRecordSets[?Name == 'www.kevinedwards.ca.']" > /dev/null 2>&1
then
    cli53 rrcreate --replace ${DOMAIN} "${HOSTNAME} 60 A ${PUBLIC_IPV4}" > /dev/null
    [ $? -eq 1 ] && error_exit "setting dns...failed"
fi

. ~/.aws/build/adminer.sh

. ~/.aws/build/roundcube.sh

. ~/.aws/build/postfixadmin.sh

${SUDO} systemctl start nginx > /dev/null 2>&1
if [ $? -eq 1 ]; then
    error_exit "starting nginx...failed"
fi

crontab -l | grep -v -F "${CRONCOMMAND}" ; echo "${CRONJOB}" | crontab -
if [ $? -eq 1 ]
then
    error_exit 'writing cronjob...failed'
fi
