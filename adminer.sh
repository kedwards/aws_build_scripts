echo "Adminer init starting...ok"
ADMINERVERSION=4.3.1
HOSTNAME=dbadm
DOMAIN=kevinedwards.ca
PHPVERSION=7.2

if ${SUDO} [ ! -d "/var/www/src/adminer/${ADMINERVERSION}" ]
then
    ${SUDO} mkdir -p "/var/www/src/adminer/${ADMINERVERSION}" > /dev/null
    ${SUDO} [ ! -d "/var/www/src/adminer/${ADMINERVERSION}" ] && error_exit 'creating adminer web src...failed'
fi

if ${SUDO} [ ! -e "/var/www/src/adminer/${ADMINERVERSION}/index.php" ]
then
    ${SUDO} wget -q -O "/var/www/src/adminer/${ADMINERVERSION}/index.php" https://www.adminer.org/latest-mysql-en.php > /dev/null
    ${SUDO} [ ! -e "/var/www/src/adminer/${ADMINERVERSION}/index.php" ] && error_exit 'retrieving adminer...failed'
fi

if ${SUDO} [ ! -e "/etc/nginx/sites-available/${HOSTNAME}.${DOMAIN}" ]
then
    set_vhost ${HOSTNAME} ${PHPVERSION}
fi

${SUDO} chown -R www-data:www-data /var/www/src/adminer
${SUDO} find /var/www/src/adminer -type d -exec chmod 775 {} \;
${SUDO} find /var/www/src/adminer -type f -exec chmod 664 {} \;

if ${SUDO} [ ! -L /var/www/${HOSTNAME}.${DOMAIN} ]
then
    ${SUDO} ln -s /var/www/src/adminer/${ADMINERVERSION} /var/www/${HOSTNAME}.${DOMAIN}
    ${SUDO} [ ! -L /var/www/${HOSTNAME}.${DOMAIN} ] && error_exit  'linking adminer web src...failed'
fi
    
get_ssl ${HOSTNAME}

cli53 rrcreate --replace ${DOMAIN} "${HOSTNAME} 300 CNAME www.kevinedwards.ca." > /dev/null
[ $? -eq 1 ] && error_exit "setting adminer dns...failed"

echo "Adminer init completed...ok"