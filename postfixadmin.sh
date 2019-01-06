echo "Postfixadmin init starting...ok"

HOSTNAME=mailadm
DOMAIN=kevinedwards.ca
DBNAME=mail
DBUSER=mailadmin
DBUSERPASSWORD=
DBPASSWORD=''
POSTFIXADMINVERSION=3.1
POSTFIXADMINBIN=https://github.com/postfixadmin/postfixadmin/archive/postfixadmin-${POSTFIXADMINVERSION}.tar.gz
PHPVERSION=7.2

if ${SUDO} [ ! -d "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}" ]
then
    ${SUDO} mkdir -p "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}"
    if ${SUDO} [ ! -e "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}/postfixadmin-${POSTFIXADMINVERSION}.tar.gz" ]
    then
        ${SUDO} wget -q ${POSTFIXADMINBIN}
    fi
    ${SUDO} tar xf "postfixadmin-${POSTFIXADMINVERSION}.tar.gz" -C "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}" --strip-components=1
    ${SUDO} mkdir -p "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}/templates_c"
fi

if ${SUDO} [ ! -e "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}/config.local.php" ]
then
    ${SUDO} tee "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}/config.local.php" > /dev/null << EOF
<?php                                                                                                                                                                                                                                 
    \$CONF['configured'] = true;
    \$CONF['setup_password'] = '';
    \$CONF['default_language'] = 'en';
    \$CONF['database_type'] = 'mysqli';
    \$CONF['database_host'] = 'db.${DOMAIN}';
    \$CONF['database_user'] = '${DBUSER}';
	\$CONF['database_password'] = '${DBUSERPASSWORD}';
    \$CONF['database_name'] = '${DBNAME}';
    \$CONF['admin_email'] = 'postmaster@${DOMAIN}';
    \$CONF['smtp_server'] = 'mail.${DOMAIN}';
    \$CONF['smtp_port'] = '25';
    \$CONF['encrypt'] = 'md5crypt';
    \$CONF['authlib_default_flavor'] = 'md5raw';
    \$CONF['dovecotpw'] = "/usr/sbin/doveadm pw";
    \$CONF['default_aliases'] = array (
        'abuse' => 'abuse@${DOMAIN}',
        'hostmaster' => 'hostmaster@${DOMAIN}',
        'postmaster' => 'postmaster@${DOMAIN}',
        'webmaster' => 'webmaster@${DOMAIN}'
    );
    \$CONF['domain_path'] = 'YES';
    \$CONF['domain_in_mailbox'] = 'NO';
    \$CONF['show_footer_text'] = 'YES';
    \$CONF['footer_text'] = 'Return to ${DOMAIN}';
    \$CONF['footer_link'] = 'https://www.${DOMAIN}';
EOF
    ${SUDO} [ ! -e "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}/config.local.php" ] && error_exit 'postfixadmin config...failed'
fi

set_vhost ${HOSTNAME} ${PHPVERSION}

${SUDO} chown -R www-data:www-data /var/www/src/postfixadmin
${SUDO} find /var/www/src/postfixadmin -type d -exec chmod 775 {} \;
${SUDO} find /var/www/src/postfixadmin -type f -exec chmod 664 {} \;

if ${SUDO} [ ! -L "/var/www/${HOSTNAME}.${DOMAIN}" ]
then
    ${SUDO} ln -s "/var/www/src/postfixadmin/${POSTFIXADMINVERSION}" "/var/www/${HOSTNAME}.${DOMAIN}"
    ${SUDO} [ ! -L "/var/www/${HOSTNAME}.${DOMAIN}" ] && error_exit 'creating postfixadmn web src...failed'
fi

get_ssl ${HOSTNAME}

mysql -u kedwards -h db.kevinedwards.ca -p${DBPASSWORD}<<EOF
USE mysql;
CREATE DATABASE IF NOT EXISTS mail CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';
CREATE USER IF NOT EXISTS '${DBUSER}'@'%' IDENTIFIED BY '${DBUSERPASSWORD}';
GRANT ALL PRIVILEGES ON mail.* to '${DBUSER}'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
if [ $? -eq 1 ]
then
	error_exit 'configuring mariadb user...failed'
fi

mysql -u kedwards -h db.kevinedwards.ca -p${DBPASSWORD}<<"EOF"
USE mail;
CREATE TABLE IF NOT EXISTS `tlspolicies` (
    `id` int unsigned NOT NULL AUTO_INCREMENT,
    `domain` varchar(255) NOT NULL,
    `policy` enum('none', 'may', 'encrypt', 'dane', 'dane-only', 'fingerprint', 'verify', 'secure') NOT NULL,
    `params` varchar(255),
    PRIMARY KEY (`id`),
    UNIQUE KEY (`domain`)
);
EOF
if [ $? -eq 1 ]
then
	error_exit 'configuring mariadb table...failed'
fi

echo "Postfixadmin init completed...ok"
