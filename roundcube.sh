echo "Roundcube init starting...ok"
HOSTNAME=webmail
DOMAIN=kevinedwards.ca
ROUNDCUBEVERSION=1.3.3
ROUNDCUBEBIN=roundcubemail-1.3.3.tar.gz
ROUNDCUBEURL=https://github.com/roundcube/roundcubemail/releases/download/${ROUNDCUBEVERSION}/${ROUNDCUBEBIN}
DBUSER=mailadmin
DBUSERPASSWORD=
DBPASSWORD=''
PHPVERSION=7.2

if ${SUDO} [ ! -d "/var/www/src/roundcube/${ROUNDCUBEVERSION}" ]
then
    ${SUDO} mkdir -p /var/www/src/roundcube
    ${SUDO} [ ! -d /var/www/src/roundcube ] && error_exit 'creating roundcube web src...failed'
fi

if ${SUDO} [ ! -f "/var/www/src/roundcube/${ROUNDCUBEVERSION}/index.php" ]
then
    if [ ! -e "/var/www/src/roundcube/${ROUNDCUBEBIN}" ]
    then
        ${SUDO} wget -q -O "/var/www/src/roundcube/${ROUNDCUBEBIN}" "${ROUNDCUBEURL}"
        ${SUDO} [ ! -e "/var/www/src/roundcube/${ROUNDCUBEBIN}" ] && error_exit 'downloading roundcube...failed'
    fi
    
    ${SUDO} tar xf "/var/www/src/roundcube/${ROUNDCUBEBIN}" --directory /var/www/src/roundcube/
	${SUDO} mv "/var/www/src/roundcube/roundcubemail-${ROUNDCUBEVERSION}" "/var/www/src/roundcube/${ROUNDCUBEVERSION}"
	${SUDO} rm -r "/var/www/src/roundcube/${ROUNDCUBEBIN}"
    ${SUDO} [ ! -f "/var/www/src/roundcube/${ROUNDCUBEVERSION}/index.php" ] && error_exit 'creating roundcube web src...failed'
fi

if ${SUDO} [ ! -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/config/config.inc.php" ]
then
    ${SUDO} tee "/var/www/src/roundcube/${ROUNDCUBEVERSION}/config/config.inc.php" > /dev/null <<EOF
<?php
\$config = []
\$config['enable_installer'] = false;
\$config['db_dsnw'] = 'mysql://${DBUSER}:${DBUSERPASSWORD}@db.kevinedwards.ca/webmail';
\$config['default_host'] = 'ssl://mail.kevinedwards.ca';
\$config['default_port'] = 993;
\$config['smtp_server'] = 'tls://mail.kevinedwards.ca';
\$config['smtp_port'] = 25;
\$config['smtp_conn_options'] = [
    'ssl' => [
        'verify_peer'  => false,
        'verify_peer_name' => false,
    ]
];
\$config['username_domain'] = 'kevinedwards.ca';
\$config['smtp_port'] = 587;
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['support_url'] = 'https://www.kevinedwards.ca/support';
\$config['product_name'] = 'kevinedwards.ca Webmail';
\$config['des_key'] = 'g6hf5d4fdjd)8$#gdbtryhed';
\$config['plugins'] = [
    'archive',
    'zipdownload',
    'enigma',
    'contextmenu',
    'markasjunk2',
    'authres_status',
    'show_pgp_mime',
    'contextmenu_folder',
    'infinitescroll',
    'automatic_addressbook_ng',
    'dropbox_attachments',
	'managesieve'
];
\$config['skin'] = 'larry';	  
EOF
    [ ! -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/config/config.inc.php" ] && error_exit 'creating roundcube config...failed'
fi
    
if ${SUDO} [ ! -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/composer.json" ]
then
    ${SUDO} tee "/var/www/src/roundcube/${ROUNDCUBEVERSION}/composer.json" > /dev/null <<EOF
{
    "name": "roundcube/roundcubemail",
    "description": "The Roundcube Webmail suite",
    "license": "GPL-3.0+",
    "repositories": [
        {
            "type": "composer",
            "url": "https://plugins.roundcube.net/"
        },
        {
            "type": "vcs",
            "url": "https://git.kolab.org/diffusion/PNL/php-net_ldap.git"
        }
    ],
    "minimum-stability": "dev", 
    "prefer-stable": true,
    "require": {
        "php": ">=5.4.0",
        "pear/pear-core-minimal": "~1.10.1",
        "pear/net_socket": "~1.2.1",
        "pear/auth_sasl": "~1.1.0",
        "pear/net_idna2": "~0.2.0",
        "pear/mail_mime": "~1.10.0",
        "pear/net_smtp": "~1.7.1",
        "pear/crypt_gpg": "~1.6.0",
        "pear/net_sieve": "~1.4.0",
        "roundcube/plugin-installer": "~0.1.6",
        "endroid/qrcode": "~1.6.5",
        "johndoh/contextmenu": "^2.3",
        "johndoh/markasjunk2": "^1.11",
        "angrychimp/php-dkim": "dev-master",
        "roundcube/authres_status": "^0.4.0",
        "posteo/show_pgp_mime": "dev-master",
        "random-cuber/contextmenu_folder": "^1.3",
        "melanie2/infinitescroll": "dev-master",
        "teon/automatic_addressbook_ng": "^0.0.1",
        "hassansin/dropbox_attachments": "^1.0",
        "johndoh/globaladdressbook": "^1.10"
    },
    "require-dev": {
        "phpunit/phpunit": "^4.8.36 || ^5.7.15"
    },
    "suggest": {
        "pear/net_ldap2": "~2.2.0 required for connecting to LDAP",
        "kolab/Net_LDAP3": "dev-master required for connecting to LDAP"
    }
}	
EOF
    ${SUDO} [ ! -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/composer.json" ] && error_exit 'creating composer config...failed'
fi

if ${SUDO} [ ! -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/plugins/managesieve/config.inc.php" ]
then
    ${SUDO} tee "/var/www/src/roundcube/${ROUNDCUBEVERSION}/plugins/managesieve/config.inc.php" > /dev/null <<EOF
<?php
$config['managesieve_port'] = 4190;
$config['managesieve_host'] = 'tls://mail.kevinedwards.ca';
$config['managesieve_auth_type'] = null;
$config['managesieve_auth_cid'] = null;
$config['managesieve_auth_pw'] = null;
$config['managesieve_usetls'] = true;
$config['managesieve_conn_options'] = [
    'ssl' => [
        'verify_peer'   => false,
        'verify_peer_name' => false
    ]
];
$config['managesieve_conn_options'] = null;
$config['managesieve_default'] = '/var/vmail/sieve/global';
$config['managesieve_script_name'] = 'managesieve';
$config['managesieve_mbox_encoding'] = 'UTF-8';
$config['managesieve_replace_delimiter'] = '';
$config['managesieve_disabled_extensions'] = [];
$config['managesieve_debug'] = false;
$config['managesieve_kolab_master'] = false;
$config['managesieve_filename_extension'] = '.sieve';
$config['managesieve_filename_exceptions'] = [];
$config['managesieve_domains'] = [];
$config['managesieve_vacation'] = 0;
$config['managesieve_vacation_interval'] = 0;
$config['managesieve_vacation_addresses_init'] = false;
$config['managesieve_vacation_from_init'] = false;
$config['managesieve_notify_methods'] = ['mailto'];
$config['managesieve_raw_editor'] = true;
EOF
    [ ! -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/plugins/managesieve/config.inc.php" ] && error_exit 'creating managesieve config...failed'
fi

${SUDO} chown -R www-data:admin /var/www/src/roundcube
${SUDO} find /var/www/src/roundcube -type d -exec chmod 775 {} \;
${SUDO} find /var/www/src/roundcube -type f -exec chmod 664 {} \;

#get_composer

cd "/var/www/src/roundcube/${ROUNDCUBEVERSION}" && composer update

set_vhost "${HOSTNAME}"

if ${SUDO} [ ! -L "/var/www/${HOSTNAME}.${DOMAIN}" ]
then
	  ${SUDO} ln -s "/var/www/src/roundcube/${ROUNDCUBEVERSION}" "/var/www/${HOSTNAME}.${DOMAIN}"
	  ${SUDO} [ ! -L "/var/www/${HOSTNAME}.${DOMAIN}" ] && error_exit 'creating roundcube web dir...failed'
fi

get_ssl "${HOSTNAME}"

cd "/var/www/src/roundcube/${ROUNDCUBEVERSION}"
if ! composer -n require johndoh/contextmenu johndoh/markasjunk2 roundcube/authres_status posteo/show_pgp_mime random-cuber/contextmenu_folder melanie2/infinitescroll teon/automatic_addressbook_ng hassansin/dropbox_attachments > /dev/null 2>&1
then
    error_exit 'composer install deps...failed'
fi

if ${SUDO} [ -e "/var/www/src/roundcube/${ROUNDCUBEVERSION}/bin/install-jsdeps.sh" ]
then
    ${SUDO} chmod +x "/var/www/src/roundcube/${ROUNDCUBEVERSION}/bin/install-jsdeps.sh"
    cd "/var/www/src/roundcube/${ROUNDCUBEVERSION}/bin" && ./install-jsdeps.sh > /dev/null
fi

mysql -u kedwards -h db.kevinedwards.ca -p${DBPASSWORD}<<EOF
USE mysql;
CREATE DATABASE IF NOT EXISTS webmail CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';
CREATE USER IF NOT EXISTS '${DBUSER}'@'%' IDENTIFIED BY '${DBUSERPASSWORD}';
GRANT ALL PRIVILEGES ON webmail.* to '${DBUSER}'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
if [ $? -eq 1 ]
then
	error_exit 'configuring mariadb user...failed'
fi

cli53 rrcreate --replace ${DOMAIN} "${HOSTNAME} 300 CNAME www.kevinedwards.ca." > /dev/null
[ $? -eq 1 ] && error_exit "setting roundcube  dns...failed"

echo "Roundcube init completed...ok"
