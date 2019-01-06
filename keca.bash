#!/usr/bin/env bash

apt update

apt upgrade

sed -i.bak 's/preserve_hostname: false/preserve_hostname: true/' /etc/cloud/cloud.cfg

tee /etc/hosts > /dev/null <<EOF
${IP} ${1}.kevinedwards.ca ${1}
127.0.0.1 localhost

::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF

echo $(hostname -f) > tee /etc/mailname

wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg && |
wget -O /etc/apt/trusted.gpg.d/mariadb.gpg https://packages.sury.org/mariadb/apt.gpg && |
wget -O /etc/apt/trusted.gpg.d/nginx-mainline.gpg https://packages.sury.org/nginx-mainline/apt.gpg

echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list > /dev/null
echo "deb https://packages.sury.org/mariadb/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/mariadb.list > /dev/null
echo "deb https://packages.sury.org/nginx-mainline/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/nginx-mainline.list > /dev/null

apt update

#nginx certbot mariadb-client unzip git php${PHPVERSION}-imagick php${PHPVERSION}-fpm php${PHPVERSION}-cli php${PHPVERSION}-mbstring php${PHPVERSION}-mysql php${PHPVERSION}-imap php${PHPVERSION}-opcache php${PHPVERSION}-curl php${PHPVERSION}-xml php${PHPVERSION}-gd php${PHPVERSION}-zip php${PHPVERSION}-intl"

apt-get install nginx certbot mariadb-client unzip git php7.3-fpm php7.3-cli php7.3-mbstring \
  php7.3-mysql php7.3-imap php7.3-opcache php7.3-curl php7.3-xml php7.3-gd php7.3-zip php7.3-intl \
  mariadb-server

sed -i.bak 's|;date.timezone =|date.timezone = America/Edmonton|' /etc/php/7.3/fpm/php.ini

openssl dhparam -dsaparam -out /etc/ssl/certs/dhparam.pem 2048 > /dev/null 2>&1

printf "kedwards:openssl passwd -apr1\n" | ${SUDO} tee /etc/nginx/passwd > /dev/null

chown www-data:www-data /etc/nginx/passwd

chmod 600 /etc/nginx/passwd

tee "/etc/nginx/sites-available/keca" > /dev/null <<EOF
server {
	listen 80;
	listen [::]:80;

	root /var/www/keca;

	index index.html index.htm index.nginx-debian.html;

	server_name www.kevinedwards.ca;

	location / {
		try_files $uri $uri/ =404;
    autoindex on;
	}
}
EOF

ln -s /etc/nginx/sites-avilable/keca /etc/nginx/sites-enabled/keca

rm -r /etc/nginx/sites-avilable/default

mkdir -p /var/www/src/keca

tee "/var/www/src/keca/index.php" > /dev/null << EOF
<h1>www.kevinedwards.ca</h1>
<?php phpinfo(); ?>
EOF

ln -s /var/www/src/keca /var/www/keca

chown -R www-data:www-data /var/www/src

find /var/www/src -type d -exec chmod 775 {} \;

find /var/www/src -type f -exec chmod 664 {} \;

tee ./get_composer > /dev/null <<EOF
#!/bin/sh

EXPECTED_SIGNATURE=\$(wget -q -O - https://composer.github.io/installer.sig)
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
ACTUAL_SIGNATURE=\$(php -r "echo hash_file('SHA384', 'composer-setup.php');")

if [ "\$EXPECTED_SIGNATURE" != "\$ACTUAL_SIGNATURE" ]
then
>&2 echo 'ERROR: Invalid installer signature'
${SUDO} rm composer-setup.php
return 1
fi

${SUDO} php composer-setup.php --quiet
RESULT=\$?
${SUDO} rm composer-setup.php
${SUDO} mv composer.phar /usr/local/bin/composer
${SUDO} chmod +x /usr/local/bin/composer
return \$RESULT
EOF

chmod +x get_composer

./get_composer

./mysql_secure_installation

mysql -u root -p <<EOF
CREATE USER IF NOT EXISTS '${DBUSER}'@'%' IDENTIFIED BY '${DBUSERPASSWORD}';
GRANT ALL PRIVILEGES ON *.* to '${DBUSER}'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

mkdir -p /var/www/src/keca/adminer/4.6.3

wget -q -O "/var/www/src/keca/adminer/4.6.3/index.php" https://www.adminer.org/latest-mysql-en.php > /dev/null

chown -R www-data:www-data /var/www/src

find /var/www/src -type d -exec chmod 775 {} \;

find /var/www/src -type f -exec chmod 664 {} \;


mkdir -p /var/www/src/keca/postfixadmin

cd /var/www/src/keca/postfixadmin && get -q wget https://github.com/postfixadmin/postfixadmin/archive/postfixadmin-3.2.tar.gz

tar xf postfixadmin-3.2.tar.gz -C /var/www/src/postfixadmin/3.2 --strip-components=1

mkdir -p /var/www/src/keca/postfixadmin/3.2/templates_c

tee /var/www/src/keca/postfixadmin/3.2/config.local.php" > /dev/null<<EOF
<?php
    \$CONF['configured'] = true;
    \$CONF['setup_password'] = '';
    \$CONF['default_language'] = 'en';
    \$CONF['database_type'] = 'mysqli';
    \$CONF['database_host'] = 'db.kevinedwards.ca';
    \$CONF['database_user'] = 'mailadm';
	  \$CONF['database_password'] = '${DB_PASSWORD}';
    \$CONF['database_name'] = 'mail';
    \$CONF['admin_email'] = 'postmaster@kevinewards.ca';
    \$CONF['smtp_server'] = 'mail.kevinedwards.ca';
    \$CONF['smtp_port'] = '25';
    \$CONF['encrypt'] = 'md5crypt';
    \$CONF['authlib_default_flavor'] = 'md5raw';
    \$CONF['dovecotpw'] = "/usr/sbin/doveadm pw";
    \$CONF['default_aliases'] = array (
        'abuse' => 'abuse@kevinedwards.ca',
        'hostmaster' => 'hostmaster@kevinedwards.ca',
        'postmaster' => 'postmaster@kevinedwards.ca',
        'webmaster' => 'webmaster@kevinedwards.ca'
    );
    \$CONF['domain_path'] = 'YES';
    \$CONF['domain_in_mailbox'] = 'NO';
    \$CONF['show_footer_text'] = 'YES';
    \$CONF['footer_text'] = 'Return to kevinedwards.ca';
    \$CONF['footer_link'] = 'https://www.kevinedwards.ca';
EOF


mysql -u root -p <<EOF
USE mysql;
CREATE DATABASE IF NOT EXISTS mail CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';
CREATE USER IF NOT EXISTS 'mailadm'@'%' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON mail.* to 'mailadm'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

mysql -u root -p <<EOF
USE mail;
CREATE TABLE IF NOT EXISTS tlspolicies (
    id int unsigned NOT NULL AUTO_INCREMENT,
    domain varchar(255) NOT NULL,
    policy enum('none', 'may', 'encrypt', 'dane', 'dane-only', 'fingerprint', 'verify', 'secure') NOT NULL,
    params varchar(255),
    PRIMARY KEY (id),
    UNIQUE KEY (domain)
);
EOF

mkdir -p /var/www/src/keca/roundcube

cd /var/www/src/keca && wget https://github.com/roundcube/roundcubemail/releases/download/1.3.7/roundcubemail-1.3.7-complete.tar.gz

tar zxf roundcubemail-1.3.7-complete.tar.gz

mv roundcubemail-1.3.7 roundcube/1.3.7

rm -r roundcubemail-1.3.7-complete.tar.gz

tee /var/www/src/keca/roundcube/1.3.7/config/config.inc.php > /dev/null <<EOF
<?php
\$config = []
\$config['enable_installer'] = false;
\$config['db_dsnw'] = 'mysql://mailadm:${DB_PASSWORD}@localhost/webmail';
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

tee /var/www/src/keca/roundcube/1.3.7/composer.json > /dev/null <<EOF
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

tee /var/www/src/keca/roundcube/1.3.7/plugins/managesieve/config.inc.php > /dev/null <<EOF
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

chown -R www-data:www-data /var/www/src

find /var/www/src -type d -exec chmod 775 {} \;

find /var/www/src -type f -exec chmod 664 {} \;

cd /var/www/src/keca/roundcube/1.3.7/ && composer update

#chmod +x /var/www/src/keca/roundcube/1.3.7/bin/install-jsdeps.sh
cd /var/www/src/roundcube/1.7.3/bin && ./install-jsdeps.sh > /dev/null

mysql -u root -p <<EOF
USE mysql;
CREATE DATABASE IF NOT EXISTS webmail CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';
CREATE USER IF NOT EXISTS 'mailadm'@'%' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON webmail.* to 'mailadm'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

---

curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -

echo "deb [arch=amd64] https://download.docker.com/linux/debian stretch stable" > /etc/apt/sources.d/docker.list
