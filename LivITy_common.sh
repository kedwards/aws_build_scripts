[ $(whoami) != 'root' ] && SUDO=sudo

DOMAIN=kevinedwards.ca

error_exit ()
{
	  echo "$1" 1>&2
	  exit 1
}

print_green ()
{
    echo -e "\e[32m${1}\e[0m"
}

init ()
{
    if ${SUDO} [ ! -e /etc/cloud/cloud.cfg.bak ]
    then
        ${SUDO} sed -i.bak 's/preserve_hostname: false/preserve_hostname: true/' /etc/cloud/cloud.cfg
        if $(grep -q 'preserve_hostname: false' /etc/cloud/cloud.cfg)
        then
            error_exit 'configuring cloud-init...failed'
        fi
    fi

    if ${SUDO} [ ! -e /etc/hosts.bak ]
    then
        ${SUDO} cp /etc/hosts /etc/hosts.bak
        ${SUDO} tee /etc/hosts > /dev/null <<EOF
127.0.1.1 ${1}.${DOMAIN} ${1}
127.0.0.1 localhost

::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF
        if $(grep -q "127.0.1.1 ${1}.${DOMAIN} ${1}" /etc/hosts)
        then
            ${SUDO} hostnamectl set-hostname --static ${1}
            echo $(hostname -f) > ${SUDO} tee /etc/mailname

            if [ $(hostname -f) != ${1}.${DOMAIN} ] || [ $(hostname) != ${1} ]
            then
                error_exit 'validating hostnames...failed'
            fi
        else
            error_exit 'writing hosts file...failed'
        fi
    fi
}

get_updates ()
{
    if ! ${SUDO} apt -q=2 update > /dev/null 2>&1
    then
        error_exit 'Updating repositories...failed'
    fi

    if ! ${SUDO} apt -q=2 upgrade -y > /dev/null 2>&1
    then
        error_exit 'Upgrading system...failed'
    fi
}

get_packages ()
{
    if ! ${SUDO} apt install -q=2 -y ${PACKAGES} > /dev/null 2>&1
    then
        error_exit 'install packages...failed'
    fi
}

set_vhost ()
{
    if ${SUDO} [ ! -e "/etc/nginx/sites-available/${1}.${DOMAIN}" ]
    then
        ${SUDO} tee "/etc/nginx/sites-available/${1}.${DOMAIN}" > /dev/null <<EOF
map \$status \$loggable {
    ~^[23]  0;
    default 1;
}

limit_req_zone \$binary_remote_addr zone=${1}.${DOMAIN}:10m rate=1r/s;

map \$scheme \$hsts_header {
    https max-age=31536000;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${1}.${DOMAIN};
    return 301 https://${1}.${DOMAIN}$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${1}.${DOMAIN};

    root /var/www/${1}.${DOMAIN};
    index index.html index.php;

    access_log /var/log/nginx/${1}.${DOMAIN}.log combined if=\$loggable;

    client_max_body_size 20M;
    charset UTF-8;

    gzip on;
    gzip_http_version 1.1;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_proxied any;
    gzip_types text/plain text/xml text/css application/x-javascript;

    ssl on;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    ssl_certificate /etc/letsencrypt/live/${1}.${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${1}.${DOMAIN}/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/${1}.${DOMAIN}/chain.pem;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_ecdh_curve secp384r1;
    ssl_session_tickets off;

    resolver 8.8.8.8 8.8.4.4 valid=86400;
    resolver_timeout 5s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;

    ssl_stapling on;
    ssl_stapling_verify on;

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
        autoindex on;
    }

    # Directives to send expires headers and turn off 404 error logging.
    location ~* ^.+\.(js|css|png|ogg|ogv|svg|svgz|eot|otf|woff|mp4|ttf|rss|atom|jpg|jpeg|gif|png|ico|zip|tgz|gz|rar|bz2|doc|xls|exe|ppt|tar|mid|midi|wav|bmp|rtf)$ {
        access_log off;
        log_not_found off;
        expires max;
    }

    location ~ \.php\$ {
        fastcgi_pass unix://var/run/php/php${2}-fpm.sock;
        fastcgi_index index.php;
        fastcgi_split_path_info ^(.+?\.php)(/.*)\$;
        fastcgi_read_timeout 150;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_script_name;
        fastcgi_param APPLICATION_ENV production;
        include fastcgi_params;
    }

    location /rspamd/ {
        proxy_pass http://localhost:11334/;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
       if $(grep -q "root /var/www/ ${1}.${DOMAIN};" "/etc/nginx/sites-available/${1}.${DOMAIN}")
       then
           error_exit 'writing vhost...failed'
        fi
    fi

    if ${SUDO} [ -L /etc/nginx/sites-enabled/default ]
    then
	    if ! ${SUDO} rm -r /etc/nginx/sites-enabled/default > /dev/null
	    then
            error_exit 'removal of default vhost...failed'
        fi
    fi

    if ${SUDO} [ ! -L "/etc/nginx/sites-enabled/${1}.${DOMAIN}" ]
    then
        ${SUDO} ln -s "/etc/nginx/sites-available/${1}.${DOMAIN}" "/etc/nginx/sites-enabled/${1}.${DOMAIN}"
        if [ $? -eq 1 ]
        then
            error_exit 'linking vhost...failed'
        fi
    fi
}

web_root ()
{
    if ${SUDO} [ ! -d "/var/www/src/${1}.${DOMAIN}" ]
    then
        ${SUDO} mkdir -p "/var/www/src/${1}.${DOMAIN}" > /dev/null
    	${SUDO} [ ! -d "/var/www/src/${1}.${DOMAIN}" ] && error_exit 'creating web src...failed'
    fi

    if ${SUDO} [ ! -e "/var/www/${1}.${DOMAIN}/index.php" ]
    then
        ${SUDO} tee "/var/www/src/${1}.${DOMAIN}/index.php" > /dev/null << EOF
<h1>${1}.${DOMAIN}</h1>
EOF
        if ! $(grep -q "<h1>${1}.${DOMAIN}</h1>" "/var/www/src/${1}.${DOMAIN}/index.php")
        then
           error_exit 'writing vhost...failed'
        fi
    fi

    if ${SUDO} [ ! -L "/var/www/${1}.${DOMAIN}" ]
    then
        ${SUDO} ln -s /var/www/src/${1}.${DOMAIN} /var/www/${1}.${DOMAIN}
        if [ $? -eq 1 ]
        then
            error_exit 'linking vhost...failed'
        fi
    fi

    ${SUDO} chown -R www-data:www-data /var/www/src
    ${SUDO} find /var/www/src -type d -exec chmod 775 {} \;
    ${SUDO} find /var/www/src -type f -exec chmod 664 {} \;
}

get_ssl ()
{
    if ${SUDO} [ ! -d "/etc/letsencrypt/live/${1}.${DOMAIN}" ]
    then
        ${SUDO} certbot certonly --standalone --rsa-key-size 4096 --agree-tos --reinstall -d ${1}.${DOMAIN} --email "kedwards@${DOMAIN}" > /dev/null 2>&1
        if [ $? -eq 1 ]; then
            error_exit "retrieving ssl...failed"
        fi
    fi
}

get_composer ()
{
    if ${SUDO} [ ! -e /usr/local/bin/composer ];
    then
        WORK_DIR=$(mktemp -dt "$(basename $0).XXXXXX")
        echo ${WORK_DIR}
        ${SUDO} [ ! -d ${WORK_DIR} ] && error_exit 'creating working dir...failed'
    fi

    ${SUDO} tee ./get_composer > /dev/null <<EOF
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
    ${SUDO} chmod +x "${WORK_DIR}/get_composer"
    ${SUDO}  "${WORK_DIR}/get_composer"
    ${SUDO} [ ! -e "/usr/local/bin/composer" ] && error_exit 'configuring composer...failed'
    echo
}
