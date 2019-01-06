#!/bin/sh -e
HOSTNAME=mail
DOMAIN=kevinedwards.ca
CODENAME=$(lsb_release -c -s)
PUBLIC_IPV4=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PACKAGES="swaks redis-server certbot rspamd postfix unbound dnsutils resolvconf postfix-mysql dovecot-core dovecot-mysql dovecot-imapd dovecot-lmtpd dovecot-managesieved" #nginx
MAILADMINPASSWORD=
MAILSECURITYGROUPID=
HOSTEDZONE=
CRONCOMMAND='${SUDO} certbot renew --pre-hook "$(aws ec2 authorize-security-group-ingress --group-id ${MAILSECURITYGROUPID} --protocol tcp --port 443 --cidr 0.0.0.0/0)" --post-hook "$(aws ec2 revoke-security-group-ingress --group-id ${MAILSECURITYGROUPID} --protocol tcp --port 443 --cidr 0.0.0.0/0)" --renew-hook "${SUDO} systemctl reload dovecot postfix" --quiet'
CRONJOB="@weekly ${CRONCOMMAND}"

trap_finish ()
{
    if [ $HTTPSOPEN ]
    then
        if ! $(aws ec2 revoke-security-group-ingress --group-id ${MAILSECURITYGROUPID} --protocol tcp --port 443 --cidr 0.0.0.0/0) > /dev/null 2>&1
        then
            echo 'closing https port...failed'
        fi
    fi
}
trap trap_finish EXIT

reverse_dns ()
{
    IP=$1
	oct1=$(echo ${IP} | tr "." " " | awk '{ print $1 }')
    oct2=$(echo ${IP} | tr "." " " | awk '{ print $2 }')
    oct3=$(echo ${IP} | tr "." " " | awk '{ print $3 }')
    oct4=$(echo ${IP} | tr "." " " | awk '{ print $4 }')
    RDNS="${oct4}.${oct3}.${oct2}.${oct1}-in-addr-arpa"
}

. ~/.aws/build/LivITy_common.sh

init ${HOSTNAME}

if ${SUDO} [ ! -e /etc/apt/sources.list.d/rspamd.list ]
then
    wget -q -O- https://rspamd.com/apt-stable/gpg.key | ${SUDO} apt-key add -
    ${SUDO} tee /etc/apt/sources.list.d/rspamd.list > /dev/null <<EOF
# Rspamd
deb http://rspamd.com/apt-stable/ ${CODENAME} main
deb-src http://rspamd.com/apt-stable/ ${CODENAME} main
EOF
    if ! $(grep -q "deb http://rspamd.com/apt-stable/ ${CODENAME} main" /etc/apt/sources.list.d/rspamd.list)
    then
        error_exit "rspamd repository setup...failed"
    fi
fi

echo "postfix postfix/mailname string ${HOSTNAME}.${DOMAIN}" | ${SUDO} debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | ${SUDO} debconf-set-selections

get_updates
get_packages ${PACKAGES}

${SUDO} systemctl stop postfix dovecot rspamd > /dev/null
if [ $? -eq 1 ]
then 
    error_exit "stopping services...failed"
fi

if ! $(aws ec2 authorize-security-group-ingress --group-id ${MAILSECURITYGROUPID} --protocol tcp --port 443 --cidr 0.0.0.0/0) > /dev/null 2>&1
then
    error_exit 'opening https port...failed'
else
    HTTPSOPEN=true
    get_ssl ${HOSTNAME}
fi

if ${SUDO} [ ! -e /etc/postfix/dh_512.pem ]
then
    ${SUDO} openssl dhparam -dsaparam -out /etc/postfix/dh_512.pem 512 > /dev/null 2>&1
    ${SUDO} openssl dhparam -dsaparam -out /etc/postfix/dh_1024.pem 1024 > /dev/null 2>&1
    ${SUDO} openssl dhparam -dsaparam -out /etc/postfix/dh_2048.pem 2048 > /dev/null 2>&1
    ${SUDO} [ ! -e /etc/postfix/dh_512.pem ] && error_exit 'configuring EDH...failed'
fi

id -u vmail > /dev/null 2>&1 || ${SUDO} useradd -mUd /var/vmail -s /bin/bash vmail &> /dev/null
${SUDO} mkdir -p /var/vmail/mailboxes
${SUDO} mkdir -p /var/vmail/sieve/global
${SUDO} chown -R vmail:vmail /var/vmail
${SUDO} chmod 770 /var/vmail
${SUDO} mkdir -p /etc/postfix/sql

# virtual_mailbox_domains
if ${SUDO} [ ! -e /etc/postfix/sql/virtual_mailbox_domains.cf ]
then
      ${SUDO} tee /etc/postfix/sql/virtual_mailbox_domains.cf > /dev/null <<EOF
hosts = db.${DOMAIN}
user = mailadmin
password = ${MAILADMINPASSWORD}
dbname = mail
query = SELECT domain FROM domain WHERE domain='%s' and backupmx = 0 and active = 1
EOF
    ${SUDO} [ ! -e /etc/postfix/sql/virtual_mailbox_domains.cf ] && error_exit 'creating virtual_mailbox_domains...failed'
fi

# virtual_mailbox_maps, virtual_mailbox_alias_maps
if ${SUDO} [ ! -e /etc/postfix/sql/virtual_mailbox_maps.cf ]
then
      ${SUDO} tee /etc/postfix/sql/virtual_mailbox_maps.cf > /dev/null <<EOF
hosts = db.${DOMAIN}
user = mailadmin
password = ${MAILADMINPASSWORD}
dbname = mail
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = 1 UNION SELECT maildir FROM mailbox, alias_domain WHERE alias_domain.alias_domain = '%d' AND mailbox.username=concat('%u', '@', alias_domain.target_domain) AND mailbox.active = 1
EOF
    ${SUDO} [ ! -e /etc/postfix/sql/virtual_mailbox_maps.cf ] && error_exit 'creating virtual_mailbox_maps...failed'
fi

# virtual_alias_maps,virtual_alias_alias_maps
if ${SUDO} [ ! -e /etc/postfix/sql/virtual_alias_maps.cf ]
then
    ${SUDO} tee /etc/postfix/sql/virtual_alias_maps.cf > /dev/null <<EOF
hosts = db.${DOMAIN}
user = mailadmin
password = ${MAILADMINPASSWORD}
dbname = mail
query = SELECT goto FROM alias WHERE address='%s' AND active = 1 UNION SELECT goto FROM alias, alias_domain WHERE alias_domain.alias_domain = '%d' AND alias.address=concat('%u', '@', alias_domain.target_domain) AND alias.active = 1
EOF
    ${SUDO} [ ! -e /etc/postfix/sql/virtual_alias_maps.cf ] && error_exit 'creating virtual_alias_maps...failed'
fi

# virtual_relay_domains
if ${SUDO} [ ! -e /etc/postfix/sql/virtual_relay_domains.cf ]
then
      ${SUDO} tee /etc/postfix/sql/virtual_relay_domains.cf > /dev/null <<EOF
hosts = db.${DOMAIN}
user = mailadmin
password = ${MAILADMINPASSWORD}
dbname = mail
query = SELECT domain FROM domain WHERE domain='%s' AND backupmx = 1 AND active = 1
EOF
    ${SUDO} [ ! -e /etc/postfix/sql/virtual_relay_domains.cf ] && error_exit 'creating virtual_relay_domains...failed'
fi

# sender_login_maps
if ${SUDO} [ ! -e /etc/postfix/sql/sender_login_maps.cf ]
then
    ${SUDO} tee /etc/postfix/sql/sender_login_maps.cf > /dev/null <<EOF
hosts = db.${DOMAIN}
user = mailadmin
password = ${MAILADMINPASSWORD}
dbname = mail
query = select username as 'owns' FROM mailbox WHERE local_part = '%u' AND domain = '%d' and active = 1 union select goto as 'owns' FROM alias, alias_domain WHERE alias_domain.alias_domain ='%d' AND alias.address = concat('%u', '@', alias_domain.target_domain) AND alias_domain.active = alias.active AND alias.active = true
EOF
    ${SUDO} [ ! -e /etc/postfix/sql/sender_login_maps.cf ] && error_exit 'creating sender_login_maps...failed'
fi

# tls_policy
# Define a new TLS policy (optional)

# TLS policies let you specify how strong a connection to another mailserver must be secured.
# There are different levels of security and verification:
#
# none: Don’t use encryption
#
# may: Encrypt, if supported by other server. Self-signed certificates are accepted, because there is no certificate verification.
#
# encrypt: Always encrypt. Self-signed certificates are accepted, because there is no certificate verification.
# 
# dane: If there are valid TLSA-records in the DNS, encryption is mandatory. The certificate is then verified via DANE.
#       If invalid TLSA records are found, fallback is “encrypt”. If no TLSA-records are found, fallback is “may”.
#
# dane-only: Encrypted connections only. Certificate verification via DANE. No fallback to weaker methods.
#
# verify: Encrypted connections only. Certificate must be issued by an accepted CA.
#         Hostname given in MX record must match hostname in certificate.
#
# secure: Encrypted connections only. Certificate must be issued by an accepted CA.
#         Hostname in certificate must by domain or subdomain of e-mail domain. No DNS used.
#
# Example:
# insert into tlspolicies (domain, policy) values ('mailbox.org', 'dane-only');
#
# The “params” field is used for additional verification details, such as “match” parameters.
# E.g. for GMX Mail you would define:
#
# insert into tlspolicies (domain, policy, params) values ('gmx.de', 'secure', 'match=.gmx.net');
#
# But why? Well, if “secure” as a mechanism is chosen, Postfix will find out the domain part of the recipient’s mail address.
# For GMX that could be thomas@gmx.de for example. Now Postfix would only allow connections to mail hosts, which have “gmx.de” 
# in their hostname, such as host1.gmx.de, host2.gmx.de and so on. The problem here is, that GMX has no hosts running at “*gmx.de”.
# They are running at gmx.NET instead. So the “secure” policy must be extended with match=.gmx.net - otherwise connections to GMX mail servers would fail.
if ${SUDO} [ ! -e /etc/postfix/sql/tls_policy.cf ]
then
    ${SUDO} tee /etc/postfix/sql/tls_policy.cf > /dev/null <<EOF
hosts = db.${DOMAIN}
user = mailadmin
password = ${MAILADMINPASSWORD}
dbname = mail
query = SELECT policy, params FROM tlspolicies WHERE domain = '%s'
EOF
     ${SUDO} [ ! -e /etc/postfix/sql/tls_policy.cf ] && error_exit 'creating tls_policy...failed'
fi

if ${SUDO} [ ! -e /etc/postfix/main.cf.bak ]
then
    ${SUDO} cp /etc/postfix/main.cf /etc/postfix/main.cf.bak
    
    # virtual
    ${SUDO} postconf -e 'mydestination = localhost ${myhostname}'
    ${SUDO} postconf -e "virtual_uid_maps = static:`awk -F':' '/vmail/{print $3}' /etc/group`"
    ${SUDO} postconf -e "virtual_gid_maps = static:`awk -F':' '/vmail/{print $3}' /etc/group`"
    ${SUDO} postconf -e 'virtual_mailbox_base = /var/vmail'
    ${SUDO} postconf -e 'virtual_transport=lmtp:unix:private/dovecot-lmtp'
    ${SUDO} postconf -e 'lmtp_host_lookup = native'
    # db queries
    ${SUDO} postconf -e 'virtual_mailbox_domains = mysql:/etc/postfix/sql/virtual_mailbox_domains.cf'
    ${SUDO} postconf -e 'virtual_mailbox_maps = mysql:/etc/postfix/sql/virtual_mailbox_maps.cf'
    ${SUDO} postconf -e 'virtual_alias_maps = mysql:/etc/postfix/sql/virtual_alias_maps.cf'
    ${SUDO} postconf -e 'relay_domains = mysql:/etc/postfix/sql/virtual_relay_domains.cf'
    ${SUDO} postconf -e 'local_recipient_maps = $virtual_mailbox_maps'
    # queue 
    ${SUDO} postconf -e 'maximal_queue_lifetime = 1h'
    ${SUDO} postconf -e 'bounce_queue_lifetime = 1h'
    ${SUDO} postconf -e 'maximal_backoff_time = 15m'
    ${SUDO} postconf -e 'minimal_backoff_time = 5m'
    ${SUDO} postconf -e 'queue_run_delay = 5m'
    # tls
    ${SUDO} postconf -e 'tls_ssl_options = NO_COMPRESSION'
    ${SUDO} postconf -e 'tls_high_cipherlist = EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA256:EECDH:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!IDEA:!ECDSA:kEDH:CAMELLIA128-SHA:AES128-SHA'
    # outbound
    ${SUDO} postconf -e 'smtp_tls_security_level = dane'
    ${SUDO} postconf -e 'smtp_dns_support_level = dnssec'
    ${SUDO} postconf -e 'smtp_tls_policy_maps = mysql:/etc/postfix/sql/tls_policy.cf'
    ${SUDO} postconf -e 'smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache'
    ${SUDO} postconf -e 'smtp_tls_protocols = !SSLv3'
    ${SUDO} postconf -e 'smtp_tls_ciphers = high'
    ${SUDO} postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'
    ${SUDO} postconf -e 'smtp_tls_mandatory_protocols = !SSLv3'
    # inbound
    ${SUDO} postconf -e 'smtpd_helo_required = yes'
    ${SUDO} postconf -e 'smtpd_tls_security_level = may'
    ${SUDO} postconf -e 'smtpd_tls_protocols = !SSLv3'
    ${SUDO} postconf -e 'smtpd_tls_mandatory_protocols = !SSLv3'
    ${SUDO} postconf -e 'smtpd_tls_ciphers = high'
    ${SUDO} postconf -e 'smtpd_tls_mandatory_ciphers=high'
    ${SUDO} postconf -e 'smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache'
    ${SUDO} postconf -e "smtpd_tls_cert_file=/etc/letsencrypt/live/${HOSTNAME}.${DOMAIN}/cert.pem"
    ${SUDO} postconf -e "smtpd_tls_key_file=/etc/letsencrypt/live/${HOSTNAME}.${DOMAIN}/privkey.pem"
    ${SUDO} postconf -e 'smtpd_tls_dh1024_param_file = /etc/postfix/dh_2048.pem'
    ${SUDO} postconf -e 'smtpd_tls_dh512_param_file = /etc/postfix/dh_512.pem'
    # Spam filter and DKIM signatures via Rspamd
    ${SUDO} postconf -e 'smtpd_milters = inet:localhost:11332'
    ${SUDO} postconf -e 'non_smtpd_milters = inet:localhost:11332'
    ${SUDO} postconf -e 'milter_protocol = 6'
    ${SUDO} postconf -e 'milter_mail_macros =  i {mail_addr} {client_addr} {client_name} {auth_authen}'
    ${SUDO} postconf -e 'milter_default_action = accept'
    ${SUDO} postconf -e 'milter_rcpt_macros = i {rcpt_addr}'
    # postscreen: # drop connections if other server is blacklisted or sending too quickly
    ${SUDO} postconf -e 'postscreen_blacklist_action = drop'
    ${SUDO} postconf -e 'postscreen_greet_action = drop'
    ${SUDO} postconf -e 'postscreen_dnsbl_action = drop'
    # Maximum mailbox size (0=unlimited - is already limited by Dovecot quota)
    ${SUDO} postconf -e 'mailbox_size_limit = 0'
    # Maximum size of inbound e-mails (50 MB, default is 10M)
    ${SUDO} postconf -e 'message_size_limit = 52428800'
    # Do not notify system users on new e-mail
    ${SUDO} postconf -e 'biff = no'
    # address extension delimiter that was found in the recipient address
    ${SUDO} postconf -e 'recipient_delimiter = +'
    # Restrictions for MUAs (Mail user agents)
    ${SUDO} postconf -e 'mua_relay_restrictions = reject_non_fqdn_recipient,reject_unknown_recipient_domain,permit_mynetworks,permit_sasl_authenticated,reject'
    ${SUDO} postconf -e 'mua_sender_restrictions = permit_mynetworks,reject_non_fqdn_sender,reject_sender_login_mismatch,permit_sasl_authenticated,reject'
    ${SUDO} postconf -e 'mua_client_restrictions = permit_mynetworks,permit_sasl_authenticated,reject'

    ${SUDO} chgrp postfix /etc/postfix/sql/*.cf
    ${SUDO} chmod 640 /etc/postfix/sql/*.cf

   
    ${SUDO} tee -a /etc/postfix/main.cf > /dev/null <<EOF
######## Phase connect
# all sending foreign servers ("SMTP clients")
# 1. always allow hosts listed in mynetworks
# 2. check ptr whitelist
# 3. reject all mail servers that does not know h
smtpd_client_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    check_client_access hash:/etc/postfix/without_ptr,
    reject_unknown_client_hostname

######## Phase HELO/EHLO
# 1. always allow hosts listed in mynetworks
# 2. reject all mail servers that does not know how to specify a correct HELO/EHLO
# 3. reject all mail servers that does not use FQDN in HELO
# 4. reject all mail servers that does not list at least a DNS A or MX record
# 5. allow the rest (behaving servers)
smtpd_helo_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    reject_unknown_helo_hostname

######## Phase MAIL FROM:
# 1. always allow hosts listed in mynetworks
# 2. reject sender email which has no DNS A or MX record
# 3. reject sender email which is not complete
# 4. allow any other from address
smtpd_sender_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    permit

######## Phase RCPT TO:
# 1. allow hosts listed in mynetworks to use non-conforming (fake/local) recipient address
# 2. reject recipient email which is not complete
# 3. reject recipient email which has no DNS A or MX record
# 4. allow AUTH clients to relay mail
# 5. rejects everything we are not final destination for
# accepts e-mails as recipient (additional to relay conditions)
# check_recipient_access checks if an account is "sendonly" 
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_hostname,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
	check_policy_service unix:private/policy-spf,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    reject_rbl_client dnsbl.sorbs.net
    reject_rbl_client dnsbl-1.uceprotect.net

######## Relaying
# 1. always allow hosts listed in mynetworks
smtpd_relay_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination

######## Data restrictions : Block clients, which start sending too early
smtpd_data_restrictions =
    reject_unauth_pipelining,
    reject_multi_recipient_bounce

######## MUA Relaying
# 1. always allow hosts listed in mynetworks
mua_relay_restrictions =
    permit_mynetworks,
	permit_sasl_authenticated,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
	reject

######## MUA Relaying
# 1. always allow hosts listed in mynetworks
mua_sender_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
	reject_sender_login_mismatch,
	reject

######## MUA Relaying
# 1. always allow hosts listed in mynetworks
mua_client_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
	reject

# postscreen filter : Whitelist / Blocklist
postscreen_access_list = 
    permit_mynetworks,
    cidr:/etc/postfix/postscreen_access,

# DNS blocklists
postscreen_dnsbl_threshold = 2
postscreen_dnsbl_sites = 
    ix.dnsbl.manitu.net*2,
    zen.spamhaus.org*2
EOF
fi

if ${SUDO} [ ! -e /etc/postfix/master.cf.bak ]
then
	${SUDO} cp /etc/postfix/master.cf /etc/postfix/master.cf.bak
    ${SUDO} tee /etc/postfix/master.cf > /dev/null <<EOF
smtp      inet  n       -       y       -       1       postscreen
    -o smtpd_sasl_auth_enable=no
smtpd     pass  -       -       y       -       -       smtpd
dnsblog   unix  -       -       y       -       0       dnsblog
tlsproxy  unix  -       -       y       -       0       tlsproxy
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_sasl_security_options=noanonymous
  -o smtpd_client_restrictions=\$mua_client_restrictions
  -o smtpd_sender_restrictions=\$mua_sender_restrictions
  -o smtpd_relay_restrictions=\$mua_relay_restrictions
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sender_login_maps=mysql:/etc/postfix/sql/sender-login-maps.cf
  -o smtpd_helo_required=no
  -o smtpd_helo_restrictions=
  -o cleanup_service_name=submission-header-cleanup
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
submission-header-cleanup unix n - n    -       0       cleanup
    -o header_checks=regexp:/etc/postfix/submission_header_cleanup
policy-spf  unix  -       n       n       -       -       spawn
    user=nobody argv=/usr/bin/policyd-spf
EOF
    ${SUDO} [ ! -e /etc/postfix/master.cf ] && error_exit 'creating master.cf...failed'
fi

# changes require 'postmap /etc/postfix/<file> && systemctl reload postfix'
if ${SUDO} [ ! -e /etc/postfix/submission_header_cleanup ]
then
    ${SUDO} tee /etc/postfix/submission_header_cleanup > /dev/null <<EOF
# Removes headers of MUAs for privacy reasons
/^Received:/            IGNORE
/^X-Originating-IP:/    IGNORE
/^X-Mailer:/            IGNORE
/^User-Agent:/          IGNORE
EOF
    ${SUDO} chmod 640 /etc/postfix/submission_header_cleanup
    ${SUDO} [ ! -e /etc/postfix/submission_header_cleanup ] && error_exit 'creating submission_header_cleanup...failed'
    ${SUDO} postmap /etc/postfix/submission_header_cleanup > /dev/null
    if [ $? -eq 1 ]
    then
        error_exit 'postmap of submission_header_cleanup...failed'
    fi
fi

if ${SUDO} [ ! -e /etc/postfix/without_ptr ]
then
    ${SUDO} tee /etc/postfix/without_ptr > /dev/null <<EOF
# allows server to send e-mails to this host even if it does not have a valid PTR-record.
#  1.2.3.3    OK
EOF
    ${SUDO} chmod 640 /etc/postfix/without_ptr
    ${SUDO} [ ! -e /etc/postfix/without_ptr ] && error_exit 'creating without_ptr...failed'
    ${SUDO} postmap /etc/postfix/without_ptr > /dev/null 2>&1
    if [ $? -eq 1 ]
    then
        error_exit 'postmap of without_ptr...failed'
    fi
fi

if ${SUDO} [ ! -e /etc/postfix/postscreen_access ]
then
    ${SUDO} tee /etc/postfix/postscreen_access > /dev/null <<EOF
# define exceptions for the postscreen filter.
#  1.2.3.3    permit
EOF
    ${SUDO} chmod 640 /etc/postfix/postscreen_access
    ${SUDO} [ ! -e /etc/postfix/postscreen_access ]  && error_exit 'creating postscreen_access...failed'
    ${SUDO} postmap /etc/postfix/postscreen_access > /dev/null
    if [ $? -eq 1 ]
    then
        error_exit 'postmap of postscreen_access...failed'
    fi
fi

if ${SUDO} [ ! -e "/etc/aliases.db" ]
then
    ${SUDO} newaliases
fi

if ${SUDO} [ ! -e /etc/dovecot/dovecot-sql.conf.ext.bak ]
then
	  ${SUDO} cp /etc/dovecot/dovecot-sql.conf.ext /etc/dovecot/dovecot-sql.conf.ext.bak
	  ${SUDO} tee /etc/dovecot/dovecot-sql.conf.ext > /dev/null <<EOF
driver = mysql
connect = host=db.${DOMAIN} dbname=mail user=mailadmin password=${MAILADMINPASSWORD}
default_pass_scheme = SHA512-CRYPT
password_query = SELECT username as user, password FROM mailbox WHERE username = '%u'
#user_query = SELECT concat('*:storage=', quota, 'M') AS quota_rule FROM mailbox WHERE username = '%u' AND quota != 0 AND active = 1;
iterate_query = SELECT username FROM mailbox where active = 1;
EOF
    ${SUDO} chmod 440 /etc/dovecot/dovecot-sql.conf.ext
    ${SUDO} [ ! -e /etc/dovecot/dovecot-sql.conf.ext.bak ] && error_exit 'creating dovecot-sql.conf.ext...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/10-auth.conf.bak ]
then
    ${SUDO} cp /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.bak
    ${SUDO} tee /etc/dovecot/conf.d/10-auth.conf > /dev/null <<EOF
disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-sql.conf.ext
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/10-auth.conf.bak ] && error_exit 'creating 10-auth.conF...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/10-mail.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/conf.d/10-mail.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/10-mail.conf > /dev/null <<EOF
mail_uid = vmail
mail_gid = vmail
mail_privileged_group = vmail

mail_home = /var/vmail/mailboxes/%n
mail_location = maildir:~/Maildir:LAYOUT=fs

namespace inbox {
	  inbox = yes
    separator = /	
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/10-mail.conf.bak ] && error_exit 'creating 10-mail.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/10-master.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/10-master.conf /etc/dovecot/conf.d/10-master.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/10-master.conf > /dev/null <<EOF
service imap-login {
    inet_listener imaps {
        port = 993
	      ssl = yes
    }                                                                                                                                                        
}

service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
        mode = 0660
        user = postfix
        group = postfix
    }
	  user = vmail
}

service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0660
	      user = postfix
	      group = postfix
    }
	
	  unix_listener auth-userdb {
        mode = 0660
        user = vmail
        group = vmail
    }
}   
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/10-master.conf.bak ] && error_exit 'creating 10-master.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/10-ssl.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/10-ssl.conf  /etc/dovecot/conf.d/10-ssl.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/10-ssl.conf > /dev/null <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/mail.kevinedwards.ca/fullchain.pem
ssl_key = </etc/letsencrypt/live/mail.kevinedwards.ca/privkey.pem
ssl_dh_parameters_length = 2048
ssl_protocols = !SSLv3
#ssl_cipher_list = AES128+EECDH:AES128+EDH:!aNULL
ssl_cipher_list = EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA256:EECDH:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!IDEA:!ECDSA:kEDH:CAMELLIA128-SHA:AES128-SHA
ssl_prefer_server_ciphers = yes
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/10-ssl.conf.bak ] && error_exit 'creating 10-ssl.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/15-mailboxes.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/15-mailboxes.conf  /etc/dovecot/conf.d/15-mailboxes.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/15-mailboxes.conf > /dev/null <<EOF
namespace inbox {
    mailbox Spam {
        auto = subscribe
        special_use = \Junk
    }

    mailbox Trash {
        auto = subscribe
        special_use = \Trash
    }

    mailbox Drafts {
        auto = subscribe
        special_use = \Drafts
    }

    mailbox Sent {
        auto = subscribe
        special_use = \Sent
    }
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/15-mailboxes.conf.bak ] && error_exit 'creating 15-mailboxes.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/20-imap.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/20-imap.conf /etc/dovecot/conf.d/20-imap.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/20-imap.conf > /dev/null <<EOF
protocol imap {
    mail_plugins = $mail_plugins quota imap_quota imap_sieve
    mail_max_userip_connections = 20
    imap_idle_notify_interval = 29 mins
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/20-imap.conf.bak ] && error_exit 'creating 20-imap.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/20-lmtp.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/20-lmtp.conf /etc/dovecot/conf.d/20-lmtp.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/20-lmtp.conf > /dev/null <<EOF
protocol lmtp {
    postmaster_address = postmaster@${DOMAIN}
    mail_plugins = $mail_plugins sieve
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/20-lmtp.conf.bak ] && error_exit 'creating 20-lmtp.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/20-managesieve.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/20-managesieve.conf  /etc/dovecot/conf.d/20-managesieve.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/20-managesieve.conf > /dev/null <<EOF
protocols = \$protocols sieve

service managesieve-login {
    inet_listener sieve {
        port = 4190
    }
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/20-managesieve.conf.bak ] && error_exit 'creating 20-managesieve.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/90-sieve.conf.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/90-sieve.conf /etc/dovecot/conf.d/90-sieve.conf.bak
	  ${SUDO} tee /etc/dovecot/conf.d/90-sieve.conf > /dev/null <<EOF
plugin {                                                                                                                                                                                                
    sieve_plugins = sieve_imapsieve sieve_extprograms
    sieve_before = /var/vmail/sieve/global/spam-global.sieve
    sieve = file:/var/vmail/sieve/%n/scripts;active=/var/vmail/sieve/%n/active-script.sieve

    # From elsewhere to Spam folder
    imapsieve_mailbox1_name = Spam
    imapsieve_mailbox1_causes = COPY
    imapsieve_mailbox1_before = file:/var/vmail/sieve/global/learn-spam.sieve

    # From Spam folder to elsewhere
    imapsieve_mailbox2_name = *
    imapsieve_mailbox2_from = Spam
    imapsieve_mailbox2_causes = COPY
    imapsieve_mailbox2_before = file:/var/vmail/sieve/global/learn-ham.sieve

    sieve_pipe_bin_dir = /usr/bin
    sieve_global_extensions = +vnd.dovecot.pipe

    quota = maildir:User quota
    quota_exceeded_message = User %u has exhausted allowed storage space.
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/90-sieve.conf.bak ] && error_exit 'creating 90-sieve.conf...failed'
fi

if ${SUDO} [ ! -e /etc/dovecot/conf.d/auth-sql.conf.ext.bak ]
then
	  ${SUDO} cp /etc/dovecot/conf.d/auth-sql.conf.ext /etc/dovecot/conf.d/auth-sql.conf.ext.bak
	  ${SUDO} tee /etc/dovecot/conf.d/auth-sql.conf.ext > /dev/null <<EOF
passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
    driver = static
    args = uid=vmail gid=vmail home=/var/vmail/mailboxes/%n
}
EOF
    ${SUDO} [ ! -e /etc/dovecot/conf.d/auth-sql.conf.ext.bak ] && error_exit 'creating auth-sql.conf...failed'
fi

if ${SUDO} [ ! -e /var/vmail/sieve/global/spam-global.sieve ]
then
	  ${SUDO} tee /var/vmail/sieve/global/spam-global.sieve > /dev/null <<EOF
require ["envelope", "fileinto", "imap4flags", "regex"];

if header :contains "X-Spam-Flag" "YES" {
    fileinto "Spam";
}

if header :is "X-Spam" "Yes" {
    fileinto "Spam";
}

if header :contains "X-Spam-Level" "*****" {
	fileinto "Spam";
}

if not header :regex "message-id" ".*@.*\." {
	  fileinto "Spam";
}
EOF
    ${SUDO} [ ! -e /var/vmail/sieve/global/spam-global.sieve ] && error_exit 'creating spam-global.sieve...failed'
    ${SUDO} sievec /var/vmail/sieve/global/spam-global.sieve
fi

if ${SUDO} [ ! -e /var/vmail/sieve/global/learn-spam.sieve ]
then
	  ${SUDO} tee /var/vmail/sieve/global/learn-spam.sieve > /dev/null <<EOF
require ["vnd.dovecot.pipe", "copy", "imapsieve"];
pipe :copy "rspamc" ["learn_spam"];
EOF
    ${SUDO} [ ! -e /var/vmail/sieve/global/learn-spam.sieve ] && error_exit 'creating learn-spam.sieve...failed'
    ${SUDO} sievec /var/vmail/sieve/global/learn-spam.sieve
fi

if ${SUDO} [ ! -e /var/vmail/sieve/global/learn-ham.sieve ]
then
	  ${SUDO} tee /var/vmail/sieve/global/learn-ham.sieve > /dev/null <<EOF
require ["vnd.dovecot.pipe", "copy", "imapsieve"];
pipe :copy "rspamc" ["learn_ham"];
EOF
    ${SUDO} [ ! -e /var/vmail/sieve/global/learn-ham.sieve ] && error_exit 'creating learn-ham.sieve...failed'
    ${SUDO} sievec /var/vmail/sieve/global/learn-ham.sieve
fi

${SUDO} chown -R vmail:vmail /var/vmail

if ${SUDO} [ ! -e /etc/logrotate.d/dovecot ]
then
	  ${SUDO} tee /etc/logrotate.d/dovecot > /dev/null <<EOF
/var/log/dovecot*.log {
  missingok
  notifempty
  delaycompress
  sharedscripts
  postrotate
  doveadm log reopen
  endscript
}
EOF
    ${SUDO} [ ! -e /etc/logrotate.d/dovecot ] && error_exit 'creating dovecot logrotate...failed'
fi

if ${SUDO} [ ! -e /var/lib/unbound/root.key ]
then
    ${SUDO} unbound-anchor -a /var/lib/unbound/root.key
    ${SUDO} systemctl reload unbound
    if [ $? -eq 1 ]
    then
        eroor_exit 'starting unbound...failed'
    fi
fi

if [ ! -e /etc/resolvconf/resolv.conf.d/head ]
then
    echo "nameserver 127.0.0.1" > ${SUDO} tee -a /etc/resolvconf/resolv.conf.d/head
    ${SUDO} [ ! -e /etc/resolvconf/resolv.conf.d/head ] && error_exit 'configuring DNS...failed'
fi

#aws route53 list-resource-record-sets --hosted-zone-id Z2K174UVVCW6BH --query "ResourceRecordSets[?Name == '_dmarc.kevinedwards.ca.']" | grep "rua=mailto:postmaster@kevinedwards.ca; ruf=mailto:postmaster@kevinedwards.ca;"
if ! aws route53 list-resource-record-sets --hosted-zone-id ${HOSTEDZONE} --query "ResourceRecordSets[?Name == '_dmarc.kevinedwards.ca.']" | grep ruf=mailto:postmaster@${DOMAIN}; > /dev/null 2>&1
then
    cli53 rrcreate --replace ${DOMAIN} "${HOSTNAME} 60 A ${PUBLIC_IPV4}" > /dev/null
    cli53 rrcreate --replace ${DOMAIN} "@ MX 10 ${HOSTNAME}" > /dev/null
    cli53 rrcreate --replace ${DOMAIN} "@ TXT v=spf1 mx a ptr a:kevinedwards.ca include:kncedwards.com ~all" > /dev/null
    cli53 rrcreate --replace ${DOMAIN} "_dmarc TXT \"v=DMARC1; p=quarantine; pct=100; rua=mailto:postmaster@${DOMAIN}; ruf=mailto:postmaster@${DOMAIN};\"" > /dev/null
fi

if [ $(cli53 -l | grep "Reverse DNS") ]
then
    reverse_dns "${PUBLIC_IPV4}"
    cli53 create ${RDNS} --comment 'Reverse DNS' > /dev/null
    cli53 rrcreate --replace ${RDNS} "@ PTR ${HOSTNAME}.${DOMAIN}" > /dev/null
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/classifier-bayes.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/classifier-bayes.conf > /dev/null <<EOF
servers = "127.0.0.1";
backend = "redis";
autolearn = true;
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/classifier-bayes.conf ]  && error_exit 'configuring classifier-bayes.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/options.inc ]
then
    ${SUDO} tee /etc/rspamd/local.d/options.inc > /dev/null <<EOF
local_addrs = "127.0.0.0/8, ::1";

dns {
    nameserver = ["127.0.0.1:53:10"];
}
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/options.inc ] && error_exit 'configuring options.inc...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/worker-normal.inc ]
then
    ${SUDO} tee /etc/rspamd/local.d/worker-normal.inc > /dev/null <<EOF
bind_socket = "localhost:11333";
EOF
   ${SUDO} [ ! -e /etc/rspamd/local.d/worker-normal.inc ] && error_exit 'configuring worker-normal.inc...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/worker-controller.inc ]
then
    ${SUDO} tee /etc/rspamd/local.d/worker-controller.inc > /dev/null <<EOF
# set password with: rspamadm pw
password = "";
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/worker-controller.inc ] && error_exit 'configuring worker-controller.inc...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/worker-proxy.inc ]
then
    ${SUDO} tee /etc/rspamd/local.d/worker-proxy.inc > /dev/null <<EOF
bind_socket = "localhost:11332";
milter = yes;
timeout = 120s;
upstream "local" {
    default = yes;
    self_scan = yes;
}
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/worker-proxy.inc ] && error_exit 'configuring worker-proxy.inc...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/dkim_signing.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/dkim_signing.conf > /dev/null <<EOF
# If false, messages with empty envelope from are not signed
allow_envfrom_empty = true;

# If true, envelope/header domain mismatch is ignored
allow_hdrfrom_mismatch = false;

# If true, multiple from headers are allowed (but only first is used)
allow_hdrfrom_multiple = false;

# If true, username does not need to contain matching domain
allow_username_mismatch = false;

# If false, messages from authenticated users are not selected for signing
auth_only = true;

# Default path to key, can include '$domain' and '$selector' variables
path = "/var/lib/rspamd/dkim/mail.key";

# Default selector to use
selector = "mail";

# If false, messages from local networks are not selected for signing
sign_local = true;

# Map file of IP addresses/subnets to consider for signing
# sign_networks = "/some/file"; # or url

# Symbol to add when message is signed
symbol = "DKIM_SIGNED";

# Whether to fallback to global config
try_fallback = true;

# Domain to use for DKIM signing: can be "header" (MIME From), "envelope" (SMTP From) or "auth" (SMTP username)
use_domain = "header";

# Domain to use for DKIM signing when sender is in sign_networks ("header"/"envelope"/"auth")
#use_domain_sign_networks = "header";

# Domain to use for DKIM signing when sender is a local IP ("header"/"envelope"/"auth")
#use_domain_sign_local = "header";

# Whether to normalise domains to eSLD
use_esld = true;

# Whether to get keys from Redis
use_redis = false;

# Hash for DKIM keys in Redis
key_prefix = "DKIM_KEYS";

# map of domains -> names of selectors (since rspamd 1.5.3)
#selector_map = "/etc/rspamd/dkim_selectors.map";

# map of domains -> paths to keys (since rspamd 1.5.3)
#path_map = "/etc/rspamd/dkim_paths.map";

# Domain specific settings
domain {

  # Domain name is used as key
  kevinedwards.ca {

    # Private key path
    path = "/var/lib/rspamd/dkim/mail.key";

    # Selector
    selector = "mail";

  }

}
EOF
	${SUDO} [ ! -e /etc/rspamd/local.d/dkim_signing.conf ] && error_exit 'configuring logging.inc...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/logging.inc ]
then
    ${SUDO} tee /etc/rspamd/local.d/logging.inc > /dev/null <<EOF
type = "file";
filename = "/var/log/rspamd/rspamd.log";
level = "error";
debug_modules = ["dkim"];
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/logging.inc ] && error_exit 'configuring logging.inc...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/milter_headers.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/milter_headers.conf > /dev/null <<EOF
use = ["x-spam-status", "x-spam-level", "authentication-results"];
authenticated_headers = ["authentication-results"];
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/milter_headers.conf ] && error_exit 'configuring milter_headers.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/replies.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/replies.conf > /dev/null << EOF
action = "no action";
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/replies.conf ] && error_exit 'configuring replies.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/redis.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/redis.conf > /dev/null << EOF
servers = "127.0.0.1";
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/redis.conf ] && error_exit 'configuring redis.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/surbl.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/surbl.conf > /dev/null <<EOF
redirector_hosts_map = "/etc/rspamd/redirectors.inc";
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/surbl.conf ] && error_exit 'configuring surbl.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/url_reputation.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/url_reputation.conf > /dev/null <<EOF
enabled = true;
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/url_reputation.conf ] && error_exit 'configuring url_reputation.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/url_tags.conf ]
then
    ${SUDO} tee /etc/rspamd/local.d/url_tags.conf > /dev/null <<EOF
enabled = true;
EOF
    [ ! -e /etc/rspamd/local.d/url_tags.conf ] && error_exit 'configuring url_tags.conf...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/rspamd.conf.local ]
then
    ${SUDO} tee /etc/rspamd/local.d/rspamd.conf.local  > /dev/null <<EOF
worker "log_helper" {
     count = 1;
}
EOF
    ${SUDO} [ ! -e /etc/rspamd/local.d/rspamd.conf.local ] && error_exit 'configuring rspamd.conf.local...failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/train-spam.sh ]
then
    ${SUDO} tee /etc/rspamd/local.d/train-spam.sh > /dev/null <<EOF
#!/bin/bash

# http://artinvoice.hu/spams/

spamfile=spam--`date '+%Y-%m-%d'`.gz
spamfile_unpacked=spam--`date '+%Y-%m-%d'`

wget -q http://artinvoice.hu/spams/\$spamfile
gunzip \$spamfile

if [ ! -e mb2md.py ]
then
    wget -q https://raw.githubusercontent.com/jpschewe/admin-scripts/master/mb2md.py
    chmod +x mb2md.py
fi

./mb2md.py -i \$spamfile_unpacked -o spam/
rspamc learn_spam spam/cur/ > /dev/null
rm -r \$spamfile_unpacked mb2md.py spam/

exit 0
EOF
    ${SUDO} chmod +x /etc/rspamd/local.d/train-spam.sh
    ${SUDO} [ ! -e /etc/rspamd/local.d/train-spam.sh ] && error_exit 'configuring train-spam.sh...failed'
fi

if ${SUDO} [ ! -e /var/lib/rspamd/surbl-whitelist.inc.local ]
then
    echo "# comment so /var/log/rspamd/rspamd.log does not fill up with errors" | ${SUDO} tee /var/lib/rspamd/spf_dkim_whitelist.inc.local /var/lib/rspamd/dmarc_whitelist.inc.local /var/lib/rspamd/mime_types.inc.local /var/lib/rspamd/2tld.inc.local /var/lib/rspamd/surbl-whitelist.inc.local /etc/rspamd/local.d/mid.inc > /dev/null
    ${SUDO} [ ! -e /var/lib/rspamd/surbl-whitelist.inc.local ] && error_exit 'configuring surbl-whitelist.inc.local...failed'
fi

if ${SUDO} [ ! -e /etc/redis/redis.conf.bak ]
then
    ${SUDO} cp /etc/redis/redis.conf /etc/redis/redis.conf.bak > /dev/null <<EOF
	  if ! ${SUDO} grep -q 'maxmemory 500mb' /etc/redis/redis.conf
	      ${SUDO} sed -i 's|# maxmemory <bytes>|maxmemory 500mb|' /etc/redis/redis.conf
 	  fi

	  if ! ${SUDO} grep -q 'maxmemory-policy volatile-lru' /etc/redis/redis.conf
	      ${SUDO} sed -i 's|# maxmemory-policy noeviction|maxmemory-policy volatile-lru|' /etc/redis/redis.conf
 	  fi
      ${SUDO} [ ! -e /etc/redis/redis.conf.bak ] && error_exit 'configuring redis.conf..failed'
fi

if ${SUDO} [ ! -e /etc/rspamd/local.d/arc.conf ]
then
    ${SUDO} mkdir -p /var/lib/rspamd/dkim
    ${SUDO} 
	${SUDO} sh chmod 440 /var/lib/rspamd/dkim/*
    ${SUDO} chown -R _rspamd:_rspamd /var/lib/rspamd/dkim
	${SUDO} mkdir -p /etc/rspamd/local.d
    ${SUDO} tee /etc/rspamd/local.d/dkim_signing.conf > /dev/null <<EOF
path = "/var/lib/rspamd/dkim/\$selector.key";
selector = "mail";

### Enable DKIM signing for alias sender addresses
allow_username_mismatch = true;
EOF
    ${SUDO} cp -R /etc/rspamd/local.d/dkim_signing.conf /etc/rspamd/local.d/arc.conf
    ${SUDO} [ ! -e /etc/rspamd/local.d/arc.conf ] && error_exit 'configuring arc.conf..failed'
fi

if ${SUDO} [ ! -e /etc/logrotate.d/mail ]
then
    ${SUDO} tee /etc/logrotate.d/mail > /dev/null <<EOF
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
{
        rotate 7
        daily
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                invoke-rc.d rsyslog rotate > /dev/null
        endscript
}
EOF
    if ${SUDO} [ ! -e /etc/logrotate.d/rsyslog.bak ]
    then
        ${SUDO} cp /etc/logrotate.d/rsyslog /etc/logrotate.d/rsyslog.bak
        ${SUDO} sed -i "/\b\(mail\)\b/d" /etc/logrotate.d/rsyslog
        ${SUDO} [ ! -e /etc/logrotate.d/rsyslog.bak ] && error_exit 'configuring mail rotate..failed'
    fi
fi

${SUDO} systemctl start rspamd > /dev/null
if [ $? -eq 1 ]
then
    error_exit 'starting rspamd...failed'
fi

crontab -l | grep -v -F "${CRONCOMMAND}" ; echo "${CRONJOB}" | crontab -
if [ $? -eq 1 ]
then
    error_exit 'writing cronjob...failed'
fi

# # if ! sudo test -f /var/lib/rspamd/bayes.spam.sqlite.bak; then
# # 	sudo cp /var/lib/rspamd/bayes.spam.sqlite /var/lib/rspamd/bayes.spam.sqlite.bak
# # 	sudo cp /var/lib/rspamd/bayes.ham.sqlite /var/lib/rspamd/bayes.ham.sqlite.bak
# # 	sudo wget -q -O /var/lib/rspamd/bayes.spam.sqlite http://rspamd.com/rspamd_statistics/bayes.spam.sqlite
# # 	sudo wget -q -O /var/lib/rspamd/bayes.ham.sqlite http://rspamd.com/rspamd_statistics/bayes.ham.sqlite
# # 	sudo chown _rspamd:_rspamd /var/lib/rspamd/bayes.ham.sqlite
# # 	sudo chown _rspamd:_rspamd /var/lib/rspamd/bayes.spam.sqlite
# # fi

#perl -MMIME::Base64 -e 'print encode_base64("kedwards\@kncedwards.com\0kedwards\@example.org\0summersun")';
# kedwards@kncedwards.com - a2Vkd2FyZHNAa25jZWR3YXJkcy5jb20Aa2Vkd2FyZHNAa25jZWR3YXJkcy5jb20AQWxpY2lhMjAxMCZSb2JlcnQyMDEx
