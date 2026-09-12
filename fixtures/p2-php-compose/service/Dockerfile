FROM php:8.3-apache

ENV APACHE_DOCUMENT_ROOT=/srv/app/public
RUN sed -ri -e "s!/var/www/html!${APACHE_DOCUMENT_ROOT}!g" \
        /etc/apache2/apache2.conf \
        /etc/apache2/conf-available/*.conf \
 && a2enmod rewrite headers

# The stock vhost only grants access to /var/www, so relocating the document root
# requires an explicit <Directory> block; without it Apache answers 403 for every
# request (which is exactly the kind of "the service looks down but is only
# misconfigured" failure the drills are meant to teach).
RUN printf '%s\n' \
    '<VirtualHost *:80>' \
    '    DocumentRoot /srv/app/public' \
    '    <Directory /srv/app/public>' \
    '        Options -Indexes +FollowSymLinks' \
    '        AllowOverride None' \
    '        Require all granted' \
    '    </Directory>' \
    '    ErrorLog ${APACHE_LOG_DIR}/error.log' \
    '    CustomLog ${APACHE_LOG_DIR}/access.log combined' \
    '</VirtualHost>' \
    > /etc/apache2/sites-available/000-default.conf

WORKDIR /srv/app
COPY public/ /srv/app/public/
COPY lib/ /srv/app/lib/

# The canary lives outside the download root on purpose: it is the target of the
# tier-3 negative probe, and no legitimate request ever reads it.
RUN mkdir -p /srv/app/files /data/notes \
 && chown -R www-data:www-data /data \
 && printf 'welcome to the fixture\n' > /srv/app/files/welcome.txt \
 && printf 'legacy file, must keep downloading after the patch\n' > /srv/app/files/legacy.txt \
 && printf 'FIXTURE_CANARY_value_outside_the_download_root\n' > /srv/canary.txt

EXPOSE 80
