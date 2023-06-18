FROM securityuniversal/python_flask_base:1

COPY ./requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY ./src /var/www/html/src
RUN chown -R www-data:www-data /var/www/html

RUN /bin/rm -f /etc/apache2/apache2.conf
RUN /bin/mv /var/www/html/src/apache_config/apache2.conf /etc/apache2/apache2.conf
RUN /bin/rm -f /etc/apache2/sites-enabled/000-default.conf
RUN /bin/mv /var/www/html/src/apache_config/000-default.conf /etc/apache2/sites-enabled/000-default.conf
RUN /bin/rm -f /etc/apache2/conf-enabled/other-vhosts-access-log.conf

RUN /bin/rm -f /etc/apache2/conf-enabled/security.conf
RUN /bin/mv /var/www/html/src/apache_config/security.conf /etc/apache2/conf-enabled/security.conf

RUN a2enmod ssl
RUN a2enmod rewrite
RUN a2enmod headers

EXPOSE 80
EXPOSE 443
CMD ["/usr/sbin/apache2", "-D", "FOREGROUND"]