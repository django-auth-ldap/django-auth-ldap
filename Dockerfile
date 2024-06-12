FROM bitnami/openldap:latest

USER root

RUN apt-get update -y
RUN apt-get upgrade -y


#RUN apt-get install -y slapd ldap-utils
RUN apt-get install -y libsasl2-dev libldap2-dev libssl-dev gcc git
RUN apt-get install -y python3-dev python3-pip

RUN pip3 install tox

COPY . /django-ldap
WORKDIR /django-ldap

CMD ["tox"]
