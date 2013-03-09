#!/bin/sh

# A handy script for testing in multiple virtualenvs. Mine are set to the
# default, but others can be passed as arguments.

if [ "$#" = "0" ]; then
    virtualenvs=`for x in 1 2 3 4 5; do echo "${HOME}/.virtualenvs/django-1.${x} "; done`
else
    virtualenvs="$*"
fi


for venv in ${virtualenvs}; do
    echo ${venv}
    source ${venv}/bin/activate
    python manage.py test django_auth_ldap
    deactivate
done
