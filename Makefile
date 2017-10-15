# This Makefile is a minor convenience for the maintainer. Nothing to see here.

.PHONY: full
full: clean sdist wheel

.PHONY: sdist
sdist:
	python setup.py sdist

.PHONY: wheel
wheel:
	python setup.py bdist_wheel

.PHONY: sign
sign:
	for f in dist/*.gz dist/*.whl; do \
	    if [ ! -e "$${f}.asc" ]; then \
	        gpg2 --detach-sign --armor "$${f}"; \
	    fi \
	done

.PHONY: upload
upload: sign
	twine upload dist/*

.PHONY: clean
clean:
	-rm -r build dist *.egg-info
