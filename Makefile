python2 = python2.7
python3 = python3.5

.PHONY: full sdist wheel sign upload upload_docs clean


full: clean sdist wheel

sdist:
	python setup.py sdist

wheel:
	-rm -r build
	$(python2) setup.py bdist_wheel
	-rm -r build
	$(python3) setup.py bdist_wheel

sign:
	for f in dist/*.gz dist/*.whl; do \
	    if [ ! -e "$${f}.asc" ]; then \
	        gpg2 --detach-sign --armor "$${f}"; \
	    fi \
	done

upload: sign
	twine upload dist/*

docs:
	@cd docs
	make html zip

upload_docs: docs
	python setup.py upload_docs --upload-dir docs/build/html

clean:
	-rm -r build dist *.egg-info
