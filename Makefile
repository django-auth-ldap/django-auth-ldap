python2 = python
python3 = python3.5


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
	    if [ ! -e ${f}.asc ] \
	        gpg2 --detach-sign --armor ${f}; \
	    fi \
	done

upload: sign
	twine upload dist/*

clean:
	-rm -r build dist *.egg-info
