python2 = python
python3 = python3.5


all: sdist wheel

sdist:
	python setup.py sdist

wheel:
	-rm -r build
	$(python2) setup.py bdist_wheel
	-rm -r build
	$(python3) setup.py bdist_wheel

upload:
	twine upload -s dist/*.gz dist/*.whl

clean:
	-rm -r build dist *.egg-info
