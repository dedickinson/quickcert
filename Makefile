#PHONY=docs

.DEFAULT_GOAL := init

init:
	/usr/bin/env python3 -m pip install pipenv --upgrade
	pipenv install --dev

package: check test
	pipenv run python setup.py sdist bdist_wheel

publish: package
	pipenv run twine upload dist/*
	
check:
	pipenv check
	pipenv run pycodestyle quickcert/*

lint:
	pipenv run pylint quickcert/*.py

test:
	pipenv run tox

ci:
	pipenv run py.test --rootdir=tests --cov=quickcert

format:
	pipenv run autopep8 --in-place --aggressive --aggressive --recursive quickcert/

# docs:
# 	cd docs && make html

clean:
	pipenv clean
	rm -rf build dist .egg .eggs quickcert.egg-info

clean-tox:
	rm -rf .tox
