#!/bin/bash

source /usr/local/bin/virtualenvwrapper.sh
mkvirtualenv turi --python `which python3`
mkdir -p iotfuzzer
cd iotfuzzer
git clone git@git.seclab.cs.ucsb.edu:peperunas/zeppolina.git
cd zeppolina
git checkout wip/objects_entropy
cd ../..
git clone git@git.seclab.cs.ucsb.edu:conand/turi.git
cd turi
git checkout diane
cd ..
pip install -e turi
git clone git@github.com:angr/pysoot.git
pip install -e pysoot
pip install ipython networkx pandas pyqt5 celery

