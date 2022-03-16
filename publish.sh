#!/bin/bash

# cp surftrace.py surftrace/

cp -r surftrace/ pub/
cp setupTrace.py pub/setup.py
cd pub/
python setup.py sdist
cd ../

cp -r surfGuide/ pub/
cp setupGuide.py pub/setup.py
cd pub/
python setup.py sdist
cd ../

cp -r pylcc/ pub/
cp setupPylcc.py pub/setup.py
cd pub/
python setup.py sdist
cd ../