#!/bin/bash

rm -rf /tmp/build-venv 2> /dev/null
python3 -m venv /tmp/build-venv
/tmp/build-venv/bin/pip3 install build
/tmp/build-venv/bin/python3 -m build
rm -rf /tmp/build-venv

pipx install dist/web_fuzzer-0.1.0-py3-none-any.whl --force