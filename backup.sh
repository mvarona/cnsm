#!/bin/bash
read -p "Commit message: " msg
git add . && \
git add -u && \
git commit -m "$msg" && \
git push origin master
