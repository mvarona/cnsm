#!/bin/bash
read -p "Commit message: " msg
git add . && \
git add -u && \
git commit -m "$msg" && \
git push "https://www.github.com/mvarona/cnsm.git" master
