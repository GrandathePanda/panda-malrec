#!/bin/bash
while true; do ls queue/pending/ | parallel -j 4 python scripts/runmal.py conf/malrec.config {/} {%} ; sleep 600 ; done
