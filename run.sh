#!/bin/bash
ls queue/pending/$2/ | parallel -j 40 python scripts/runmal.py conf/malrec.config {/} {%} $1 ; sleep 600
