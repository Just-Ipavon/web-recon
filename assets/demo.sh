#!/usr/bin/env bash
# Records the README demo: types the command out like a human, then runs it.
#
#   asciinema rec assets/demo.cast --cols 100 --rows 40 --overwrite \
#       -c "bash assets/demo.sh"
#   python assets/retime.py assets/demo.cast assets/demo.cast
#   npx svg-term-cli --in assets/demo.cast --out assets/demo.svg \
#       --window --width 100 --height 40 --padding 14
#
# WEBRECON overrides the binary, e.g. WEBRECON=.venv/bin/webrecon.

set -u

WEBRECON="${WEBRECON:-webrecon}"
ARGS="example.com -m dns,http,tls --no-passive -r 10"
LINE="webrecon $ARGS"

printf '\033[1;32m$\033[0m '
sleep 0.5

for (( i = 0; i < ${#LINE}; i++ )); do
    printf '%s' "${LINE:i:1}"
    sleep 0.045
done

printf '\n'
sleep 0.4

# shellcheck disable=SC2086
"$WEBRECON" $ARGS
