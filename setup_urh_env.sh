#!/usr/bin/env zsh

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"
BIN_PATH="$SCRIPT_PATH/bin"
PATH="$PATH:$BIN_PATH"
export PATH
