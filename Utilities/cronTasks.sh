#!/bin/bash

old=$(ps -eo command)
while true; do
    new=$(ps -eo command)
    diff <(echo "$old") <(echo "$new")
    old=$new
    sleep 1
done
