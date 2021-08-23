#!/bin/bash

gcc add-chain.c add-rule.c add-table.c rem-chain.c rem-rule.c rem-table.c upd-table.c main.c -o main -l nftnl  -l mnl -lzmq

gcc bezero.c -o bezero -lzmq
