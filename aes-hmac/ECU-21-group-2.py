#!/usr/bin/python3

import sys, json
from  lib_ecu import ecu

# ECU Identifier
identifier = sys.argv[0]
with open("shared_key_group_2.json") as f:
    security_keys = json.load(f)
newcontroler = ecu(identifier, message_type='symmetric', security_keys=security_keys)
newcontroler.proc()
