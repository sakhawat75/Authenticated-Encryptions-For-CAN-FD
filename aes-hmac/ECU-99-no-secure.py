#!/usr/bin/python3

import sys
from  lib_ecu import ecu

# ECU Identifier
identifier = sys.argv[0]
newcontroler = ecu(identifier)
newcontroler.proc()
