#!/usr/bin/python3

import sys, json
from lib_ecu import ecu
import shared_public_keys

# ECU Identifier
identifier = sys.argv[0]
signature_private = b'-----BEGIN EC PRIVATE KEY-----\nMFQCAQEEFHSnOew3TjWGdW5j6Lc0i2PJcteqoAsGCSskAwMCCAEBAaEsAyoABOgl\nAkto92xomhttE6I0YMbEcw6JQObSnkJsbJIfwN/CfkmnvTM280M=\n-----END EC PRIVATE KEY-----\n'
newcontroler = ecu(identifier, message_type='ecdsa', public_shared_keys=shared_public_keys.public_keys, private_key=signature_private)
newcontroler.proc()
