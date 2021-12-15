#!/usr/bin/python3

import sys, json
from lib_ecu import ecu
import shared_public_keys

# ECU Identifier
identifier = sys.argv[0]
signature_private = b'-----BEGIN EC PRIVATE KEY-----\nMFQCAQEEFIKDpuojmn0PhpgKUWzTFzITwZbAoAsGCSskAwMCCAEBAaEsAyoABCxx\nJXFJRkMAqj0CfUH8qqoJjBpNLOhK5kOP3SloHPZompGyDe7jq3s=\n-----END EC PRIVATE KEY-----\n'

newcontroler = ecu(identifier, message_type='ecdsa', public_shared_keys=shared_public_keys.public_keys, private_key=signature_private)
newcontroler.proc()
