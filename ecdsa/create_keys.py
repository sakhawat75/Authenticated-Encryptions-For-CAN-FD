import ecdsa


def more_keys():
    for i in range(1,4):
        sk = ecdsa.SigningKey.generate(curve=ecdsa.BRAINPOOLP160r1)
        vk = sk.verifying_key
        signature = sk.sign(b"message")
        assert vk.verify(signature, b"message")
        print(f'    "{i}": {"{"}')
        print('        "signature_private": ', sk.to_pem(), ",")
        print('        "signature_public": ', vk.to_pem())
        print("    },")

more_keys()

