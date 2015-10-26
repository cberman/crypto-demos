# crypto-demos
## multienc.py
A collection of functions to encrypt a message with multiple public keys, so that any corresponding private key can decrypt. It is also possible to retroactively allow additional parties to decrypt.
This is implemented similarly to PGP: the message itself is encrypted with symmetric crypto using a newly generated session key, which is then encrypted with each of the parties' public keys.
