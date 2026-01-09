import string

def identity_encoder(w: str):
    yield w

def url_encoder(w: str):
    yield w
    yield w + "%00"

    if not w:
        return

    encode_dotdot = w.replace("..", "%2e%2e")
    yield encode_dotdot
    yield encode_dotdot + "%00"

    encode_dotdot_and_slashes = encode_dotdot.replace("/", "%2f").replace("\\", "%5c")
    yield encode_dotdot_and_slashes
    yield encode_dotdot_and_slashes + "%00"

def url_encoder_strict(w: str):
    yield "".join("%{0:0>2x}".format(ord(c)) if c not in (string.ascii_uppercase + string.ascii_lowercase + string.digits) else c for c in w)