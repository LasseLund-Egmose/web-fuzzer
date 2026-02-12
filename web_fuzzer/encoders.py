import string

def identity_encoder(args, w: str):
    yield w

def lfi_encoder(args, w: str):
    words = [w]

    if "php-filter" in args.lfi_encoders:
        words.append(f"php://filter/convert.base64-encode/resource={w}")

    for f in words:
        if "id" in args.lfi_encoders:
            yield f

        if not f:
            return
        
        if "dot-dot" in args.lfi_encoders:
            encode_dotdot = f.replace("..", "%2e%2e")
            yield encode_dotdot

        if "dot-dot-slash" in args.lfi_encoders:
            encode_dotdot_and_slashes = encode_dotdot.replace("/", "%2f").replace("\\", "%5c")
            yield encode_dotdot_and_slashes

def url_encoder_strict(args, w: str):
    yield "".join("%{0:0>2x}".format(ord(c)) if c not in (string.ascii_uppercase + string.ascii_lowercase + string.digits) else c for c in w)