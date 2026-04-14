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
        
        url_encoded = f.replace("..", "%2e%2e").replace("/", "%2f").replace("\\", "%5c")
        if "url-encode" in args.lfi_encoders:
            yield url_encoded

        double_url_encoded = url_encoded.replace("%", "%25")
        if "double-url-encode" in args.lfi_encoders:
            yield double_url_encoded

def json_encoder(args, w: str):
    yield w.replace('"', '\\"')

def url_encoder_strict(args, w: str):
    yield "".join("%{0:0>2x}".format(ord(c)) if c not in (string.ascii_uppercase + string.ascii_lowercase + string.digits) else c for c in w)