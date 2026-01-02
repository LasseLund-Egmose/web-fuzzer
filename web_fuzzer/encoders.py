import base64
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
    return "".join("%{0:0>2x}".format(ord(c)) if c not in (string.ascii_uppercase + string.ascii_lowercase + string.digits) else c for c in w)

def revshell_encoder_linux(w: str):
    yield w
    yield url_encoder_strict(w)

    bash_wrap = f"bash -c '{w.replace("'", "\\'")}'"
    yield bash_wrap
    yield url_encoder_strict(bash_wrap)

def revshell_encoder_windows(w: str):
    yield w
    yield url_encoder_strict(w)

    powershell_wrap = f"powershell -c '{w.replace("'", "\\'")}'"
    yield powershell_wrap
    yield url_encoder_strict(powershell_wrap)

    powershell_encode = f"powershell -e {base64.b64encode(w.encode('utf-16le')).decode('utf-8')}"
    yield powershell_encode
    yield url_encoder_strict(powershell_encode)