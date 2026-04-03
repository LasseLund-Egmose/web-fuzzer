import argparse
import asyncio
import hashlib
import json
import numpy as np
import os
import re
import shutil

from functools import partial
from glob import glob
from multiprocessing import Pool, cpu_count
from playwright.async_api import async_playwright
from tqdm import tqdm

from .const import MAX_DISPLAY_RESULTS, INTERESTING_STRINGS
from .data_classes import *
from .util import find_common_substrings, parse_http_response
from .encoders import *
from .php import php_fuzz
from .revshells import get_revshells
from .sql import *
from .wordlists import wordlist_strip_prefix
from .xss import xss_fuzz, xss_fuzz_labeled

def relpath_linux(args):
    if args.known_relpath:
        return [args.known_relpath.encode()]
    
    return [b"", b"/", b"../", b"../../", b"../../../", b"../../../../../../../../../../../../", b"/", b"~/"]

def relpath_windows(args):
    if args.known_relpath:
        return [args.known_relpath.encode()]
    
    return [b"", b"/", b"\\", b".\\", b"..\\", b"..\\..\\", b"..\\..\\..\\", b"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\", b"C:\\"]

def relpath(args):
    if args.known_relpath:
        return [args.known_relpath.encode()]
    
    return relpath_linux(args) + relpath_windows(args)

DEFAULT_USERNAMES = ['admin', 'administrator', 'root', 'user', 'guest', 'test', 'demo', 'support', 'operator']
DEFAULT_PASSWORDS = ['admin', 'password', '123456', '12345678', '123456789', 'admin123', 'Admin@123', 'P@ssw0rd', 'qwerty', 'welcome', '12345', '123456789', '1234', 'letmein', 'changeme', 'password123', 'Aa123456', '111111', '1234567890', 'admin123']

FUZZ_TYPES = {
    "command-injection": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/seclists/Fuzzing/command-injection-commix.txt"
        ]),
    ], encoders=[identity_encoder], required_args=[]),

    "logins": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        ]),
        FuzzParameter(name="FUZ2Z", wordlists=[
            "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-1000.txt"
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "login-passwords": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-1000000.txt"
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "login-usernames": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "lfi-general": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath,
            [wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt", [b"/", b"c:\\", b"C:\\", b"c:/", b"C:/"])]
        ]),
    ], encoders=[lfi_encoder], required_args=[]),

    "lfi-general-linux": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_linux,
            [wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt", [b"~/", b"/", b"~"])]
        ]),
    ], encoders=[lfi_encoder], required_args=[]),

    "lfi-general-linux-extra": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_linux,
            [wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt", [b"/"])]
        ]),
    ], encoders=[lfi_encoder], required_args=[]),

    "lfi-general-windows": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_windows, [
                wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt", [b"c:\\", b"C:\\", b"c:/", b"C:/"]),
                wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt", [b"/", b"c:\\", b"C:\\", b"c:/", b"C:/"])
            ]
        ]),
    ], encoders=[lfi_encoder], required_args=[]),

    "lfi-known-file": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath,
            lambda args: [args.known_file.encode()]
        ]),
    ], encoders=[lfi_encoder], required_args=["known_file"]),
    
    "lfi-known-part-linux": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_linux,
            lambda args: [args.known_part.encode()],
            "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt"
        ]),
    ], encoders=[lfi_encoder], required_args=["known_part"]),

    "lfi-webroot-windows": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_windows,
            wordlist_strip_prefix("/usr/share/seclists/Discovery/Web-Content/default-web-root-directory-windows.txt", [b"c:\\", b"C:\\", b"c:/", b"C:/"]),
            "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt"
        ]),
    ], encoders=[lfi_encoder], required_args=[]),

    "php": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            php_fuzz
        ]),
    ], encoders=[url_encoder_strict], required_args=["attackbox_ip", "attackbox_web_port"]),

    "revshell-linux": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            lambda args: [rev.encode() for rev in get_revshells(args.attackbox_ip, args.attackbox_port, args.attackbox_web_port, os="linux")]
        ]),
    ], encoders=[url_encoder_strict], required_args=["attackbox_ip", "attackbox_port", "attackbox_web_port"]),

    "revshell-windows": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            lambda args: [rev.encode() for rev in get_revshells(args.attackbox_ip, args.attackbox_port, args.attackbox_web_port, os="windows")]
        ]),
    ], encoders=[url_encoder_strict], required_args=["attackbox_ip", "attackbox_port", "attackbox_web_port"]),

    "sqli-execute-linux": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            sqli_execute_linux
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "sqli-execute-windows": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            sqli_execute_windows
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "sqli-id-known-payloads": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/wordlists/wfuzz/Injections/SQL.txt"
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "sqli-id-union-stack": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            sqli_prefix,
            sqli_union_stack,
            sqli_suffix,
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "xss": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            xss_fuzz,
        ]),
    ], encoders=[url_encoder_strict], required_args=["attackbox_ip", "attackbox_web_port"]),
}

def key_by(scan_results: list, key: str):
    results = {}

    for scan_result in scan_results:
        k_val = getattr(scan_result, key)

        if k_val not in results:
            results[k_val] = set()
        
        results[k_val].add(scan_result)
    
    return results

def compute_outliers(values, z_scores):
    max_z_score = int(round(max(z_scores), 0)) + 1
    for start_z in range(max_z_score, 0, -1):
        outliers = values[z_scores > start_z]

        if len(outliers) > 0:
            yield outliers.tolist(), start_z

            for z in range(start_z - 1, 0, -1): # Yield 2 more
                yield values[z_scores > z].tolist(), z

            break

def compute_analysis_groups(keyed_results: dict):
    if len(keyed_results.keys()) == 0:
        return [], 0, 0

    weighted_dict = {}
    for key in keyed_results:
        weighted_dict[key] = len(keyed_results[key])
    
    values = np.array(list(weighted_dict.keys()), dtype=float)
    weights = np.array(list(weighted_dict.values()), dtype=float)

    mean = np.average(values, weights=weights)
    variance = np.average((values - mean)**2, weights=weights)

    std = np.sqrt(variance)
    if std == 0:
        std = 0.000000000001

    z_scores = np.abs(values - mean) / std

    return compute_outliers(values, z_scores), mean, std

def display_analysis_group(keyed_results: dict, total: int):
    for i, (k_val, results) in enumerate(sorted(keyed_results.items(), key=lambda s: s[0], reverse=True)):
        if i >= 50: # Cap at displaying 50 results
            break

        results = list(sorted(results, key=lambda r: r.url))

        print(f"{k_val} ({round(len(results) / total * 100, 2)}% of all results):")
        for result in results[:MAX_DISPLAY_RESULTS]:
            print(f"- {dict(result.payloads)}")
        
        if len(results) > MAX_DISPLAY_RESULTS:
            print("- ...")
        
        print()


def display_analysis(scan_results: list, key: str, key_name: str, outlier_based = False):
    total = len(scan_results)
    keyed_results = key_by(scan_results, key)
    
    if outlier_based:
        outliers, mean, std = compute_analysis_groups(keyed_results)
        print(f"\033[38;5;28m----- Results for {key_name} (mean={round(mean, 2)}, std={round(std, 2)}):\033[0m")

        displayed_outliers = set()
        for outliers, z in outliers:
            keyed_results_outliers = {}
            for key in keyed_results:
                if key not in outliers or key in displayed_outliers:
                    continue
                
                keyed_results_outliers[key] = keyed_results[key]
                displayed_outliers.add(key)
            
            if len(keyed_results_outliers.keys()) == 0:
                continue

            print(f"\033[38;5;114m--- New outliers for z={z}:\033[0m")
            display_analysis_group(keyed_results_outliers, total)
        
        return
    
    print(f"\033[38;5;28m----- Results for {key_name}:\033[0m")
    display_analysis_group(keyed_results, total)

def display_missing_payloads_analysis(missing_payloads: dict):
    print(f"\033[38;5;28m----- Missing payloads in results analysis:\033[0m")

    for data_file, params_payloads in missing_payloads.items():
        print(f"\033[38;5;114m--- Missing payloads for {data_file}:\033[0m")

        if sum([len(p) for p in params_payloads.values()]) > 100:
            print(f"- Too many missing payloads to display ({sum([len(p) for p in params_payloads.values()])} total), skipping...\n")
            continue

        for param, payloads_linenos in sorted(params_payloads.items(), key=lambda item: item[0]):
            for payload, _ in sorted(payloads_linenos.items(), key=lambda item: min(item[1])):
                print(f"- Parameter \033[38;5;24m{param}\033[0m: Missing payload \033[38;5;117m{payload}\033[0m")


        print()

def parse_response_bodies(scan_result, interesting_strings, substring_search_targets, min_substring_len, xss_test):
    async def xss_test_async(html_body):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            console_logs = []
            page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))

            await page.set_content(html_body)
            
            await page.wait_for_load_state("domcontentloaded")
            await page.wait_for_timeout(500)

            await browser.close()

            payloads_fired = set()
            for log in console_logs:
                if not log.startswith("[log] "):
                    continue

                log = log[6:]

                if log.isnumeric():
                    payloads_fired.add(int(log))
            
            return payloads_fired

    with open(scan_result.resultfile_path, "rb") as f:
        _, response_raw = f.read().split(b"\n---- \xe2\x86\x91 Request ---- Response \xe2\x86\x93 ----\n\n")
    
    response_body = parse_http_response(response_raw)

    # Search for interesting substrings
    search_results = set()
    for needle in interesting_strings:
        if isinstance(needle, re.Pattern):
            for result in needle.finditer(response_body):
                result = result.group()

                if len(result) < min_substring_len:
                    continue

                if all([result[i] == 0 for i in range(1, len(result), 2)]):
                    search_results.add(result.decode("utf-16le"))
                else:
                    search_results.add(result.decode())
            
            continue
        
        if needle.lower().encode() in response_body.lower():
            search_results.add(needle)

    # Add scan result's payloads as substring search targets as well
    for _, payload in scan_result.payloads:
        if len(payload) >= min_substring_len:
            substring_search_targets.add(payload.encode())

    # Find substrings
    filtered_substring_matches = set()
    substring_matches = find_common_substrings(substring_search_targets, response_body, min_substring_len)
    for match in substring_matches:
        if any([len(match) < len(other_match) and match in other_match for other_match in substring_matches]):
            continue # Take only broadest matches

        filtered_substring_matches.add(match)
    
    xss_payloads = set()
    if xss_test:
        try:
            xss_payloads = asyncio.run(xss_test_async(response_body.decode()))
        except:
            pass

    return scan_result, search_results, filtered_substring_matches, xss_payloads

def display_response_interesting_strings_analysis(search_results: dict):
    print(f"\033[38;5;28m----- Results for interesting strings:\033[0m")

    for key, results in sorted(search_results.items(), key=lambda i: i[0]):
        if len(results) == 0:
            continue

        print(f"\033[38;5;114m--- String `{key}`:\033[0m")

        for i, result in enumerate(results):
            if i >= MAX_DISPLAY_RESULTS:
                print("- ...")
                break

            print(f"- {dict(result.payloads)}")
        
        print()

def display_response_substring_analysis(substring_matches: dict):   
    print(f"\033[38;5;28m----- Results for substring reflection:\033[0m")

    for substring, results in sorted(substring_matches.items(), key=lambda i: i[0]):
        if len(results) == 0:
            continue

        print(f"\033[38;5;114m--- String `{substring}`:\033[0m")

        for i, result in enumerate(results):
            if i >= MAX_DISPLAY_RESULTS:
                print("- ...")
                break

            print(f"- {dict(result.payloads)}")
        
        print()

def display_response_xss_analysis(xss_payloads: set, payloads_dict: dict):
    print(f"\033[38;5;28m----- Results for XSS payloads that fired:\033[0m")

    # List all remote payloads
    for payload_id, (payload_type, payload) in payloads_dict.items():
        if payload_type != "Remote":
            continue

        print(f"- Remote payload (ID {payload_id}): {payload}")

    # List fired local payloads
    for payload_id in sorted(xss_payloads):
        payload_type, payload = payloads_dict.get(payload_id, ("unknown", "Unknown payload"))
        print(f"- Local payload fired (ID {payload_id}): {payload}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--proto', required=True, help="http or https")
    parser.add_argument('-r', '--request', required=True, help="Request template file")
    parser.add_argument('-t', '--types', required=True, choices=list(FUZZ_TYPES.keys()), nargs="+", help="Type of fuzz")
    parser.add_argument('-th', '--threads', type=int, default=4, help="Number of threads to run FFUF with")
    parser.add_argument('-w', '--wordlist', nargs="+", default=[], help="Override built-in parameter wordlist. In the format `/path/to/wordlist.txt:param` (can be used multiple times)")

    parser.add_argument('--attackbox-ip')
    parser.add_argument('--attackbox-port', type=int)
    parser.add_argument('--attackbox-web-port', type=int)
    parser.add_argument('--known-file')
    parser.add_argument('--known-part')
    parser.add_argument('--known-relpath')
    parser.add_argument('--lfi-encoders', nargs="+",
                        choices=["id", "url-encode", "double-url-encode", "php-filter"],
                        default=["id", "url-encode", "double-url-encode", "php-filter"],
                        help="Encoders to use for LFI fuzzing.")

    args = parser.parse_args()

    fuzz_types = [FUZZ_TYPES[t] for t in args.types]
    fuzz_params = set([fp.name for ft in fuzz_types for fp in ft.params])

    override_params = {}
    for w in args.wordlist or []:
        if w.count(":") != 1:
            print(f"Invalid wordlist format: `{w}`. Should be in the format `/path/to/wordlist.txt:param`")
            return
        
        path, param = w.split(":", maxsplit=1)
        if param not in fuzz_params:
            print(f"Invalid parameter `{param}` in wordlist override. Should be one of {', '.join(sorted(fuzz_params))}")
            return

        print(f"Overriding parameter `{param}` with wordlist `{path}`")
        override_params[param] = path

    for typ, fuzz_type in zip(args.types, fuzz_types):
        for req_arg in fuzz_type.required_args:
            if not getattr(args, req_arg):
                print(f"Error: Argument `{req_arg.replace("_", "-")}` is required to perform `{typ}` fuzzing")
                return
            
    if args.known_file and args.known_file[0] == "/":
        print("--known-file should not start with a slash")
        return
    
    if args.known_part and (args.known_part[0] == "/" or args.known_part[-1] != "/"):
        print("--known-part should not start with a slash, and it should end with one")
        return
    
    if args.known_relpath and args.known_relpath[-1] != "/":
        print("--known-relpath should end with a slash")
        return

    if ("revshell-linux" in args.types or "revshell-windows" in args.types) and args.threads > 1:
        print("revshell-linux and revshell-windows must be run with 1 thread only!")
        return

    response_search_targets = set()
    with open(args.request, "rb") as f: # Check that params are given in the request file and determine substring search targets
        request_raw = f.read()

        for fuzz_type in fuzz_types:
            for param in fuzz_type.params:
                assert param.name.encode() in request_raw

        requestline_headers, request_body = request_raw, b""
        if b"\r\n\r\n" in request_raw or b"\n\n" in request_raw:
            requestline_headers, request_body = request_raw.split(b"\r\n\r\n", maxsplit=1) if b"\r\n\r\n" in request_raw else request_raw.split(b"\n\n", maxsplit=1)
        
        requestline, *headers = requestline_headers.split(b"\r\n") if b"\r\n" in requestline_headers else requestline_headers.split(b"\n")
        
        request_path = requestline.split(b" ")[1].decode()
        request_headers = dict([h.decode().split(": ") for h in headers if b": " in h])
        request_body = request_body.decode()

        request_query = request_path.split("?")[1] if "?" in request_path else ""
        request_params = dict([p.split("=") for p in request_query.split("&")]) if "&" in request_query else {}

        response_search_targets = set(request_params.values()).union(set(request_headers.values()))

        if request_body and len(request_body) < 64:
            response_search_targets.add(request_body)

        response_search_targets = set([t.encode() for t in response_search_targets])
    
    config_hash = hashlib.md5(f"{args.proto}|{args.request}|{args.types}|{args.attackbox_ip}|{args.attackbox_port}|{args.known_part}".encode("utf-8")).hexdigest()
    data_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "web-fuzzer", config_hash)
    shutil.rmtree(data_dir, ignore_errors=True)
    os.makedirs(data_dir)

    command_args = []
    for fuzz_type in fuzz_types:
        command_args.extend(fuzz_type.command_args(override_params, data_dir, args))

    for i, fuzz_args in enumerate(command_args):
        data_file = os.path.join(data_dir, f"ffuf-{i}.json")
        log_file = os.path.join(data_dir, f"ffuf-log-{i}.txt")

        print("Press CTRL+C to stop the scan and start analysis (partial results will be saved and analyzed), or wait for it to finish...")
        os.system(f"ffuf -noninteractive -t {args.threads} -mc all -request-proto {args.proto} -request {args.request} -timeout 30{fuzz_args} -debug-log {log_file} -o {data_file} -of json -od {data_dir}/ > /dev/null")

    scan_results = set()
    missing_payloads = {}

    data_files = glob(os.path.join(data_dir, "ffuf-*.json"))
    for data_file in sorted(data_files):
        print(f"\n\nProcessing {data_file}...")

        with open(data_file, "rb") as f:
            scan = json.load(f)

            missing_payloads[data_file] = {}

            for wordlist_param in scan["config"]["wordlists"]:
                wordlist, param = wordlist_param.split(":")
                assert param not in missing_payloads[data_file]

                missing_payloads[data_file][param] = {}
                with open(wordlist) as f:
                    for i, line in enumerate(f.read().splitlines()):
                        if line not in missing_payloads[data_file][param]:
                            missing_payloads[data_file][param][line] = []
                        
                        missing_payloads[data_file][param][line].append(i)

            for result in tqdm(scan["results"]):
                payloads = result["input"]
                del payloads["FFUFHASH"]
                
                scan_results.add(ScanResult(payloads=frozenset(payloads.items()), url=result["url"], status=result["status"], length=result["length"],
                                                words=result["words"], lines=result["lines"], content_type=result["content-type"], duration=result["duration"],
                                                resultfile_path = os.path.join(data_dir, result["resultfile"])))

                for param, value in payloads.items():
                    if value in missing_payloads[data_file][param]:
                        del missing_payloads[data_file][param][value]

    print("\n\n")

    display_analysis(scan_results, "status", "Status code")
    display_analysis(scan_results, "length", "Content length", outlier_based=True)
    display_analysis(scan_results, "words", "Content words", outlier_based=True)
    display_analysis(scan_results, "lines", "Content lines", outlier_based=True)
    display_analysis(scan_results, "duration", "Time to response (nanoseconds)", outlier_based=True)

    display_missing_payloads_analysis(missing_payloads)

    # Response body parsing
    global_search_results = {}

    min_len = 8
    response_search_targets = set(filter(lambda t: len(t) >= min_len, response_search_targets))
    global_substring_matches = {}

    global_xss_payloads = set()

    parse_callable = partial(parse_response_bodies, interesting_strings=INTERESTING_STRINGS, substring_search_targets=response_search_targets, min_substring_len=min_len, xss_test=("xss" in args.types))
    with Pool(cpu_count() // 2) as pool:
        for scan_result, search_results, substring_matches, xss_payloads in tqdm(pool.imap_unordered(parse_callable, scan_results), total=len(scan_results), desc="Analyzing response bodies..."):
            for key in search_results: # Handle keyword search
                if key not in global_search_results:
                    global_search_results[key] = set()

                global_search_results[key].add(scan_result)
            
            for substring in substring_matches: # Handle substring search
                if substring not in global_substring_matches:
                    global_substring_matches[substring] = set()
                
                global_substring_matches[substring].add(scan_result)
            
            for payload in xss_payloads: # Handle XSS payloads that fired
                global_xss_payloads.add(payload)

    display_response_interesting_strings_analysis(global_search_results)
    display_response_substring_analysis(global_substring_matches)

    if "xss" in args.types:
        display_response_xss_analysis(global_xss_payloads, {i: (t, p) for i, t, p in xss_fuzz_labeled(args)})

if __name__ == "__main__":
    main()