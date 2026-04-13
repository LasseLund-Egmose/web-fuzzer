def ssrf_service_fuzz(args):
    for hostname in ["localhost", "127.0.0.1"]:
        for port in range(1, 65536):
            yield f"http://{hostname}:{port}/".encode()