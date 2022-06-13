import contextlib
import logging
import os
import subprocess
import tempfile
import time
import uuid

from defweb.common.constants import (
    DEFAULT_CONFIG,
    CERT_ROOT,
    CERT_PATH,
    KEY_PATH,
    CA_KEY_PATH,
    CA_CERT_PATH,
    CA_SIGNING_KEY_PATH,
    CSR_PATH,
    SIGNED_CERT_PATH,
)


class DefWebPKI(object):
    def __init__(self):
        """
        This DefWebPKI class is based on / inspired by the proxy.py pki code
        """
        self.logger = logging.getLogger(__name__)

        if not os.path.exists(CERT_ROOT):
            os.makedirs(CERT_ROOT)

    def remove_passphrase(
        self,
        key_in_path: str,
        key_out_path: str,
        password: str = "DefWeb",
        timeout: int = 10,
    ) -> bool:
        """
        Remove passphrase from a private key.
        """
        command = [
            "openssl",
            "rsa",
            "-passin",
            f"pass:{password}",
            "-in",
            key_in_path,
            "-out",
            key_out_path,
        ]
        return self.run_openssl_command(command, timeout)

    def gen_private_key(
        self,
        key_path: str,
        password: str = "DefWeb",
        bits: int = 2048,
        timeout: int = 10,
    ) -> bool:
        """
        Generates a private key.
        """
        command = [
            "openssl",
            "genrsa",
            "-aes256",
            "-passout",
            f"pass:{password}",
            "-out",
            key_path,
            str(bits),
        ]
        return self.run_openssl_command(command, timeout)

    def gen_public_key(
        self,
        public_key_path: str,
        private_key_path: str,
        subject: str,
        private_key_password: str = "DefWeb",
        alt_subj_names: str = None,
        extended_key_usage: str = None,
        validity_in_days: int = 365,
        timeout: int = 10,
    ) -> bool:
        """
        For a given private key, generates a corresponding public key.
        """
        with self.ssl_config(alt_subj_names, extended_key_usage) as (config_path):
            command = [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-days",
                f"{validity_in_days}",
                "-subj",
                subject,
                "-passin",
                f"pass:{private_key_password}",
                "-config",
                config_path,
                "-key",
                private_key_path,
                "-out",
                public_key_path,
            ]

            return self.run_openssl_command(command, timeout)

    def gen_csr(
        self,
        csr_path: str,
        key_path: str,
        crt_path: str,
        password: str = "DefWeb",
        timeout: int = 10,
    ) -> bool:
        """
        Generates a CSR based upon existing certificate and key file.
        """
        command = [
            "openssl",
            "x509",
            "-x509toreq",
            "-passin",
            f"pass:{password}",
            "-in",
            crt_path,
            "-signkey",
            key_path,
            "-out",
            csr_path,
        ]
        return self.run_openssl_command(command, timeout)

    def sign_csr(
        self,
        csr_path: str,
        crt_path: str,
        ca_key_path: str,
        ca_crt_path: str,
        serial: str,
        ca_key_password: str = "DefWeb",
        alt_subj_names: str = None,
        extended_key_usage: str = None,
        validity_in_days: int = 365,
        timeout: int = 10,
    ) -> bool:
        """
        Sign a CSR using CA key and certificate.
        """
        with self.ext_file(alt_subj_names, extended_key_usage) as extension_path:
            command = [
                "openssl",
                "x509",
                "-req",
                "-sha256",
                "-CA",
                ca_crt_path,
                "-CAkey",
                ca_key_path,
                "-passin",
                f"pass:{ca_key_password}",
                "-set_serial",
                f"{serial}",
                "-days",
                f"{validity_in_days}",
                "-extfile",
                extension_path,
                "-in",
                csr_path,
                "-out",
                crt_path,
            ]
            return self.run_openssl_command(command, timeout)

    def get_ext_config(
        self, alt_subj_names: str = None, extended_key_usage: str = None
    ) -> bytes:
        config = b""
        # Add SAN extension
        if alt_subj_names is not None and len(alt_subj_names) > 0:
            alt_names = []
            for cname in alt_subj_names:
                alt_names.append(f"DNS:{cname}".encode("utf-8"))
            config += b"\nsubjectAltName=" + b",".join(alt_names)
        # Add extendedKeyUsage section
        if extended_key_usage is not None:
            config += f"\nextendedKeyUsage={extended_key_usage}".encode("utf-8")
        return config

    @contextlib.contextmanager
    def ext_file(
        self, alt_subj_names: str = None, extended_key_usage: str = None
    ) -> None:
        # Write config to temp file
        config_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex)
        with open(config_path, "wb") as cnf:
            cnf.write(self.get_ext_config(alt_subj_names, extended_key_usage))

        yield config_path

        # Delete temp file
        os.remove(config_path)

    @contextlib.contextmanager
    def ssl_config(
        self, alt_subj_names: str = None, extended_key_usage: str = None
    ) -> None:
        config = DEFAULT_CONFIG

        # Add custom extensions
        config += self.get_ext_config(alt_subj_names, extended_key_usage)

        # Write config to temp file
        config_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex)
        with open(config_path, "wb") as cnf:
            cnf.write(config)

        yield config_path

        # Delete temp file
        os.remove(config_path)

    def run_openssl_command(self, command: list, timeout: int) -> bool:
        cmd = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=CERT_ROOT
        )
        cmd.communicate(timeout=timeout)
        return cmd.returncode == 0

    def create_https_certs(self) -> bool:

        gen_p_key = self.gen_private_key(KEY_PATH)
        rem_pass = self.remove_passphrase(KEY_PATH, KEY_PATH)
        gen_pub_key = self.gen_public_key(
            CERT_PATH,
            KEY_PATH,
            subject="/C=NL/ST=DefWeb/L=DefWeb/O=DefWeb/OU=DefWeb/CN=127.0.0.1",
        )

        return all([gen_p_key, rem_pass, gen_pub_key])

    def create_ca_certs(self) -> bool:

        gen_p_key = self.gen_private_key(CA_KEY_PATH)
        rem_pass = self.remove_passphrase(CA_KEY_PATH, CA_KEY_PATH)
        gen_pub_key = self.gen_public_key(
            CA_CERT_PATH,
            CA_KEY_PATH,
            subject="/C=NL/ST=DefWeb_CA/L=DefWeb_CA/O=DefWeb_CA/OU=DefWeb_CA/CN=127.0.0.1",
        )

        gen_sign_key = self.gen_private_key(CA_SIGNING_KEY_PATH)
        rem_sign_pass = self.remove_passphrase(CA_SIGNING_KEY_PATH, CA_SIGNING_KEY_PATH)

        return all([gen_p_key, rem_pass, gen_pub_key, gen_sign_key, rem_sign_pass])

    def sign_https_certs(self) -> bool:

        gen_csr = self.gen_csr(CSR_PATH, KEY_PATH, CERT_PATH)
        sign_csr = self.sign_csr(
            CSR_PATH, SIGNED_CERT_PATH, CA_KEY_PATH, CA_CERT_PATH, f"{int(time.time())}"
        )

        return all([gen_csr, sign_csr])


# if __name__ == "__main__":
#     available_actions = (
#         "remove_passphrase",
#         "gen_private_key",
#         "gen_public_key",
#         "gen_csr",
#         "sign_csr",
#     )
#
#     parser = argparse.ArgumentParser()
#
#     parser.add_argument(
#         "action",
#         type=str,
#         default=None,
#         help="Valid actions: " + ", ".join(available_actions),
#     )
#     parser.add_argument(
#         "--password",
#         type=str,
#         default="proxy.py",
#         help="Password to use for encryption. Default: proxy.py",
#     )
#     parser.add_argument(
#         "--private-key-path", type=str, default=None, help="Private key path"
#     )
#     parser.add_argument(
#         "--public-key-path", type=str, default=None, help="Public key path"
#     )
#     parser.add_argument(
#         "--subject",
#         type=str,
#         default="/CN=localhost",
#         help="Subject to use for public key generation. Default: /CN=localhost",
#     )
#     parser.add_argument(
#         "--csr-path",
#         type=str,
#         default=None,
#         help="CSR file path.  Use with gen_csr and sign_csr action.",
#     )
#     parser.add_argument(
#         "--crt-path",
#         type=str,
#         default=None,
#         help="Signed certificate path.  Use with sign_csr action.",
#     )
#     parser.add_argument(
#         "--hostname",
#         type=str,
#         default=None,
#         help="Alternative subject names to use during CSR signing.",
#     )
#     args = parser.parse_args(sys.argv[1:])
#
#     # Validation
#     if args.action not in available_actions:
#         logger.error("Invalid --action. Valid values " + ", ".join(available_actions))
#         sys.exit(1)
#     if (
#         args.action in ("gen_private_key", "gen_public_key")
#         and args.private_key_path is None
#     ):
#         logger.error("--private-key-path is required for " + args.action)
#         sys.exit(1)
#     if args.action == "gen_public_key" and args.public_key_path is None:
#         logger.error("--public-key-file is required for private key generation")
#         sys.exit(1)
#
#     # Execute
#     if args.action == "gen_private_key":
#         gen_private_key(args.private_key_path, args.password)
#     elif args.action == "gen_public_key":
#         gen_public_key(
#             args.public_key_path, args.private_key_path, args.password, args.subject
#         )
#     elif args.action == "remove_passphrase":
#         remove_passphrase(args.private_key_path, args.password, args.private_key_path)
#     elif args.action == "gen_csr":
#         gen_csr(
#             args.csr_path, args.private_key_path, args.password, args.public_key_path
#         )
#     elif args.action == "sign_csr":
#         sign_csr(
#             args.csr_path,
#             args.crt_path,
#             args.private_key_path,
#             args.password,
#             args.public_key_path,
#             str(int(time.time())),
#             alt_subj_names=[args.hostname],
#         )
