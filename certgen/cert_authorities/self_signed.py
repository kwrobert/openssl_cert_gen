import os
import glob

from certgen.utils import run_subprocess_with_output


def generate_self_signed_cert_from_path(csr_path, valid_days=1001):
    """
    Generate a self-signed certificate and private key given a path to a certificate
    signing request file

    Parameters
    ----------

    csr_path : str 
        Path to Certificate Signing Request file in base64 encoded PEM format
    valid_days : int 
        Number of days signed certificate will be valid for.

    Returns
    -------
    
    None

    Raises
    ------

    subprocess.CalledProcessError : If the call to openssl fails
    """
    name, ext = os.path.splitext(csr_path)
    certfile = name + ".cert"
    keyfile = name + ".key"
    print(
        "CSR File: {}\nCert File: {}\nPrivate Key: {}".format(
            csr_path, certfile, keyfile
        )
    )
    cmd = "openssl x509 -in {} -out {} -req -signkey {} -days {}".format(
        csr_path, certfile, keyfile, valid_days
    )
    run_subprocess_with_output(cmd)
    print("Self signed cert {} created successfully".format(certfile))


def generate_self_signed_certs_from_dir(csr_dir, valid_days=1001):
    """
    generate_self_signed_certs_from_dir

    Parameters
    ----------

    csr_dir : str
        Path to a directory containing CSR files
    valid_days : 
        Number of days signed certificates will be valid for.

    Returns
    -------

    None

    Raises
    ------

    subprocess.CalledProcessError : If the call to openssl fails
    """

    csr_files = glob.glob(os.path.join(csr_dir, "**", "*.csr"))
    print("Found following csr_files = {}".format(csr_files))
    for csr in csr_files:
        generate_self_signed_cert_from_path(csr, valid_days=valid_days)
