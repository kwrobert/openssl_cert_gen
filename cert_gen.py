#!/usr/bin/env python

import subprocess
import os
import logging as log
import inquirer
import copy
import glob
import certsrv
import warnings
import contextlib

import requests
from urllib3.exceptions import InsecureRequestWarning


old_merge_environment_settings = requests.Session.merge_environment_settings

@contextlib.contextmanager
def no_ssl_verification():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass

# log.basicConfig(filename='cert_gen.log',level=log.DEBUG)

conf_template = \
"""
[ req ]
default_bits = 2048
default_keyfile = solution_name.key
distinguished_name = req_distinguished_name
encrypt_key = no
prompt = no
string_mask = nombstr
req_extensions = v3_req
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment, nonRepudiation
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = {subjectAltName}
[ req_distinguished_name ]
countryName = {countryName}
stateOrProvinceName = {stateOrProvinceName}
localityName = {localityName}
0.organizationName = {organizationName}
organizationalUnitName = {organizationalUnitName}
commonName = {commonName}
"""

def validate_subjaltname(answers, current):
    valid = True
    for s in current.split(","):
        if not (s[0:4] == "DNS:" or s[0:3] == "IP:"):
            print("Name {} invalid. Must begin with 'DNS:' or 'IP:'")
            valid = False
            break
    return valid 

def validate_countryname(answers, current):
    valid = True
    if len(current) > 2:
        print("Country name must be only 2 characters long")
        valid = False
    return valid


def generate_new_cert(outdir, name, common_conf):
    """
    Generate a new certificate configuration and certificate in `outdir` using `name`
    for the name of all files without the extension
    """

    print("Generating cert {}".format(name))
    conf = copy.copy(common_conf)
    questions = [
      inquirer.Text('commonName', message="commonName"),
      inquirer.Text('subjectAltName', message="subjectAltName (can be a csv)",
          validate=validate_subjaltname),
    ]
    conf.update(inquirer.prompt(questions))
    print("conf = {}".format(conf))
    # Write the config file
    conf_path = os.path.join(outdir, name+".cfg")
    key_path = os.path.join(outdir, name+".key.encrypted")
    csr_path = os.path.join(outdir, name+".csr")
    with open(conf_path, 'w') as f:
        f.write(conf_template.format(**conf))
    # Make the keys
    cmd = ("openssl req -new -nodes -out {csr_path} -keyout {key_path} -config "
          "{conf_path}")
    cmd = cmd.format(key_path=key_path, csr_path=csr_path, conf_path=conf_path)
    print("cmd = {}".format(cmd))
    try:
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        print("FAILED COMMAND: {}".format(e.cmd))
        print("COMMAND OUTPUT: {}".format(e.output))
        print("COMMAND STDOUT: {}".format(e.stdout))
        print("COMMAND STDERR: {}".format(e.stderr))
        raise
    print("output = {}".format(output))
    # Decrypt the private key
    cmd = "openssl rsa -in {key_path} -out {out_path}"
    cmd = cmd.format(key_path=key_path, out_path=key_path[0:key_path.rfind(".")])
    subprocess.check_output(cmd, shell=True)


def convert_ca_cert_chain_to_base64_pem(infile, outfile=''):
    """
    Converts the CA Certificate Chain contained in `infile` to the standard Base 64
    encoded X.509 format
    """

    infile_path, infile_ext =  os.path.splitext(infile)
    if not outfile:
        outfile = infile_path + ".cer"
    # Maps infile extensions to the command required to convert them to PEM format. This
    # isn't fool proof because users can put any extension they want on a file, but that
    # doesn't mean it's actually in that format
    # TODO: Find a way to identify format of infile from its contents
    cmds = {"p7b": "openssl pkcs7 -print_certs -in {infile} -out {outfile}"} 
    try:
        cmd = cmds[infile_ext]
    except KeyError as e:
        e.args = ("Cannot convert CA Cert chain from {} format".format(infile_ext),)
        raise
    cmd = cmd.format(infile=infile, outfile=outfile)
    subprocess.check_output(cmd, shell=True)
    return outfile


def submit_all_csrs_in_dir(csr_dir):
    """
    Looks for all CSR files under `csr_dir` recursively and submits a Certificate
    Signing Request to a Microsoft CA
    """

    # This submits the CSR to the CA for the environment. The CA signing the
    # private keys created above so people know we are who we say we are
    srv_info = {"fqdn": "ca2.vcloud.wei", "username": "kr", "password": "Worldcom1"}
    ca_srvr = certsrv.Certsrv(srv_info["fqdn"], srv_info["username"],
            srv_info["password"])
    csr_files = glob.glob(os.path.join(csr_dir, '**', '*.csr'))
    print("csr_files = {}".format(csr_files))
    with no_ssl_verification():
        for csr in csr_files:
            cert = ca_srvr.get_cert(csr, "Administrator")
            print(cert)

def generate_self_signed_certs(csr_dir):
    """
    """
    csr_files = glob.glob(os.path.join(csr_dir, '**', '*.csr'))
    print("csr_files = {}".format(csr_files))
    for csr in csr_files:
        name, ext = os.path.splitext(csr)
        certfile = name + ".pem"
        keyfile = name + ".key"
        cmd = "openssl x509 -in {} -out {} -req -signkey {} -days 1001".format(csr, certfile, keyfile)
        subprocess.check_output(cmd, shell=True)

def main():

    questions = [
      inquirer.Checkbox('solns',
                        message="What are you interested in?",
                        choices=['vRealize Automation',
                                 'vRealize Automation Distributed',
                                 'vRealize Business',
                                 'vRealize Operations'],
                        ),
    ]
    answers = inquirer.prompt(questions)
    answers['solns'] = [el.replace(" ", "_") for el in answers['solns']]

    print("Enter configurations common to all certs below:")
    questions = [
      inquirer.Text('countryName', message="countryName", validate=validate_countryname),
      inquirer.Text('stateOrProvinceName', message="stateOrProvinceName"),
      inquirer.Text('localityName', message="localityName"),
      inquirer.Text('organizationName', message="organizationName"),
      inquirer.Text('organizationalUnitName', message="organizationalUnitName"),
      # inquirer.Text('commonName', message="commonName"),
    ]
    answers["sslconfig"] = inquirer.prompt(questions)
    print("answers = {}".format(answers))
    # This generates all the Certificate Signing Requests (.csr files) and the private
    # keys.
    for soln in answers['solns']:
        out = os.path.join("certs", soln)
        print("out = {}".format(out))
        if not os.path.isdir(out):
            os.makedirs(out)
        if "vRealize_Automation" in soln:
            print("Generating vRealize Automation Certs ...")
            distrib = False
            if "Distributed" in soln:
                names = ("IaaS", "IaaS-Manager", "VCAC")
            else:
                names = ("IaaS", "VCAC")
            for name in names:
                generate_new_cert(out, name, answers["sslconfig"])

    # questions = [
    #   inquirer.Text('fqdn', message="CA Server FQDN"),
    #   inquirer.Text('username', message="Domain Admin Username"),
    #   inquirer.Text('password', message="Domain Admin Password"),
    # ]
    # srv_info = inquirer.prompt(questions)

    questions = [
        inquirer.List('ca',
                      message="What kind of certificate authority are you using?",
                      choices=['Self Signed', 'Microsoft CA'],
                  ),
    ]

    answers = inquirer.prompt(questions)
    func_lookup = {"Self Signed": generate_self_signed_certs,
                   "Microsoft CA": submit_all_csrs_in_dir}
    func_lookup[answers['ca']](os.path.abspath("certs"))
    # submit_all_csrs_in_dir(os.path.abspath("certs"))
    

if __name__ == "__main__":
    main()
