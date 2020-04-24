#!/usr/bin/env python

import subprocess
import os
import logging as log
import inquirer
import copy
import glob
import time
import shutil
import configparser
import sys

import argparse as ap

from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions as EC

map_soln_to_csr_names = {
    "vRealize_Automation_Medium_Distributed": [
        "IaaS-Web",
        "IaaS-Manager",
        "Appliances",
    ],
    "vRealize_Automation_Small": ["IaaS", "Appliances"],
    "vRealize_Business": ["vBusiness"],
    "vRealize_Operations": ["vROPS"],
}


conf_template = """
[ req ]
default_bits = 2048
default_keyfile = {solution_name}.key
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

class MicrosoftCA:
    def __init__(self, fqdn, user, passwd, download_dir=None):
        opts = Options()
        if download_dir is not None:
            print(f"Changing download dir to {download_dir}!")
            prefs = {"download.default_directory": download_dir}
            opts.add_experimental_option("prefs", prefs)
        # opts.set_headless()
        # assert opts.headless
        self.browser = Chrome(options=opts)
        self.wait = WebDriverWait(self.browser, 100)
        self.URL = "https://{}:{}@{}/certsrv".format(user, passwd, fqdn)

    def navigate_to_homepage(self):
        self.browser.get(self.URL)

    def navigate_to_cert_sign_page_from_homepage(self):
        self.browser.find_element_by_link_text("Request a certificate").click()
        self.browser.find_element_by_link_text("advanced certificate request").click()

    def fill_out_signing_page_and_download(self, cert_contents, cert_template):
        """
        Fills out cert signing page and downloads signed cert and cert chain
        """

        print("Fill out page")
        # Fill out text area with cert contents
        text_area = self.browser.find_element_by_id("locTaRequest")
        text_area.send_keys(cert_contents)
        # Select the cert tempalte
        template_select = Select(self.browser.find_element_by_id("lbCertTemplateID"))
        for opt in template_select.options:
            if opt.text == cert_template:
                opt.click()
                break
        else:
            raise RuntimeError(f"Not certificate templates named {cert_template}")
        self.browser.find_element_by_id("btnSubmit").click()
        # Select base 64 encoded and download
        self.browser.find_element_by_id("rbB64Enc").click()
        self.browser.find_element_by_link_text("Download certificate").click()
        self.browser.find_element_by_link_text("Download certificate chain").click()


# log.basicConfig(filename='cert_gen.log',level=log.DEBUG)



def validate_subjaltname(answers, current):
    valid = True
    for s in current.split(","):
        if not (s[0:4] == "DNS:" or s[0:3] == "IP:"):
            print("\nName {} invalid. Must begin with 'DNS:' or 'IP:'".format(s))
            valid = False
            break
    return valid


def validate_countryname(answers, current):
    valid = True
    if len(current) > 2:
        print("Country name must be only 2 characters long")
        valid = False
    return valid


def generate_new_csr_and_key(outdir, name, config):
    """
    Generate a new certificate configuration and certificate in `outdir` using `name`
    for the name of all files without the extension
    """

    print("Generating csr and key {}".format(name))
    # Write the config file
    conf_path = os.path.join(outdir, name + ".cfg")
    key_path = os.path.join(outdir, name + ".key.encrypted")
    csr_path = os.path.join(outdir, name + ".csr")
    with open(conf_path, "w") as f:
        f.write(conf_template.format(solution_name=name, **config))
    # Make the keys
    cmd = (
        "openssl req -new -nodes -out {csr_path} -keyout {key_path} -config "
        "{conf_path}"
    )
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
    cmd = cmd.format(key_path=key_path, out_path=key_path[0 : key_path.rfind(".")])
    subprocess.check_output(cmd, shell=True)


def convert_ca_cert_chain_to_base64_pem(infile, outfile=""):
    """
    Converts the CA Certificate Chain contained in `infile` to the standard Base 64
    encoded X.509 format
    """

    infile_path, infile_ext = os.path.splitext(infile)
    if not outfile:
        outfile = infile_path + "_pem_cert_chain.cer"
    # Maps infile extensions to the command required to convert them to PEM format. This
    # isn't fool proof because users can put any extension they want on a file, but that
    # doesn't mean it's actually in that format
    # TODO: Find a way to identify format of infile from its contents
    cmds = {"p7b": "openssl pkcs7 -print_certs -in {infile} -out {outfile}"}
    try:
        cmd = cmds[infile_ext.strip(".")]
    except KeyError as e:
        e.args = ("Cannot convert CA Cert chain from {} format".format(infile_ext),)
        raise
    cmd = cmd.format(infile=infile, outfile=outfile)
    subprocess.check_output(cmd, shell=True)
    return outfile


def submit_all_csrs_to_microsoft_ca(csr_dir, config):
    """
    Looks for all CSR files under `csr_dir` recursively and submits a Certificate
    Signing Request to a Microsoft CA for each CSR found
    """

    info = config["DEFAULT"]

    assert "microsoft_ca_address" in info
    assert "microsoft_ca_username" in info
    assert "microsoft_ca_password" in info
    print("info = {}".format(dict(info)))

    # This submits the CSR to the CA for the environment. The CA signing the
    # private keys created above so people know we are who we say we are
    csr_files = glob.glob(os.path.join(csr_dir, "**", "*.csr"))
    print("csr_files = {}".format(csr_files))
    ca_srvr = MicrosoftCA(
        info["microsoft_ca_address"],
        info["microsoft_ca_username"],
        info["microsoft_ca_password"],
        download_dir=csr_dir,
    )
    for csr_file in csr_files:
        # Download the certs from CA page
        with open(csr_file, "r") as f:
            cert_contents = f.read()
        ca_srvr.navigate_to_homepage()
        ca_srvr.navigate_to_cert_sign_page_from_homepage()
        ca_srvr.fill_out_signing_page_and_download(cert_contents, "Web Server")
        # wait to finish downloading before moving
        time.sleep(3)
        # Rename downloaded certs
        existing_certs = glob.glob(os.path.join(csr_dir, "**", "*certnew*"))
        for old_cert in existing_certs:
            print(f"Removing existing cert {old_cert}")
            os.remove(old_cert)
        csr_file_path, csr_file_name_with_ext = os.path.split(csr_file)
        csr_file_name = os.path.splitext(csr_file_name_with_ext)[0]
        signed_cert_download_path = os.path.join(csr_dir, "certnew.cer")
        cert_chain_download_path = os.path.join(csr_dir, "certnew.p7b")
        signed_cert_new_name = os.path.join(
            csr_file_path, f"{csr_file_name}_signed_cert.cer"
        )
        cert_chain_new_name = os.path.join(
            csr_file_path, f"{csr_file_name}_cert_chain.p7b"
        )
        shutil.move(signed_cert_download_path, signed_cert_new_name)
        shutil.move(cert_chain_download_path, cert_chain_new_name)
        # Finally, convert the PKCS #7 cert chain provided by Microsoft CAs to PEM
        # format
        convert_ca_cert_chain_to_base64_pem(cert_chain_new_name)
    ca_srvr.browser.quit()
    return


def generate_self_signed_certs(csr_dir, config):
    """
    """
    csr_files = glob.glob(os.path.join(csr_dir, "**", "*.csr"))
    print("csr_files = {}".format(csr_files))
    for csr in csr_files:
        name, ext = os.path.splitext(csr)
        certfile = name + ".cert"
        keyfile = name + ".key"
        cmd = "openssl x509 -in {} -out {} -req -signkey {} -days 1001".format(
            csr, certfile, keyfile
        )
        subprocess.check_output(cmd, shell=True)


def prompt_user_for_inputs():
    config = {}
    # Get common cert config
    print("Enter configuration common to all certs below:")
    questions = [
        inquirer.Text(
            "countryName", message="countryName", validate=validate_countryname
        ),
        inquirer.Text("stateOrProvinceName", message="stateOrProvinceName"),
        inquirer.Text("localityName", message="localityName"),
        inquirer.Text("organizationName", message="organizationName"),
        inquirer.Text("organizationalUnitName", message="organizationalUnitName"),
    ]
    config["DEFAULT"].update(inquirer.prompt(questions))
    # Get certificate authority
    questions = [
        inquirer.List(
            "ca",
            message="What kind of certificate authority are you using?",
            choices=["self_signed", "microsoft_ca"],
        )
    ]
    answers = inquirer.prompt(questions)
    config["DEFAULT"]["ca"] = answers["ca"]
    if answers["ca"] == "microsoft_ca":
        questions = [
            inquirer.Text("microsoft_ca_address", message="Enter Microsoft CA IP or FQDN"),
            inquirer.Text("microsoft_ca_username", message="Enter Microsoft CA username"),
            inquirer.Text("microsoft_ca_password", message="Enter Microsoft CA password"),
        ]
        answers = inquirer.prompt(questions)
        config["DEFAULT"].update(answers)
    # Collect solutions and get their config
    questions = [
        inquirer.Checkbox(
            "solns",
            message="What solutions are you deploying (select multiple with spacebar)?",
            choices=list(map_soln_to_csr_names.keys()),
        )
    ]
    answers = inquirer.prompt(questions)
    for soln in answers["solns"]:
        config[soln] = {}
        for csr_name in map_soln_to_csr_names[soln]:
            questions = [
                inquirer.Text(
                    f"{csr_name}_commonName", message=f"Enter {csr_name} common name"
                ),
                inquirer.Text(
                    f"{csr_name}_SubjectAlternateName",
                    message=f"Enter {csr_name} subject alternate name(s) (can be a csv)",
                    validate=validate_subjaltname,
                ),
            ]
            answers = inquirer.prompt(questions)
            config[soln].update(answers)
    return config


def certgen():

    parser = ap.ArgumentParser(
        description="Automated cert generator for various VMWare products"
    )
    parser.add_argument(
        "--print-solns", action="store_true", help="Print supported solutions"
    )
    parser.add_argument("--print-template", nargs=1, help="Print template config file")
    parser.add_argument("file", nargs="?", help="Config file with necessary inputs")
    args = parser.parse_args()

    if args.print_solns:
        print("Supported solutions:")
        for soln in map_soln_to_csr_names.keys():
            print(f" - {soln}")
        quit()

    if args.print_template:
        with open("config_template.ini", "r") as f:
            print(f.read())
        quit()

    if args.file is None:
        config = prompt_user_for_inputs()
    else:
        if not os.path.exists(args.file):
            raise ValueError(f"Path {args.file} does not exist")
        if not os.path.isfile(args.file):
            raise ValueError(f"Path {args.file} not a regular file")
        config = configparser.ConfigParser(delimiters=("=",))
        config.read(args.file)
        config = dict(config)

    print(args)
    print("config = {}".format(config))

    # This generates all the Certificate Signing Requests (.csr files) and the private
    # keys.
    common_conf_keys = (
        "countryName",
        "stateOrProvinceName",
        "localityName",
        "organizationName",
        "organizationalUnitName",
    )
    common_conf = {k: config["DEFAULT"][k] for k in common_conf_keys}
    for soln in config.keys():
        if soln == "DEFAULT":
            continue
        print("soln = {}".format(soln))
        out = os.path.join("certs", soln)
        print("out = {}".format(out))
        if not os.path.isdir(out):
            os.makedirs(out)
        print(f"Generating certificate signing requests for {soln}")
        for name in map_soln_to_csr_names[soln]:
            soln_info = config[soln]
            csr_conf = copy.copy(common_conf)
            common_name_key = f"{name.lower()}_commonname"
            san_key = f"{name.lower()}_subjectalternatename"
            # Must add the common name to the list of subject alternate names
            san_str = "DNS:" + soln_info[common_name_key] + "," + soln_info[san_key]
            csr_conf["subjectAltName"] = san_str 
            csr_conf["commonName"] = soln_info[common_name_key]
            print("csr_conf = {}".format(csr_conf))
            generate_new_csr_and_key(out, name, csr_conf)

    print("BEGINNING SIGNING PROCESS ...")
    func_lookup = {
        "self_signed": generate_self_signed_certs,
        "microsoft_ca": submit_all_csrs_to_microsoft_ca,
    }
    ca = config["DEFAULT"]["ca"]
    if ca not in func_lookup:
        raise ValueError(f"Unsupported CA {ca}")
    func_lookup[ca](os.path.abspath("certs"), config)
