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

from certgen.cert_authorities.microsoft_ca import MicrosoftCA
from certgen.cert_authorities.self_signed import generate_self_signed_certs_from_dir
from certgen.utils import generate_new_csr_and_key, convert_cert_chain_to_base64_pem


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


def submit_all_csrs_to_microsoft_ca(csr_dir, config):
    """
    Looks for all CSR files under `csr_dir` recursively and submits a Certificate
    Signing Request to a Microsoft CA for each CSR found
    """

    info = config["DEFAULT"]

    assert "microsoft_ca_address" in info
    assert "microsoft_ca_username" in info
    assert "microsoft_ca_password" in info
    assert "microsoft_ca_template_name" in info
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
        ca_srvr.fill_out_signing_page_and_download(cert_contents, info["microsoft_ca_template_name"])
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
        convert_cert_chain_to_base64_pem(cert_chain_new_name)
    ca_srvr.browser.quit()


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
            inquirer.Text(
                "microsoft_ca_address", message="Enter Microsoft CA IP or FQDN"
            ),
            inquirer.Text(
                "microsoft_ca_username", message="Enter Microsoft CA username"
            ),
            inquirer.Text(
                "microsoft_ca_password", message="Enter Microsoft CA password"
            ),
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
        description=("Automated cert generator for various VMWare products. Accepts INI "
                     "file or prompts user for inputs")
    )
    parser.add_argument(
        "--print-solns", action="store_true", help="Print supported solutions"
    )
    parser.add_argument("--print-template", action="store_true", help="Print template config file")
    parser.add_argument("file", nargs="?", help="Config file in INI format with inputs")
    args = parser.parse_args()

    if args.print_solns:
        print("Supported solutions:")
        for soln in map_soln_to_csr_names.keys():
            print(f" - {soln}")
        quit()

    if args.print_template:
        template_path = os.path.join(os.path.dirname(__file__), "data", "config_template.ini")
        with open(template_path, "r") as f:
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
        "self_signed": generate_self_signed_certs_from_dir,
        "microsoft_ca": submit_all_csrs_to_microsoft_ca,
    }
    ca = config["DEFAULT"]["ca"]
    if ca not in func_lookup:
        raise ValueError(f"Unsupported CA {ca}")
    func_lookup[ca](os.path.abspath("certs"), config)
