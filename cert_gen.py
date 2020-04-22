#!/usr/bin/env python

import subprocess
import os
import logging as log
import inquirer
import copy
import glob


from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support import expected_conditions as EC

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
            print("Name {} invalid. Must begin with 'DNS:' or 'IP:'".format(s))
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


def submit_all_csrs_to_microsoft_ca(csr_dir):
    """
    Looks for all CSR files under `csr_dir` recursively and submits a Certificate
    Signing Request to a Microsoft CA for each CSR found
    """

    # This submits the CSR to the CA for the environment. The CA signing the
    # private keys created above so people know we are who we say we are
    # questions = [
    #   inquirer.Text('fqdn', message="CA Server FQDN"),
    #   inquirer.Text('username', message="Domain Admin Username"),
    #   inquirer.Text('password', message="Domain Admin Password"),
    # ]
    # srv_info = inquirer.prompt(questions)
    srv_info = {
        "fqdn": "ca1.messier.local",
        "username": "kwr_admin",
        "password": "W0rldc0m2018",
    }
    # ca_srvr = certsrv.Certsrv(srv_info["fqdn"], srv_info["username"],
    #         srv_info["password"])
    csr_files = glob.glob(os.path.join(csr_dir, "**", "*.csr"))
    print("csr_files = {}".format(csr_files))
    download_dir = os.path.abspath(os.path.split(csr_files[0])[0])
    ca_srvr = MicrosoftCA(
        srv_info["fqdn"],
        srv_info["username"],
        srv_info["password"],
        download_dir=download_dir,
    )
    # for csr in csr_files:
    #     cert = ca_srvr.get_cert(csr, "Administrator")
    #     print(cert)
    for csr_file in csr_files:
        # Download the certs from CA page
        with open(csr_file, "r") as f:
            cert_contents = f.read()
        ca_srvr.navigate_to_homepage()
        ca_srvr.navigate_to_cert_sign_page_from_homepage()
        ca_srvr.fill_out_signing_page_and_download(cert_contents, "Web Server")
        # wait to finish downloading before moving
        time.sleep(2)
        # Rename downloaded certs
        csr_file_name_with_ext = os.path.split(csr_file)[-1]
        csr_file_name = os.path.splitext(csr_file_name_with_ext)[0]
        signed_cert_download_path = os.path.join(download_dir, "certnew.cer")
        cert_chain_download_path = os.path.join(download_dir, "certnew.p7b")
        signed_cert_new_name = os.path.join(download_dir, f"{csr_file_name}_signed_cert.cer")
        cert_chain_new_name = os.path.join(download_dir, f"{csr_file_name}_cert_chain.p7b")
        shutil.move(signed_cert_download_path, signed_cert_new_name)
        shutil.move(cert_chain_download_path, cert_chain_new_name)
    ca_srvr.browser.quit()

def generate_self_signed_certs(csr_dir):
    """
    """
    csr_files = glob.glob(os.path.join(csr_dir, '**', '*.csr'))
    print("csr_files = {}".format(csr_files))
    for csr in csr_files:
        name, ext = os.path.splitext(csr)
        certfile = name + ".cert"
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
    # questions = [
    #   inquirer.Text('countryName', message="countryName", validate=validate_countryname),
    #   inquirer.Text('stateOrProvinceName', message="stateOrProvinceName"),
    #   inquirer.Text('localityName', message="localityName"),
    #   inquirer.Text('organizationName', message="organizationName"),
    #   inquirer.Text('organizationalUnitName', message="organizationalUnitName"),
    #   # inquirer.Text('commonName', message="commonName"),
    # ]
    # answers["sslconfig"] = inquirer.prompt(questions)
    answers["sslconfig"] = {"countryName": "US",
                            "stateOrProvinceName": "NH",
                            "localityName": "Salem",
                            "organizationName": "WEI",
                            "organizationalUnitName": "Eng"}
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
                names = ("IaaS-Web", "IaaS-Manager", "VCAC")
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
                   "Microsoft CA": submit_all_csrs_to_microsoft_ca}
    func_lookup[answers['ca']](os.path.abspath("certs"))
    # submit_all_csrs_in_dir(os.path.abspath("certs"))
    

if __name__ == "__main__":
    main()
