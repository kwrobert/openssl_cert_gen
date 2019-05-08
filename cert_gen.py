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


    def __init__(self, fqdn, user, passwd):
        opts = Options()
        # opts.set_headless()
        # assert opts.headless
        self.browser = Chrome(options=opts)
        self.wait = WebDriverWait(self.browser, 100)
        self.URL = "https://{}:{}@{}/certsrv".format(user, passwd, fqdn)
        self.browser.get(self.URL)

    def open_time_entry_sheet(self):
        """
        Open the time entry sheet for the first time, starting from the homepage
        """
        # TODO: Validate we are at the homepage before attempting this
        self.wait.until(EC.element_to_be_clickable((By.ID, "openTimeEntry")))
        button = self.browser.find_element_by_id("openTimeEntry")
        result = button.click()
        print(result)

    def _check_so_list(self, so_num):
        """
        Check the SO drop down on the time entry page for the given SO number
        """
        print("so_num = {}".format(so_num))
        # self.wait.until(EC.element_to_be_clickable((By.NAME, "select-so")))
        # sel_el = self.browser.find_element_by_name("select-so")
        # print(sel_el)
        # print("sel_el.text = {}".format(sel_el.text))
        # actions = ActionChains(self.browser)
        # actions.pause(2)
        # actions.move_to_element_with_offset(sel_el, 2, 2)
        # actions.pause(2)
        # actions.click(sel_el)
        # result = actions.perform()
        # select_obj = Select(sel_el)
        # print(select_obj.options)

        div = self.browser.find_element_by_name("cont_with_so")
        print("div = {}".format(div))


        # element = self.browser.find_element_by_xpath("//select[@name='select-so']")
        # print("element = {}".format(element))
        # all_options = element.find_elements_by_tag_name("option")
        # print("all_options = {}".format(all_options))
        # for option in all_options:
        #     print("Value is: %s" % option.get_attribute("value"))
            # option.click()
        # el.click()
        # options = el.find_elements_by_tag_name("option")
        # print(options)

        import pdb
        pdb.set_trace()  # XXX BREAKPOINT

    def _toggle_form(self):
        # self.wait.until(EC.element_to_be_clickable((By.ID, "control_connect2")))
        # el = self.browser.find_element_by_id("control_connect2")
        el = self.browser.find_element_by_css_selector(
            "input#control_connect2.widget-switch.checkbox-sw.checkbox"
        )
        print(el)
        print(el.get_attribute("name"))
        actions = ActionChains(self.browser)
        actions.move_to_element(el)
        actions.click(el)
        result = actions.perform()
        print("result = {}".format(result))

    def create_entry(self, event):
        # First check if the SO is in the SO dropdown list. This determines whether or
        # not we continue with the default form or use a "custom" form
        # self._toggle_form()
        if self._check_so_list(event.so_number):
            print("Use default form!")
        else:
            print("Use custom form!")

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


def submit_all_csrs_to_microsoft_ca(csr_dir):
    """
    Looks for all CSR files under `csr_dir` recursively and submits a Certificate
    Signing Request to a Microsoft CA
    """

    # This submits the CSR to the CA for the environment. The CA signing the
    # private keys created above so people know we are who we say we are
    # questions = [
    #   inquirer.Text('fqdn', message="CA Server FQDN"),
    #   inquirer.Text('username', message="Domain Admin Username"),
    #   inquirer.Text('password', message="Domain Admin Password"),
    # ]
    # srv_info = inquirer.prompt(questions)
    srv_info = {"fqdn": "ca2.vcloud.wei", "username": "kr", "password": "Worldcom1"}
    # ca_srvr = certsrv.Certsrv(srv_info["fqdn"], srv_info["username"],
    #         srv_info["password"])
    ca_srvr = MicrosoftCA(srv_info['fqdn'], srv_info["username"], srv_info["password"])
    input("Continue?")
    csr_files = glob.glob(os.path.join(csr_dir, '**', '*.csr'))
    print("csr_files = {}".format(csr_files))
    # for csr in csr_files:
    #     cert = ca_srvr.get_cert(csr, "Administrator")
    #     print(cert)

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
                   "Microsoft CA": submit_all_csrs_to_microsoft_ca}
    func_lookup[answers['ca']](os.path.abspath("certs"))
    # submit_all_csrs_in_dir(os.path.abspath("certs"))
    

if __name__ == "__main__":
    main()
