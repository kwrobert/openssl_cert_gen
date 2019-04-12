import subprocess
import os
import logging as log
import inquirer
import copy

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
    output = subprocess.check_output(cmd, shell=True)
    print("output = {}".format(output))
    # Decrypt the private key
    cmd = "openssl rsa -in {key_path} -out {out_path}"
    cmd = cmd.format(key_path=key_path, out_path=key_path[0:key_path.rfind(".")])
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
      inquirer.Text('countryName', message="countryName"),
      inquirer.Text('stateOrProvinceName', message="stateOrProvinceName"),
      inquirer.Text('localityName', message="localityName"),
      inquirer.Text('organizationName', message="organizationName"),
      inquirer.Text('organizationalUnitName', message="organizationalUnitName"),
      # inquirer.Text('commonName', message="commonName"),
    ]
    answers["sslconfig"] = inquirer.prompt(questions)
    print("answers = {}".format(answers))
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

if __name__ == "__main__":
    main()
