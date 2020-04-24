import subprocess
import os

def run_subprocess_with_output(cmd):
    print("Running command: {}".format(cmd))
    try:
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        print("FAILED COMMAND: {}".format(e.cmd))
        print("COMMAND OUTPUT: {}".format(e.output))
        print("COMMAND STDOUT: {}".format(e.stdout))
        print("COMMAND STDERR: {}".format(e.stderr))
        raise
    print("Command output: {}".format(output))
    return output


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
    run_subprocess_with_output(cmd)
    # Decrypt the private key
    cmd = "openssl rsa -in {key_path} -out {out_path}"
    cmd = cmd.format(key_path=key_path, out_path=key_path[0 : key_path.rfind(".")])
    subprocess.check_output(cmd, shell=True)
    return csr_path, key_path

def convert_cert_chain_to_base64_pem(infile, outfile=""):
    """
    Converts the Certificate Chain contained in `infile` to the standard Base 64
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
    run_subprocess_with_output(cmd)
    return outfile
