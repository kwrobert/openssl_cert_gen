import os
import shutil
import glob
import time
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


def submit_all_csrs_to_microsoft_ca(csr_dir):
    """
    Looks for all CSR files under `csr_dir` recursively and submits a Certificate
    Signing Request to a Microsoft CA
    """

    # This submits the CSR to the CA for the environment. The CA signing the
    # private keys created above so people know we are who we say we are
    questions = [
      inquirer.Text('fqdn', message="CA Server FQDN"),
      inquirer.Text('username', message="Domain Admin Username"),
      inquirer.Text('password', message="Domain Admin Password"),
    ]
    srv_info = inquirer.prompt(questions)
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


submit_all_csrs_to_microsoft_ca("./certs")
