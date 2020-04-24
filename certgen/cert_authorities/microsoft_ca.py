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
        print(opts)
        print("opening browser")
        self.browser = Chrome(options=opts)
        self.wait = WebDriverWait(self.browser, 100)
        self.URL = "https://{}:{}@{}/certsrv".format(user, passwd, fqdn)
        print("browser open")

    def navigate_to_homepage(self):
        print("navigate to homepage")
        self.browser.get(self.URL)
        print("homepage open")

    def navigate_to_cert_sign_page_from_homepage(self):
        self.browser.find_element_by_link_text("Request a certificate").click()
        self.browser.find_element_by_link_text("advanced certificate request").click()

    def fill_out_signing_page_and_download(self, cert_contents, cert_template):
        """
        Fills out cert signing page and downloads signed cert and cert chain
        """

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
            raise RuntimeError(f"No certificate templates named {cert_template}")
        self.browser.find_element_by_id("btnSubmit").click()
        # Select base 64 encoded and download
        self.browser.find_element_by_id("rbB64Enc").click()
        self.browser.find_element_by_link_text("Download certificate").click()
        self.browser.find_element_by_link_text("Download certificate chain").click()
