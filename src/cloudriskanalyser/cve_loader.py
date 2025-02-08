import jsonpickle
import logging
import nvdlib
import os


#################################
# Global variables
#################################
logger = logging.getLogger(__name__)


#################################
# This class is responsible for loading and providing the CVE data
# documentation for NVDLib: https://nvdlib.com/en/stable/
#################################
class CVELoader():
    def __init__(self) -> None:
        # load the required API key from the env variables
        self.NVD_API_KEY = os.getenv("NVD_API_KEY")

    def get_CPEs_for_string(self, search_string: str) -> None:
        r = nvdlib.searchCPE(keywordSearch=search_string, key=self.NVD_API_KEY)
        for eachCPE in r:
            print(eachCPE.cpeName)

    def get_CVEs_for_CPE(self, cpe_string: str) -> None:
        r = nvdlib.searchCVE(cpeName=cpe_string, key=self.NVD_API_KEY)
        for eachCVE in r:
            print(eachCVE.id, str(eachCVE.score[0]), eachCVE.url)

    def get_CVEs_for_string(self, search_string: str) -> str:
        filename: str = "cve_data.json"

        cve_list: list[str] = nvdlib.searchCVE(keywordSearch=search_string, key=self.NVD_API_KEY)

        with open(filename, "w") as outfile:
            outfile.write(jsonpickle.encode(cve_list))

        outfile.close()

        return filename
