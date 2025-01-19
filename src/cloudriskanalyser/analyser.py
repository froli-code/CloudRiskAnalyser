#!/usr/bin/python
import logging
import sys

# Own modules
from llm_data import LLMResearcher
from llm_data import LLMPrompts as prm


#################################
# Constants
#################################
URL_CVE_MITRE: str = "https://cve.mitre.org/"


#################################
# Shared Functions
#################################
# Check if the provided application is a legitimate CSP
def is_valid_csp(csp_name: str) -> bool:

    result = LLMResearcher().get_research_results(prm.PROMT_CHECK_CSP.format(csp=csp_name))

    # check if a valid result was received
    print("There is a " + str(result) + "% chance that " + csp_name + " is a cloud service provider")

    if int(result) >= 50:
        return True
    else:
        return False


# Evaluate the "Lack of Control" risk
def get_risk_lack_of_control(csp_url: str) -> bool:
    result = "NA"

    if result == "NA":
        print("Lack of Control Risk: No valid output")
        return False
    else:
        print("Output: " + result)
        return True


# Evaluate the "Insec Auth" risk
def get_risk_insec_auth(csp_url: str) -> bool:
    result = "NA"

    if result == "NA":
        print("Insec Auth Risk: No valid output")
        return False
    else:
        print("Output: " + result)
        return True


# Evaluate the "Compliance Issues" risk
def get_risk_comp_issues(csp_url: str) -> bool:
    result = "NA"

    if result == "NA":
        print("Compliance Issues Risk: No valid output")
        return False
    else:
        print("Output: " + result)
        return True


#################################
# Main
#################################
def main():
    logging.basicConfig()
    logging.getLogger("langchain_community.retrievers.web_research").setLevel(logging.ERROR)

    # --- accept user input
    print("Welcome to CloudRiskAnalyser")
    application_name = input("Please enter the name of a cloud storage service which you would like to assess (e.g. Dropbox): ")
    user_country = input("Please enter your residency country: ")  # noqa: F841

    # --- find out if data is a valid CSP
    print("Starting assessment...")
    if (is_valid_csp(application_name)):
        print(application_name + " is a valid cloud storge service. Continuing...")
    else:
        print(application_name + " is no valid cloud storage service. Please try again.")
        sys.exit()

    # --- gather data for assessing risk
    # get_risk_lack_of_control(application_url)

    # get_risk_comp_issues(application_url)

    # get_risk_comp_issues(application_url)

    # --- calculate result


if __name__ == "__main__":
    main()
