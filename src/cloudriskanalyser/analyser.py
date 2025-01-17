#!/usr/bin/python
import sys
import typing

from scrapegraphai.graphs import SmartScraperGraph

# Own modules
from llm_data import LLMConfiguration as cfg
from llm_data import LLMPromts as prm


#################################
# Constants
#################################
URL_CVE_MITRE: str = "https://cve.mitre.org/"


#################################
# Shared Functions
#################################
# Check if an URL is a legitimate CSP
def is_valid_csp(csp_url: str) -> bool:

    # check if the website is a legitimate CSP (LLM check)
    output = get_scrape_output(csp_url, prm.PROMT_CHECK_CSP)
    percentage = output["percentage"]

    # check if a valid result was received
    if percentage == "NA":
        print("It was not possible to access " + csp_url + ". Does it represent a valid domain-name?")
        return False

    else:
        print("There is a " + str(percentage) + "% chance that " + csp_url + " is a cloud service provider")

        if int(percentage) >= 50:
            return True
        else:
            return False


# Evaluate the "Lack of Control" risk
def get_risk_lack_of_control(csp_url: str) -> bool:
    output = get_scrape_output(URL_CVE_MITRE, prm.get_promt_check_risk_lack_of_control(csp_url))
    result = output["result"]

    if result == "NA":
        print("Lack of Control Risk: No valid output")
        return False
    else:
        print("Output: " + result)
        return True


# Evaluate the "Insec Auth" risk
def get_risk_insec_auth(csp_url: str) -> bool:
    output = get_scrape_output(csp_url, prm.PROMT_CHECK_RISK_INSEC_AUTH)
    result = output["result"]

    if result == "NA":
        print("Insec Auth Risk: No valid output")
        return False
    else:
        print("Output: " + result)
        return True


# Evaluate the "Compliance Issues" risk
def get_risk_comp_issues(csp_url: str) -> bool:
    output = get_scrape_output(csp_url, prm.PROMT_CHECK_RISK_COMP_ISSUES)
    result = output["result"]

    if result == "NA":
        print("Compliance Issues Risk: No valid output")
        return False
    else:
        print("Output: " + result)
        return True


# Let the LLM search the content of a source
def get_scrape_output(source: str, promt: str) -> dict[str, typing.Any]:

    smart_scraper_graph = SmartScraperGraph(
        source=source,
        prompt=promt,
        config=cfg.GRAPH_CONFIG
    )

    return smart_scraper_graph.run()  # type: ignore[no-any-return]


#################################
# Main
#################################
def main():

    # --- accept user input
    print("Welcome to CloudRiskAnalyser")
    application_url = input("Please enter the domain name of a cloud storage service which you would like to assess (format: https://www.example.com): ")
    user_country = input("Please enter your residency country: ")  # noqa: F841

    # --- find out if data is a valid CSP
    print("Starting assessment...")
    if (is_valid_csp(application_url)):
        print(application_url + " is a valid cloud storge service. Continuing...")
    else:
        print(application_url + " is no valid cloud storage service. Please try again.")
        sys.exit()

    # --- gather data for assessing risk
    get_risk_lack_of_control(application_url)

    get_risk_comp_issues(application_url)

    get_risk_comp_issues(application_url)

    # --- calculate result


if __name__ == "__main__":
    main()
