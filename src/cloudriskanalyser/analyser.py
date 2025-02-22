#!/usr/bin/python
import logging
import os
import sys
import warnings

from datetime import date

# Own modules
from llm_data import LLMPrompts as prm
from llm_researcher import DataGatheringMethod, LLMResearcher, LLMResearcherGeminiSearch, LLMResearcherGeminiDirect, LLMResearcherGeminiCVE
from risk_calculator import RiskCalculator, CVEEntry

#################################
# Global variables
#################################
logger = logging.getLogger(__name__)

#################################
# Constants
#################################
URL_CVE_MITRE: str = "https://cve.mitre.org/"
LOG_FORMAT: str = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)s - %(funcName)s ] %(message)s"


#################################
# Shared Functions
#################################
# Check if the provided application is a legitimate CSP
def is_valid_csp(csp_name: str, data_gathering_method: DataGatheringMethod, llm_test_mode: bool = False) -> bool:
    research_runner: LLMResearcher = get_research_runner(data_gathering_method)

    if llm_test_mode:
        print("LLM-TEST-MODE - assessing is_valid_csp")

    result: str = research_runner.get_research_results(prm.PROMT_CHECK_CSP_GOOGLE.format(csp=csp_name),
                                                       prm.PROMT_CHECK_CSP_DATA_EXTRACT.format(csp=csp_name),
                                                       llm_test_mode
                                                       )

    logger.info("Returning result from LLM: " + result)

    return str_to_bool(result)


# Evaluate the "Lack of Control" risk
def get_risk_data_lack_of_control(risk_calculator: RiskCalculator, data_gathering_method: DataGatheringMethod, llm_test_mode: bool = False) -> RiskCalculator:
    csp_name: str = risk_calculator.csp_name

    research_runner: LLMResearcher = get_research_runner(data_gathering_method)

    if llm_test_mode:
        print("LLM-TEST-MODE - assessing get_risk_data_lack_of_control")

    result_control = research_runner.get_research_results(csp_name,
                                                          prm.PROMT_CHECK_RISK_LACK_OF_CONTROL_DATA_EXTRACT.format(csp=csp_name, current_date=date.today()),
                                                          llm_test_mode
                                                          )

    logger.info("Returning result from LLM: " + result_control)

    lines = result_control.splitlines()
    cve_list: list[CVEEntry] = []

    for line in lines:
        entries = line.split(";")

        try:
            cvss_float = float(entries[1])
            cve_list.append(CVEEntry(entries[0], cvss_float))
        except ValueError:
            logger.warn("Non-float value returned for CVSS score: \"" + entries[0] + "\"; \"" + entries[1] + "\"")
        except IndexError:
            logger.warn("Empty value returned for CVSS score. Ignoring this entry.")

    # Provide CVE list to risk_calculator. It will then calculate the risk.
    risk_calculator.set_risk_params_lack_of_control(cve_list)

    return risk_calculator


# Evaluate the "Insec Auth" risk
def get_risk_data_insec_auth(risk_calculator: RiskCalculator, data_gathering_method: DataGatheringMethod, llm_test_mode: bool = False) -> RiskCalculator:
    csp_name = risk_calculator.csp_name

    research_runner: LLMResearcher = get_research_runner(data_gathering_method)

    if llm_test_mode:
        print("LLM-TEST-MODE - assessing get_risk_data_insec_auth 1")

    result_mfa = research_runner.get_research_results(prm.PROMT_CHECK_RISK_INSEC_AUTH_1_GOOGLE.format(csp=csp_name),
                                                      prm.PROMT_CHECK_RISK_INSEC_AUTH_1_DATA_EXTRACT.format(csp=csp_name),
                                                      llm_test_mode
                                                      )

    if llm_test_mode:
        print("LLM-TEST-MODE - assessing get_risk_data_insec_auth 2")

    result_proto = research_runner.get_research_results(prm.PROMT_CHECK_RISK_INSEC_AUTH_2_GOOGLE.format(csp=csp_name),
                                                        prm.PROMT_CHECK_RISK_INSEC_AUTH_2_DATA_EXTRACT.format(csp=csp_name),
                                                        llm_test_mode
                                                        )

    logger.info("Returning result from LLM: " + result_mfa + " / " + result_proto)

    risk_calculator.set_risk_params_insec_auth(str_to_bool(result_mfa), str_to_bool(result_proto))

    return risk_calculator


# Evaluate the "Compliance Issues" risk
def get_risk_data_comp_issues(risk_calculator: RiskCalculator, data_gathering_method: DataGatheringMethod, llm_test_mode: bool = False) -> RiskCalculator:
    csp_name = risk_calculator.csp_name

    research_runner: LLMResearcher = get_research_runner(data_gathering_method)

    if llm_test_mode:
        print("LLM-TEST-MODE - assessing get_risk_data_comp_issues")

    result_default_countries: str = research_runner.get_research_results(prm.PROMT_CHECK_RISK_COMP_ISSUES_1_GOOGLE.format(csp=csp_name),
                                                                         prm.PROMT_CHECK_RISK_COMP_ISSUES_1_DATA_EXTRACT.format(csp=csp_name),
                                                                         llm_test_mode
                                                                         )

    logger.info("Returning result from LLM: " + result_default_countries)

    # It is difficult to gather the "possible countries". This variable is currently filled with the default value "unknown".
    risk_calculator.set_risk_params_comp_issues(result_default_countries.split(";"), "unknown")

    return risk_calculator


# This method is used to convert string values to bool
def str_to_bool(input: str) -> bool:
    # an integer value is expected in the string.
    # this integer is then assessed and converted to bool.

    try:
        result_int = int(input)
    except ValueError:
        print("LLM did not return an integer value.")
        print("LLM Output: " + input)
        return False

    if result_int >= 50:
        return True
    else:
        return False


# This method returns an LLMResearchRunner, depending on the selected data-gathering method
def get_research_runner(data_gathering_method: DataGatheringMethod) -> LLMResearcher:
    match data_gathering_method:
        case DataGatheringMethod.GEMINI_SEARCH_SEPARATE:
            return (LLMResearcherGeminiSearch())
        case DataGatheringMethod.GEMINI_DIRECT:
            return (LLMResearcherGeminiDirect())
        case DataGatheringMethod.GEMINI_CVE_DB:
            return (LLMResearcherGeminiCVE())


# This method asks the user which data-gathering method he wants to use
def get_from_usr_default_data_gath_method() -> DataGatheringMethod:

    print("Different data-gathering methods are available. Please select from the list below (default: 1):")
    print("1 - GEMINI_SEARCH_SEPARATE")
    print("2 - GEMINI_DIRECT")

    data_gathering_method_int: int = 1

    try:
        data_gathering_method_int = int(input("Please select: "))
    except ValueError:
        print("Non-nummeric value entered. Falling back to default")

    match data_gathering_method_int:
        case 1:
            return DataGatheringMethod.GEMINI_SEARCH_SEPARATE
        case 2:
            return DataGatheringMethod.GEMINI_DIRECT
        case _:
            return DataGatheringMethod.GEMINI_SEARCH_SEPARATE


# This method asks the user if he wants to enable llm-test mode
def get_from_usr_llm_test_mode() -> bool:

    llm_test_mode_str = input("Do you want to enable LLM test mode? (y / n, default n): ")

    match llm_test_mode_str:
        case "y":
            return True
        case "n":
            return False
        case _:
            return False


#################################
# Main
#################################
def main():
    # --- Logging setup
    logging.basicConfig(filename='analyser.log', level=logging.DEBUG, format=LOG_FORMAT)

    # Debug google-searches
    # logging.getLogger("googleapiclient.discovery").setLevel(logging.DEBUG)

    # Prevent logging of lang-chain deprecation warnings (new package is not compatible currently)
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    # Clear chroma vector store -> clear data from previous runs
    os.system('rm -rdf chroma_db_oai/')

    # --- accept user input
    print("Welcome to CloudRiskAnalyser")
    application_name = input("Please enter the name of a cloud storage service which you would like to assess (e.g. Dropbox): ")
    user_country = input("Please enter your residency country: ")

    # the method defined by the user applies to all risks, except get_risk_data_lack_of_control (because that always needs to access the CVE db)
    data_gathering_method = get_from_usr_default_data_gath_method()

    # ask the user if he wants to use llm-test mode
    llm_test_mode = get_from_usr_llm_test_mode()

    # --- find out if data is a valid CSP
    print("Starting assessment...")
    if (is_valid_csp(application_name, data_gathering_method, llm_test_mode)):
        risk_calculator = RiskCalculator(application_name, user_country)
    else:
        print(application_name + " is no valid cloud storage service. Please try again.")
        sys.exit()

    # --- gather data for assessing risk
    risk_calculator = get_risk_data_lack_of_control(risk_calculator, DataGatheringMethod.GEMINI_CVE_DB, llm_test_mode)

    risk_calculator = get_risk_data_insec_auth(risk_calculator, data_gathering_method, llm_test_mode)

    risk_calculator = get_risk_data_comp_issues(risk_calculator, data_gathering_method, llm_test_mode)

    # --- calculate result
    risk_calculator = risk_calculator.get_risk()


if __name__ == "__main__":
    main()
