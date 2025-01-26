#!/usr/bin/python
import logging
import sys
import warnings

# Own modules
from llm_data import LLMResearcher
from llm_data import LLMPrompts as prm
from risk_calculator import RiskCalculator, CSPThreatModel

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
def is_valid_csp(csp_name: str) -> bool:

    result = LLMResearcher().get_research_results(prm.PROMT_CHECK_CSP_GOOGLE.format(csp=csp_name),
                                                  prm.PROMT_CHECK_CSP_DATA_EXTRACT.format(csp=csp_name)
                                                  )

    logger.info("Returning result from LLM: " + result)

    return str_to_bool(result)


# Evaluate the "Lack of Control" risk
def get_risk_data_lack_of_control(risk_calculator: RiskCalculator) -> RiskCalculator:
    csp_name: str = risk_calculator.csp_name

    result_control: str = LLMResearcher().get_research_results(prm.PROMT_CHECK_RISK_LACK_OF_CONTROL_1_GOOGLE.format(csp=csp_name),
                                                               prm.PROMT_CHECK_RISK_LACK_OF_CONTROL_1_DATA_EXTRACT.format(csp=csp_name)
                                                               )

    logger.info("Returning result from LLM: " + result_control)

    # Currently always setting "HONEST_BUT_CURIOUS" because the data cannot be gathered correctly yet.
    risk_calculator.set_risk_params_lack_of_control(CSPThreatModel.HONEST_BUT_CURIOUS)

    return risk_calculator


# Evaluate the "Insec Auth" risk
def get_risk_data_insec_auth(risk_calculator: RiskCalculator) -> RiskCalculator:
    csp_name = risk_calculator.csp_name
    result_mfa = LLMResearcher().get_research_results(prm.PROMT_CHECK_RISK_INSEC_AUTH_1_GOOGLE.format(csp=csp_name),
                                                      prm.PROMT_CHECK_RISK_INSEC_AUTH_1_DATA_EXTRACT.format(csp=csp_name)
                                                      )
    result_proto = LLMResearcher().get_research_results(prm.PROMT_CHECK_RISK_INSEC_AUTH_2_GOOGLE.format(csp=csp_name),
                                                        prm.PROMT_CHECK_RISK_INSEC_AUTH_2_DATA_EXTRACT.format(csp=csp_name)
                                                        )

    logger.info("Returning result from LLM: " + result_mfa + " / " + result_proto)

    risk_calculator.set_risk_params_insec_auth(str_to_bool(result_mfa), str_to_bool(result_proto))

    return risk_calculator


# Evaluate the "Compliance Issues" risk
def get_risk_data_comp_issues(risk_calculator: RiskCalculator) -> RiskCalculator:
    csp_name = risk_calculator.csp_name
    result_default_countries: str = LLMResearcher().get_research_results(prm.PROMT_CHECK_RISK_COMP_ISSUES_1_GOOGLE.format(csp=csp_name),
                                                                         prm.PROMT_CHECK_RISK_COMP_ISSUES_1_DATA_EXTRACT.format(csp=csp_name)
                                                                         )
    result_possible_countries: str = LLMResearcher().get_research_results(prm.PROMT_CHECK_RISK_COMP_ISSUES_2_GOOGLE.format(csp=csp_name),
                                                                          prm.PROMT_CHECK_RISK_COMP_ISSUES_2_DATA_EXTRACT.format(csp=csp_name)
                                                                          )

    logger.info("Returning result from LLM: " + result_default_countries + " / " + result_possible_countries)

    risk_calculator.set_risk_params_comp_issues(result_default_countries.split(";"), result_possible_countries.split(";"))

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


#################################
# Main
#################################
def main():
    # --- Logging setup
    logging.basicConfig(filename='analyser.log', level=logging.INFO, format=LOG_FORMAT)

    # Debug google-searches
    # logging.getLogger("googleapiclient.discovery").setLevel(logging.DEBUG)

    # Prevent logging of lang-chain deprecation warnings (new package is not compatible currently)
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    # --- accept user input
    print("Welcome to CloudRiskAnalyser")
    application_name = input("Please enter the name of a cloud storage service which you would like to assess (e.g. Dropbox): ")
    user_country = input("Please enter your residency country: ")  # noqa: F841

    # --- find out if data is a valid CSP
    print("Starting assessment...")
    if (is_valid_csp(application_name)):
        risk_calculator = RiskCalculator(application_name, user_country)
    else:
        print(application_name + " is no valid cloud storage service. Please try again.")
        sys.exit()

    # --- gather data for assessing risk
    risk_calculator = get_risk_data_lack_of_control(risk_calculator)

    risk_calculator = get_risk_data_insec_auth(risk_calculator)

    risk_calculator = get_risk_data_comp_issues(risk_calculator)

    # --- calculate result
    risk_calculator = risk_calculator.get_risk()


if __name__ == "__main__":
    main()
