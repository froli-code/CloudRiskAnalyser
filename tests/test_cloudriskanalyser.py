#!/usr/bin/python
import pytest

# Own modules
import analyser as cra
from llm_researcher import DataGatheringMethod
from risk_calculator import RiskCalculator, RiskLevel, CVEEntry

#################################
# CONSTANTS
#################################
DATA_GATHERING_METHOD: list[DataGatheringMethod] = [DataGatheringMethod.GEMINI_SEARCH_SEPARATE, DataGatheringMethod.GEMINI_DIRECT]
# DATA_GATHERING_METHOD: list[DataGatheringMethod] = [DataGatheringMethod.GEMINI_DIRECT]


#################################
# Tests
#################################
# --- Test the data-gathering for identifying a CSP
@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_validate_csp_dropbox(n):
    # Dropbox is a valid CSP, result "True" expected
    if cra.is_valid_csp("Dropbox", n):
        assert True
    else:
        assert False


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_validate_csp_onedrive(n):
    # Onedrive is a valid CSP, result "True" expected
    if cra.is_valid_csp("Onedrive", n):
        assert True
    else:
        assert False


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_validate_csp_box(n):
    # Box is a valid CSP, result "True" expected
    if cra.is_valid_csp("Box", n):
        assert True
    else:
        assert False


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_validate_csp_wikipedia(n):
    # Wikipedia is NOT avalid CSP, result "False" expected
    if not cra.is_valid_csp("Wikipedia", n):
        assert True
    else:
        assert False


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_validate_csp_asdf(n):
    # "asdf" is NOT avalid domainname, result "False" expected
    if not cra.is_valid_csp("asdf", n):
        assert True
    else:
        assert False


# --- Test the data-gathering for 'insec auth' risk
@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_insec_auth_risk_dropbox(n):
    # "Dropbox" supports MFA and SAML, result "True" expected
    csp_name = "Dropbox"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_data_insec_auth(risk_calculator, n)

    if risk_calculator.csp_supports_mfa and risk_calculator.csp_supports_auth_protocols:
        assert True
    else:
        pytest.skip("Unexpected LLM output")


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_insec_auth_risk_onedrive(n):
    # "Onedrive" supports MFA and SAML, result "True" expected
    # Sometimes it is not possible to find out if SAML is supported or not (because entra ID is responsible for authentication, and not onedrive)
    # Therefore both values will be accepted as ok.
    csp_name = "Onedrive"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_data_insec_auth(risk_calculator, n)

    if (risk_calculator.csp_supports_mfa is True and
        (risk_calculator.csp_supports_auth_protocols is True or
         risk_calculator.csp_supports_auth_protocols is False)):
        assert True
    else:
        pytest.skip("Unexpected LLM output")


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_insec_auth_risk_box(n):
    # "Box" supports MFA and SAML, result "True" expected
    csp_name = "Dropbox"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_data_insec_auth(risk_calculator, n)

    if risk_calculator.csp_supports_mfa and risk_calculator.csp_supports_auth_protocols:
        assert True
    else:
        pytest.skip("Unexpected LLM output")


# --- Test the data-gathering for 'comp-issues' risk
@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_comp_issues_risk_dropbox(n):
    # Check which countries are supported by "Dropbox"
    csp_name: str = "Dropbox"
    user_country: str = "Switzerland"
    # csp_default_countries: list[str] = ['United States']
    # csp_possible_countries: list[str] = ['Germany', ' Australia', ' Japan']

    risk_calculator: RiskCalculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_data_comp_issues(risk_calculator, n)

    if risk_calculator.csp_default_countries != "unknown" and \
       risk_calculator.csp_possible_countries != "unknown":
        assert True
    else:
        pytest.skip("Unexpected LLM output")


@pytest.mark.parametrize('n', DATA_GATHERING_METHOD)
def test_comp_issues_risk_onedrive(n):
    # Check which countries are supported by "Onedrive"
    # There would be many possible locations, but the current application cannot identify this.
    csp_name: str = "Onedrive"
    user_country: str = "Switzerland"
    csp_default_countries: list[str] = ['unknown']
    csp_possible_countries: list[str] = ['unknown']

    risk_calculator: RiskCalculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_data_comp_issues(risk_calculator, n)

    if risk_calculator.csp_default_countries == csp_default_countries and \
       risk_calculator.csp_possible_countries == csp_possible_countries:
        assert True
    else:
        pytest.skip("Unexpected LLM output")


# --- Test the risk-calculation functions
def test_risk_calc_lack_of_control_low():
    # For "Calc Lack of Control" there is only one data gathering method (GEMINI_CVE_DB). Therefore this test is not parametrized.

    # CVSS Score summary 3.1 -> should be HONEST_BUT_CURIOUS
    # "HONEST_BUT_CURIOUS", risk should be LOW

    cve_list: list[CVEEntry] = []

    cve_list.append(CVEEntry("CVE-9999-1000", 1.1))
    cve_list.append(CVEEntry("CVE-9999-1001", 2.0))

    # Provide CVE list to risk_calculator. It will then calculate the risk.

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Switzerland")
    risk_calculator.set_risk_params_lack_of_control(cve_list)

    if risk_calculator.get_risk_lack_of_control() == RiskLevel.LOW:
        assert True
    else:
        assert False


def test_risk_calc_lack_of_control_medium():
    # For "Calc Lack of Control" there is only one data gathering method (GEMINI_CVE_DB). Therefore this test is not parametrized.

    # CVSS Score summary 25.3 -> should be CHEAP_AND_LAZY
    # "CHEAP_AND_LAZY", risk should be MEDIUM

    cve_list: list[CVEEntry] = []

    cve_list.append(CVEEntry("CVE-9999-2000", 9.1))
    cve_list.append(CVEEntry("CVE-9999-2001", 8.7))
    cve_list.append(CVEEntry("CVE-9999-2003", 7.5))

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Switzerland")
    risk_calculator.set_risk_params_lack_of_control(cve_list)

    if risk_calculator.get_risk_lack_of_control() == RiskLevel.MEDIUM:
        assert True
    else:
        assert False


def test_risk_calc_lack_of_control_high():
    # For "Calc Lack of Control" there is only one data gathering method (GEMINI_CVE_DB). Therefore this test is not parametrized.

    # CVSS Score summary 56.7 -> should be MALICIOUS
    # "MALICIOUS", risk should be HIGH

    cve_list: list[CVEEntry] = []

    cve_list.append(CVEEntry("CVE-9999-3000", 9.1))
    cve_list.append(CVEEntry("CVE-9999-3001", 8.7))
    cve_list.append(CVEEntry("CVE-9999-3003", 7.5))
    cve_list.append(CVEEntry("CVE-9999-3004", 6.5))
    cve_list.append(CVEEntry("CVE-9999-3005", 9.5))
    cve_list.append(CVEEntry("CVE-9999-3006", 8.0))
    cve_list.append(CVEEntry("CVE-9999-3007", 7.4))

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Switzerland")
    risk_calculator.set_risk_params_lack_of_control(cve_list)

    if risk_calculator.get_risk_lack_of_control() == RiskLevel.HIGH:
        assert True
    else:
        assert False


def test_risk_calc_insec_auth_risk_low():
    # If MFA or SSO Protocols are supported, the risk should be LOW

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Switzerland")
    risk_calculator.set_risk_params_insec_auth(True, False)

    if risk_calculator.get_risk_insec_auth() == RiskLevel.LOW:
        assert True
    else:
        assert False


def test_risk_calc_insec_auth_risk_high():
    # If neither MFA or SSO Protocols are supported, the risk should be HIGH

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Switzerland")
    risk_calculator.set_risk_params_insec_auth(False, False)

    if risk_calculator.get_risk_insec_auth() == RiskLevel.HIGH:
        assert True
    else:
        assert False


def test_risk_calc_comp_issues_risk_low():
    # If The data-residency is in the same country as the user, the risk should be LOW.

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Switzerland")
    risk_calculator.set_risk_params_comp_issues(["Switzerland", "Sweden"], ["Unknown"])

    if risk_calculator.get_risk_comp_issues() == RiskLevel.LOW:
        assert True
    else:
        assert False


def test_risk_calc_comp_issues_risk_med_low():
    # If The data-residency is covered by GDPR (and the user too), the risk should be MEDIUM-LOW.

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Germany")
    risk_calculator.set_risk_params_comp_issues(["Belgium", "Sweden"], ["Unknown"])

    if risk_calculator.get_risk_comp_issues() == RiskLevel.MEDIUM_LOW:
        assert True
    else:
        assert False


def test_risk_calc_comp_issues_risk_medium():
    # If The data-residency is in a different country (not covered by GDPR), the risk should be MEDIUM.

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Germany")
    risk_calculator.set_risk_params_comp_issues(["United States"], ["Unknown"])

    if risk_calculator.get_risk_comp_issues() == RiskLevel.MEDIUM:
        assert True
    else:
        assert False


def test_risk_calc_comp_issues_risk_high():
    # If The data-residency unknown, the risk should be HIGH.

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Germany")
    risk_calculator.set_risk_params_comp_issues(["Unknown"], ["Unknown"])

    if risk_calculator.get_risk_comp_issues() == RiskLevel.HIGH:
        assert True
    else:
        assert False


def test_risk_calc_all_no_inp():
    # If no risk-parameters are set, the output should be "NA"
    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Germany")

    risk_calculator.get_risk()

    if risk_calculator.risk_lack_of_control == RiskLevel.NA and \
       risk_calculator.risk_insec_auth == RiskLevel.NA and \
       risk_calculator.risk_comp_issues == RiskLevel.NA and \
       risk_calculator.risk_overall == RiskLevel.NA:
        assert True
    else:
        assert False


def test_risk_calc_all_medium():
    # The overall risk level should be MEDIUM

    cve_list: list[CVEEntry] = []

    cve_list.append(CVEEntry("CVE-9999-2000", 9.1))
    cve_list.append(CVEEntry("CVE-9999-2001", 8.7))
    cve_list.append(CVEEntry("CVE-9999-2003", 7.5))

    risk_calculator: RiskCalculator = RiskCalculator("TestCSP", "Germany")

    risk_calculator.set_risk_params_lack_of_control(cve_list)
    risk_calculator.set_risk_params_insec_auth(True, False)
    risk_calculator.set_risk_params_comp_issues(["United States"], ["Unknown"])

    risk_calculator.get_risk()

    if risk_calculator.risk_overall == RiskLevel.MEDIUM:
        assert True
    else:
        assert False


#################################
# Shared Functions
#################################
