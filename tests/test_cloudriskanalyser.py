#!/usr/bin/python

# Own modules
import analyser as cra
from risk_calculator import RiskCalculator


#################################
# Tests
#################################

def test_validate_csp_dropbox():
    # Dropbox is a valid CSP, result "True" expected
    if cra.is_valid_csp("Dropbox"):
        assert True
    else:
        assert False


def test_validate_csp_onedrive():
    # Onedrive is a valid CSP, result "True" expected
    if cra.is_valid_csp("Onedrive"):
        assert True
    else:
        assert False


def test_validate_csp_box():
    # Box is a valid CSP, result "True" expected
    if cra.is_valid_csp("Box"):
        assert True
    else:
        assert False


def test_validate_csp_wikipedia():
    # Wikipedia is NOT avalid CSP, result "False" expected
    if not cra.is_valid_csp("Wikipedia"):
        assert True
    else:
        assert False


def test_validate_csp_asdf():
    # "asdf" is NOT avalid domainname, result "False" expected
    if not cra.is_valid_csp("asdf"):
        assert True
    else:
        assert False


def test_insec_auth_risk_dropbox():
    # "Dropbox" supports MFA and SAML, result "True" expected
    csp_name = "Dropbox"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_insec_auth(risk_calculator)

    if risk_calculator.csp_supports_mfa and risk_calculator.csp_supports_auth_protocols:
        assert True
    else:
        assert False


def test_insec_auth_risk_onedrive():
    # "Onedrive" supports MFA and SAML, result "True" expected
    csp_name = "Onedrive"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_insec_auth(risk_calculator)

    if risk_calculator.csp_supports_mfa and risk_calculator.csp_supports_auth_protocols:
        assert True
    else:
        assert False


def test_insec_auth_risk_box():
    # "Box" supports MFA and SAML, result "True" expected
    csp_name = "Dropbox"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_insec_auth(risk_calculator)

    if risk_calculator.csp_supports_mfa and risk_calculator.csp_supports_auth_protocols:
        assert True
    else:
        assert False


def test_comp_issues_risk_dropbox():
    # Check which countries are supported by "Dropbox"
    csp_name: str = "Dropbox"
    user_country: str = "Switzerland"
    # csp_default_countries: list[str] = ['United States']
    # csp_possible_countries: list[str] = ['Germany', ' Australia', ' Japan']

    risk_calculator: RiskCalculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_comp_issues(risk_calculator)

    if risk_calculator.csp_default_countries != "unknown" and \
       risk_calculator.csp_possible_countries != "unknown":
        assert True
    else:
        assert False


def test_comp_issues_risk_onedrive():
    # Check which countries are supported by "Onedrive"
    # There would be many possible locations, but the current application cannot identify this.
    csp_name: str = "Onedrive"
    user_country: str = "Switzerland"
    csp_default_countries: list[str] = ['unknown']
    csp_possible_countries: list[str] = ['unknown']

    risk_calculator: RiskCalculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_comp_issues(risk_calculator)

    if risk_calculator.csp_default_countries == csp_default_countries and \
       risk_calculator.csp_possible_countries == csp_possible_countries:
        assert True
    else:
        assert False


#################################
# Shared Functions
#################################
