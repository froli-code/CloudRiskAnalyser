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
    csp_name = "Dropbox"
    user_country = "Switzerland"

    risk_calculator = RiskCalculator(csp_name, user_country)
    risk_calculator = cra.get_risk_insec_auth(risk_calculator)

    if risk_calculator.csp_supports_mfa and risk_calculator.csp_supports_auth_protocols:
        assert True
    else:
        assert False

#################################
# Shared Functions
#################################
