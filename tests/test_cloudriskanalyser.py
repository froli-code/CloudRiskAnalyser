#!/usr/bin/python

# Own modules
import analyser as cra


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
