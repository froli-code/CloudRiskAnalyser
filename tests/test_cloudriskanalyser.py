# import pytest

# Own modules
import cloudriskanalyser.analyser as cra


def test_validate_csp_dropbox():
    # www.dropbox.com is a valid CSP, result "True" expected
    if cra.is_valid_csp("http://www.dropbox.com"):
        assert True
    else:
        assert False


def test_validate_csp_onedrive():
    # http://www.onedrive.com is a valid CSP, result "True" expected
    if cra.is_valid_csp("http://www.onedrive.com"):
        assert True
    else:
        assert False


def test_validate_csp_box():
    # http://www.box.com is a valid CSP, result "True" expected
    if cra.is_valid_csp("http://www.box.com"):
        assert True
    else:
        assert False


def test_validate_csp_wikipedia():
    # http://www.wikipedia.org is NOT avalid CSP, result "False" expected
    if not cra.is_valid_csp("http://www.wikipedia.org"):
        assert True
    else:
        assert False


def test_validate_csp_asdf():
    # "asdf" is NOT avalid domainname, result "False" expected
    if not cra.is_valid_csp("asdf"):
        assert True
    else:
        assert False
        