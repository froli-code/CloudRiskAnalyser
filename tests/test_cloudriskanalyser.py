# import pytest

# Own modules
import cloudriskanalyser.analyser as cra


def test_validate_csp_dropbox():

    # www.dropbox.com is a valid CSP, result "True" expected
    if cra.is_valid_csp("http://www.dropbox.com"):
        assert True
    else:
        assert False

    # www.wikipedia.org is no valid CSP, result "False" expected
    # if not cra.is_valid_csp("www.wikipedia.org"):
    #     assert True
    # else:
    #    assert False

    # flup is no valid FQDN, result "False" expected
    # if not cra.is_valid_csp("flup"):
    #    assert True
    # else:
    #    assert False
