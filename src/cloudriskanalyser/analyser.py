#!/usr/bin/python
import re
import sys


#################################
# Constants
#################################

#################################
# Shared Functions
#################################
def is_valid_csp(csp_url: str) -> bool:
    # verify if the string is technically a valid hostname
    if is_valid_hostname(csp_url):
        return True
    else:
        return False

    # Include content-wise check if the application is acutally a CSP


def is_valid_hostname(hostname: str) -> bool:
    if len(hostname) > 255:
        return False
    if "." not in hostname:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


#################################
# Main
#################################
def main():
    # accept user input
    print("Welcome to CloudRiskAnalyser")
    application_url = input("Please enter the FQDN of a cloud storage service which you would like to assess: ")

    if (is_valid_csp(application_url)):
        print(application_url + " is a valid cloud storge service.")
    else:
        print(application_url + " is no valid cloud storage service. Please try again.")
        sys.exit()


if __name__ == "__main__":
    main()
