#!/usr/bin/python
import os
import sys
import typing

from scrapegraphai.graphs import SmartScraperGraph

#################################
# Constants
#################################
GOOGLE_APIKEY = os.environ["GEMINI_API_KEY"]
GRAPH_CONFIG = {
    "llm": {
        "api_key": GOOGLE_APIKEY,
        "model": "google_genai/gemini-1.5-flash",
        "model_tokens": 8192
    }
}

PROMT_CHECK_CSP = "Does the proided URL describe a cloud storage application? \
                   A cloud storage application is a webservice which allows a user to host their files, and share them with others. \
                   Answer with a percentage, in a variable called 'percentage'."


#################################
# Shared Functions
#################################
# Check if an URL is a legitimate CSP
def is_valid_csp(csp_url: str) -> bool:

    # check if the website is a legitimate CSP (LLM check)
    output = get_scrape_output(csp_url, PROMT_CHECK_CSP)
    percentage = output["percentage"]

    # check if a valid result was received
    if percentage == "NA":
        print("It was not possible to access " + csp_url + ". Does it represent a valid domain-name?")
        return False

    else:
        print("There is a " + str(percentage) + "% chance that " + csp_url + " is a cloud service provider")

        if percentage >= 50:
            return True
        else:
            return False


# Let the LLM search the content of a source
def get_scrape_output(source: str, promt: str) -> dict[str, typing.Any]:

    smart_scraper_graph = SmartScraperGraph(
        source=source,
        prompt=promt,
        config=GRAPH_CONFIG
    )

    return smart_scraper_graph.run()  # type: ignore[no-any-return]


#################################
# Main
#################################
def main():

    # accept user input
    print("Welcome to CloudRiskAnalyser")
    application_url = input("Please enter the domain name of a cloud storage service which you would like to assess (format: https://www.example.com): ")

    if (is_valid_csp(application_url)):
        print(application_url + " is a valid cloud storge service.")
    else:
        print(application_url + " is no valid cloud storage service. Please try again.")
        sys.exit()


if __name__ == "__main__":
    main()
