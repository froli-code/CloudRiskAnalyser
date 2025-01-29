#################################
# This class stores various LLM prompts
#################################
class LLMPrompts:
    # --------------------------------
    # Constants
    # --------------------------------

    # --- Assessing if the input is actually a CSP
    PROMT_CHECK_CSP_DATA_EXTRACT: str = "Is {csp} a cloud storage application? Provide the answer in likelihood from 0 to 100. \
                Only provide the number in the answer."
    PROMT_CHECK_CSP_GOOGLE: str = "Find out if {csp} is a cloud storage application. Only generate two questions."

    # --- Assessing the "Lack of control" risk
    # PROMT_CHECK_RISK_LACK_OF_CONTROL_1_GOOGLE: str = "Find out how many CVE vulnerabilities {csp} had in the last 5 years."
    PROMT_CHECK_RISK_LACK_OF_CONTROL_1_GOOGLE: str = "cvedetails.com {csp} vulnerability list"
    PROMT_CHECK_RISK_LACK_OF_CONTROL_1_DATA_EXTRACT: str = "How many CVE vulnerabilities did {csp} have in the last 2 years? List the CVE-IDs."
    PROMT_CHECK_RISK_LACK_OF_CONTROL_2: str = " can be considered 'Honest but curious', 'Cheap and lazy' or 'Malicious. \
                A 'Honest but curious' application has not many security weaknesses, while a 'Cheap and lazy' application might have some. \
                A 'Malicious' application will have many weaknesses. \
                Provide the answer in a variable called 'result'."

    # --- Assessing the "Insecure auth" risk
    PROMT_CHECK_RISK_INSEC_AUTH_1_GOOGLE: str = "Find out if {csp} supports MFA.  Only generate two questions."
    PROMT_CHECK_RISK_INSEC_AUTH_1_DATA_EXTRACT: str = "Does {csp} support MFA? Provide the answer in likelihood from 0 to 100. \
                Only provide the number in the answer."

    PROMT_CHECK_RISK_INSEC_AUTH_2_GOOGLE: str = "Find out if {csp} supports SSO. Only generate two questions."
    PROMT_CHECK_RISK_INSEC_AUTH_2_DATA_EXTRACT: str = "Does {csp} support SSO with OIDC, SAML or OAuth? \
                Provide the answer in likelihood from 0 to 100. Only provide the number in the answer."

    # --- Assessing the "Compliance issues" risk
    PROMT_CHECK_RISK_COMP_ISSUES_1_GOOGLE: str = "Find out in which countries {csp} stores their user's data by default."
    PROMT_CHECK_RISK_COMP_ISSUES_1_DATA_EXTRACT: str = "In which countries does {csp} store their user's data by default? \
                Only provide the default locations as output in a list. Ignore the ones additional to the default. \
                If not possible, provide only the text 'unknown'. If there are multiple results, separate them with semicolons."

    PROMT_CHECK_RISK_COMP_ISSUES_2_GOOGLE: str = "Find out if {csp} offers the possibility to select where the user's data is stored."
    PROMT_CHECK_RISK_COMP_ISSUES_2_DATA_EXTRACT: str = "Does {csp} provide different data-storage locations, in addition to the default?\
                Only provide the country names of the additional ones in a list. \
                If not possible, provide only the text 'unknown' without ANY other text, such as 'FINAL ANSWER'. \
                If there are multiple results, separate them with semicolons."
