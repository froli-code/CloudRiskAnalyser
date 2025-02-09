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
    PROMT_CHECK_RISK_LACK_OF_CONTROL_DATA_EXTRACT: str = "How many CVE vulnerabilities in your context relate to {csp} and were published in the last 2 years? \
                Today is {current_date}. Provide the CVE-Number and the CVS-Scores. \
                List only those two values, separated by semicolons. Create one line for each CVE. Omit ANY other text, such as 'FINAL ANSWER'."

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
