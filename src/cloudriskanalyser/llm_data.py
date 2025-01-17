class LLMConfiguration:
    import os

    GOOGLE_APIKEY = os.environ["GEMINI_API_KEY"]

    GRAPH_CONFIG = {
        "llm": {
            "api_key": GOOGLE_APIKEY,
            "model": "google_genai/gemini-1.5-flash",
            "model_tokens": 8192
        }
    }


class LLMPromts:
    #################################
    # Constants
    #################################

    # --- Assessing if the input is actually a CSP
    PROMT_CHECK_CSP: str = "Does the proided URL describe a cloud storage application? \
                A cloud storage application is a webservice which allows a user to host their files, and share them with others. \
                Answer with a percentage, in a variable called 'percentage'."

    # --- Assessing the "Lack of control" risk
    PROMT_CHECK_RISK_LACK_OF_CONTROL_1: str = "Assess if the cloud storage application "
    PROMT_CHECK_RISK_LACK_OF_CONTROL_2: str = " can be considered 'Honest but curious', 'Cheap and lazy' or 'Malicious. \
                A 'Honest but curious' application has not many security weaknesses, while a 'Cheap and lazy' application might have some. \
                A 'Malicious' application will have many weaknesses. \
                Provide the answer in a variable called 'result'."

    # --- Assessing the "Insecure auth" risk
    PROMT_CHECK_RISK_INSEC_AUTH: str = "Return output 'NA' in a variable called 'result'"

    # --- Assessing the "Compliance issues" risk
    PROMT_CHECK_RISK_COMP_ISSUES: str = "Return output 'NA' in a variable called 'result'"

    #################################
    # Shared Functions
    #################################

    # --- Concat the two strings for "Lack of control" risk, together with the name of the CSP
    @classmethod
    def get_promt_check_risk_lack_of_control(cls, csp: str) -> str:
        return str(cls.PROMT_CHECK_RISK_LACK_OF_CONTROL_1 + csp + cls.PROMT_CHECK_RISK_LACK_OF_CONTROL_2)
