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
    PROMT_CHECK_CSP = "Does the proided URL describe a cloud storage application? \
                   A cloud storage application is a webservice which allows a user to host their files, and share them with others. \
                   Answer with a percentage, in a variable called 'percentage'."
