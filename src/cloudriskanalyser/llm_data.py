import logging

from langchain.chains import RetrievalQAWithSourcesChain
from langchain_chroma import Chroma
from langchain_community.retrievers.web_research import WebResearchRetriever
from langchain_community.utilities.google_search import GoogleSearchAPIWrapper
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings

#################################
# Global variables
#################################
logger = logging.getLogger(__name__)


#################################
# This class allows to search on google, and let an LLM process the result
#################################
class LLMResearcher:
    # Setup everything needed for executing a research command
    def __init__(self) -> None:
        self.vectorstore = Chroma(
                                embedding_function=GoogleGenerativeAIEmbeddings(model="models/embedding-001"),
                                persist_directory="./chroma_db_oai"
                            )
        self.llm = ChatGoogleGenerativeAI(
                                model="gemini-1.5-flash",
                                temperature=0
                            )
        self.search = GoogleSearchAPIWrapper()
        self.web_research_retriever = WebResearchRetriever.from_llm(
                                llm=self.llm,  # type: ignore[arg-type]
                                vectorstore=self.vectorstore,
                                search=self.search,
                                allow_dangerous_requests=True,
                                num_search_results=10
                            )

        self.qa_chain = RetrievalQAWithSourcesChain.from_chain_type(self.llm, retriever=self.vectorstore.as_retriever())

    # Search something
    def get_research_results(self, question_google: str, question_data_extract: str) -> str:
        # Search the web and store the result in the vectorstore
        self.web_research_retriever.invoke(question_google)

        logger.info("Asking the LLM: " + question_data_extract)

        # Ask the LLM to extract information from the vectorstore
        result = self.qa_chain.invoke(question_data_extract)

        logger.info("Answer from LLM: " + result["answer"])

        # DEBUGGING: allows the user to ask test different questions
        user_input = "exit"
        while user_input != "exit":
            print("DEBUG-MODE: Googled for: " + question_google)
            print("DEBUG-MODE: Insert question for LLM. Insert 'exit' to continue.")
            user_input = input("Input: ")
            if user_input != "exit":
                result = self.qa_chain.invoke(user_input)
                print("Debug LLM output: " + result["answer"])

        result_cleansed = str(result["answer"]).replace("\n", "")

        return result_cleansed


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
