from langchain.chains import RetrievalQAWithSourcesChain
from langchain_chroma import Chroma
from langchain_community.retrievers.web_research import WebResearchRetriever
from langchain_community.utilities.google_search import GoogleSearchAPIWrapper
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings


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
                                llm=self.llm,
                                vectorstore=self.vectorstore,
                                search=self.search,
                                allow_dangerous_requests=True
                            )
        self.qa_chain = RetrievalQAWithSourcesChain.from_chain_type(self.llm, retriever=self.web_research_retriever)

    # Search something
    def get_research_results(self, question: str) -> int:
        result = self.qa_chain.invoke(input={"question": question})

        result_cleansed = str(result["answer"]).replace("\n", "")

        try:
            result_int = int(result_cleansed)
        except ValueError:
            print("LLM did not return an integer value.")
            print("LLM Output: " + result_cleansed)

        return result_int


#################################
# This class stores various LLM prompts
#################################
class LLMPrompts:
    # --------------------------------
    # Constants
    # --------------------------------

    # --- Assessing if the input is actually a CSP
    PROMT_CHECK_CSP: str = "Is {csp} a cloud storage application? Provide the answer in likelihood from 0 to 100. Only provide the number in the answer."

    # --- Assessing the "Lack of control" risk
    PROMT_CHECK_RISK_LACK_OF_CONTROL_1: str = "Assess if the cloud storage application "
    PROMT_CHECK_RISK_LACK_OF_CONTROL_2: str = " can be considered 'Honest but curious', 'Cheap and lazy' or 'Malicious. \
                A 'Honest but curious' application has not many security weaknesses, while a 'Cheap and lazy' application might have some. \
                A 'Malicious' application will have many weaknesses. \
                Provide the answer in a variable called 'result'."

    # --- Assessing the "Insecure auth" risk
    PROMT_CHECK_RISK_INSEC_AUTH_1: str = "Does {csp} support MFA? Provide the answer in likelihood from 0 to 100. Only provide the number in the answer."
    PROMT_CHECK_RISK_INSEC_AUTH_2: str = "Does {csp} support user authentication over the protocols OIDC, SAML or OAuth? \
                If only a paid-tier allows those methods, consider it as being supported. \
                Provide the answer in likelihood from 0 to 100. Only provide the number in the answer."

    # --- Assessing the "Compliance issues" risk
    PROMT_CHECK_RISK_COMP_ISSUES: str = "Return output 'NA' in a variable called 'result'"

    # --------------------------------
    # Shared Functions
    # --------------------------------

    # --- Concat the two strings for "Lack of control" risk, together with the name of the CSP
    @classmethod
    def get_promt_check_risk_lack_of_control(cls, csp: str) -> str:
        return str(cls.PROMT_CHECK_RISK_LACK_OF_CONTROL_1 + csp + cls.PROMT_CHECK_RISK_LACK_OF_CONTROL_2)
