import logging
import uuid

from abc import ABC, abstractmethod
from enum import Enum
from langchain.chains import RetrievalQAWithSourcesChain
from langchain_chroma import Chroma
from langchain_community.document_loaders import JSONLoader
from langchain_community.retrievers.web_research import WebResearchRetriever
from langchain_community.utilities.google_search import GoogleSearchAPIWrapper
from langchain_core.messages.base import BaseMessage
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings

# Own modules
from cve_loader import CVELoader


#################################
# Global variables
#################################
logger = logging.getLogger(__name__)


#################################
# This class provides an Enum for storing the different-data-gathering methods
#################################
class DataGatheringMethod(Enum):
    GEMINI_SEARCH_SEPARATE = 1
    GEMINI_DIRECT = 2
    GEMINI_CVE_DB = 3


#################################
# This is a the abstract base-class for the LLM research runner
#################################
class LLMResearcher(ABC):
    def __init__(self) -> None:
        pass

    @abstractmethod
    def get_research_results(self, question_google: str, question_data_extract: str, llm_test_mode: bool) -> str:
        pass


#################################
# This class allows to search on google, and let an LLM process the result
#################################
class LLMResearcherGeminiSearch(LLMResearcher):
    # Setup everything needed for executing a research command
    def __init__(self) -> None:
        self.vectorstore = Chroma(
                                embedding_function=GoogleGenerativeAIEmbeddings(model="models/embedding-001"),
                                persist_directory="./chroma_db_oai",
                                collection_name=str(uuid.uuid4())
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
    def get_research_results(self, question_google: str, question_data_extract: str, llm_test_mode: bool) -> str:
        # Search the web and store the result in the vectorstore
        self.web_research_retriever.invoke(question_google)

        logger.info("Asking the LLM: " + question_data_extract)

        # Ask the LLM to extract information from the vectorstore
        result = self.qa_chain.invoke(question_data_extract)

        logger.info("Answer from LLM: " + result["answer"])

        # LLM-TEST-MODE: allows the user to ask test different questions
        if llm_test_mode:
            print("LLM-TEST-MODE - Entering LLM Test Mode. Insert 'exit' to continue.")
            user_input = input("LLM-TEST-MODE - Input: ")

            while user_input != "exit":
                result_tst = self.qa_chain.invoke(user_input)
                print("LLM-TEST-MODE - Output: " + result_tst["answer"])
                user_input = input("LLM-TEST-MODE - Input: ")

        result_cleansed = str(result["answer"]).replace("\n", "")

        return result_cleansed


#################################
# This class allows to provide a query directly to gemini AI
#################################
class LLMResearcherGeminiDirect(LLMResearcher):
    # Setup everything needed for executing a research command
    def __init__(self) -> None:

        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-pro",
            temperature=0,
            max_tokens=None,
            timeout=None,
            max_retries=2
        )

    # Search something
    def get_research_results(self, question_google: str, question_data_extract: str, llm_test_mode: bool) -> str:

        logger.info("Asking the LLM: " + question_data_extract)

        # Ask the LLM
        result: BaseMessage = self.llm.invoke(question_data_extract)

        logger.info("Answer from LLM: " + str(result.content))

        # LLM-TEST-MODE: allows the user to ask test different questions
        if llm_test_mode:
            print("LLM-TEST-MODE - Entering LLM Test Mode. Insert 'exit' to continue.")
            user_input = input("LLM-TEST-MODE - Input: ")

            while user_input != "exit":
                result_tst = self.llm.invoke(user_input)
                print("LLM-TEST-MODE - Output: " + str(result_tst.content))
                user_input = input("LLM-TEST-MODE - Input: ")

        return str(result.content)


#################################
# This class allows to search on the CVE database and extract the content with gemini
#################################
class LLMResearcherGeminiCVE(LLMResearcher):
    # Setup everything needed for executing a research command
    def __init__(self) -> None:
        self.vectorstore = Chroma(
                                embedding_function=GoogleGenerativeAIEmbeddings(model="models/embedding-001"),
                                persist_directory="./chroma_db_oai",
                                collection_name=str(uuid.uuid4())
                            )
        self.llm = ChatGoogleGenerativeAI(
                                model="gemini-1.5-pro",
                                temperature=0
                            )
        self.qa_chain = RetrievalQAWithSourcesChain.from_chain_type(self.llm, retriever=self.vectorstore.as_retriever())

    # Search something
    def get_research_results(self, csp_name: str, question_data_extract: str, llm_test_mode: bool) -> str:
        # Invoke the CVE API and search for all CVEs for this CSP
        cve_loader: CVELoader = CVELoader()
        cve_list_file_name = cve_loader.get_CVEs_for_string(csp_name)

        loader: JSONLoader = JSONLoader(cve_list_file_name, jq_schema=".", text_content=False)
        cve_documents = loader.load()

        # Add json file to the vectorstore
        self.vectorstore.add_documents(documents=cve_documents)

        logger.info("Asking the LLM: " + question_data_extract)

        # Ask the LLM to extract information from the vectorstore
        result = self.qa_chain.invoke(question_data_extract)

        logger.info("Answer from LLM: " + result["answer"])

        # LLM-TEST-MODE: allows the user to ask test different questions
        if llm_test_mode:
            print("LLM-TEST-MODE - Entering LLM Test Mode. Insert 'exit' to continue.")
            user_input = input("LLM-TEST-MODE - Input: ")

            while user_input != "exit":
                result_tst = self.qa_chain.invoke(user_input)
                print("LLM-TEST-MODE - Output: " + result_tst["answer"])
                user_input = input("LLM-TEST-MODE - Input: ")

        result_cleansed: str = result["answer"]

        return result_cleansed
