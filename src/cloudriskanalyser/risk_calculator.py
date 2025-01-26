import logging

from enum import Enum

#################################
# Global variables
#################################
logger = logging.getLogger(__name__)


#################################
# Constants
#################################
GDPR_COUNTRY_LIST: list[str] = ["Austria", "Belgium", "Bulgaria", "Croatia", "Cyprus", "Czech Republic", "Denmark",
                                "Estonia", "Finland", "France", "Germany", "Greece", "Hungary", "Ireland", "Italy",
                                "Latvia", "Lithuania", "Luxembourg", "Malta", "The Netherlands", "Poland", "Portugal",
                                "Romania", "Slovakia", "Slovenia", "Spain", "Sweden", "United Kingdom"]


#################################
# This class provides an Enum for storing the risk-levels
#################################
class RiskLevel(Enum):
    LOW = 1
    MEDIUM_LOW = 2
    MEDIUM = 3
    MEDIUM_HIGH = 4
    HIGH = 5


#################################
# This class provides an Enum for storing CSP threat models
#################################
class CSPThreatModel(Enum):
    HONEST_BUT_CURIOUS = 1
    CHEAP_AND_LAZY = 2
    MALICIOUS = 3


#################################
# This class takes information about cloud services as input, and calculates the risk of using it.
#################################
class RiskCalculator:

    # Init the class and take the name as input.
    def __init__(self, csp_name: str, user_country: str) -> None:
        self.csp_name: str = csp_name
        self.user_country: str = user_country

        logger.info("Initialized RiskCalculator object. csp_name: " + csp_name + "; user_country: " + user_country)

    # --------------------------------
    # Shared Functions
    # --------------------------------
    # Set information for "lack of control" risk
    def set_risk_params_lack_of_control(self, csp_threat_model: CSPThreatModel) -> None:
        self.csp_threat_model = csp_threat_model

        logger.info("Risk variables set for 'lack of control risk'. nA")

    # Set information for "insec auth" risk
    def set_risk_params_insec_auth(self, csp_supports_mfa: bool, csp_supports_auth_protocols: bool) -> None:
        self.csp_supports_mfa = csp_supports_mfa
        self.csp_supports_auth_protocols = csp_supports_auth_protocols

        logger.info("Risk variables set for 'insec auth risk'. csp_supports_mfa: " + str(csp_supports_mfa) +
                    "; csp_supports_auth_protocols: " + str(csp_supports_auth_protocols))

    # Set information for "comp_issues" risk
    def set_risk_params_comp_issues(self, csp_default_countries: list[str], csp_possible_countries: list[str]) -> None:
        # If not known, "unknown" will be passed
        self.csp_default_countries = csp_default_countries
        self.csp_possible_countries = csp_possible_countries

        logger.info("Risk variables set for 'comp issues risk'. csp_default_countries: " + str(csp_default_countries) +
                    "; csp_possible_countries: " + str(csp_possible_countries))

    # Calculate overall risk based on information stored in this class
    def get_risk(self) -> None:

        # Calculate 'lack of control' risk
        self.risk_lack_of_control: RiskLevel = self.get_risk_lack_of_control()

        # Calculate 'insec auth' risk
        self.risk_insec_auth: RiskLevel = self.get_risk_insec_auth()

        # Calculate 'comp issues' risk
        self.risk_comp_issues: RiskLevel = self.get_risk_comp_issues()

    # Calculate 'lack of control' risk
    def get_risk_lack_of_control(self) -> RiskLevel:

        # If HONEST BUT CURIOUS -> Low Risk
        # If CHEAP AND LAZY -> Medium Risk
        # If MALICIOUS -> High Risk

        match self.csp_threat_model:
            case CSPThreatModel.HONEST_BUT_CURIOUS:
                return RiskLevel.LOW
            case CSPThreatModel.CHEAP_AND_LAZY:
                return RiskLevel.MEDIUM
            case CSPThreatModel.MALICIOUS:
                return RiskLevel.HIGH

    # Calculate 'insec auth' risk
    def get_risk_insec_auth(self) -> RiskLevel:

        # If neither MFA or SSO protocols are available, the risk will be "High".
        # If one of both are present, the risk will be "Low".
        if self.csp_supports_mfa or self.csp_supports_auth_protocols:
            return RiskLevel.LOW
        else:
            return RiskLevel.HIGH

    # Calculate 'comp issues' risk
    def get_risk_comp_issues(self) -> RiskLevel:

        # If UNKNOWN -> High Risk
        # If MULTIPLE COUNTRIES -> High Risk  -> Unclear how to check. This is currently not covered.
        # If OTHER COUNTRY -> Medium Risk
        # If OTHER COUNTRY, similar jurisdiction -> Medium-Low Risk
        # If SAME COUNTRY -> Low Risk

        # Unknown -> Always high risk
        if "Unknown" in self.csp_default_countries:
            return RiskLevel.HIGH

        # User-Country supported -> Always low risk
        elif self.user_country in self.csp_default_countries:
            return RiskLevel.LOW

        # Country from similar jurisdiction -> Medium-Low risk
        # - If user country is in GDPR-List
        # - And any CSP country is also in GDPR-List
        elif (self.user_country in GDPR_COUNTRY_LIST and
              len(set(GDPR_COUNTRY_LIST) & set(self.csp_default_countries)) > 0):
            return RiskLevel.MEDIUM_LOW

        # In this case the data is stored in any other country. -> High risk
        else:
            return RiskLevel.MEDIUM

    # Print all instance variables, for testing
    def print_instance_vars(self) -> None:
        print("-- Printing RiskCalculator variables --")
        print(vars(self))
