import logging

#################################
# Global variables
#################################
logger = logging.getLogger(__name__)


#################################
# This class takes information about cloud services as input, and calculates the risk of using it.
#################################
class RiskCalculator:

    # Init the class and take the name as input.
    def __init__(self, csp_name: str, user_country: str) -> None:
        self.csp_name = csp_name
        self.user_country = user_country

        logger.info("Initialized RiskCalculator object. csp_name: " + csp_name + "; user_country: " + user_country)

    # --------------------------------
    # Shared Functions
    # --------------------------------
    # Set information for "lack of control" risk
    def set_risk_params_lack_of_control(self) -> None:

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

    # Calculate risk based on information stored in this class
    def get_risk(self) -> None:
        pass

    # Print all instance variables, for testing
    def print_instance_vars(self) -> None:
        print("-- Printing RiskCalculator variables --")
        print(vars(self))
