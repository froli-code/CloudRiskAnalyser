#################################
# This class takes information about cloud services as input, and calculates the risk of using it.
#################################
class RiskCalculator:

    # Init the class and take the name as input.
    def __init__(self, csp_name: str, user_country: str) -> None:
        self.csp_name = csp_name
        self.user_country = user_country

    # --------------------------------
    # Shared Functions
    # --------------------------------
    # Set information for "lack of control" risk
    def set_risk_params_lack_of_control(self) -> None:
        pass

    # Set information for "insec auth" risk
    def set_risk_params_insec_auth(self, csp_supports_mfa: bool, csp_supports_auth_protocols: bool) -> None:
        self.csp_supports_mfa = csp_supports_mfa
        self.csp_supports_auth_protocols = csp_supports_auth_protocols

    # Set information for "comp_issues" risk
    def set_risk_params_comp_issues(self, csp_default_countries: list[str], csp_possible_countries: list[str]) -> None:
        # If not known, "unknown" will be passed
        self.csp_default_countries = csp_default_countries
        self.csp_possible_countries = csp_possible_countries

    # Calculate risk based on information stored in this class
    def get_risk(self) -> None:
        pass

    # Print all instance variables, for testing
    def print_instance_vars(self) -> None:
        print("-- Printing RiskCalculator variables --")
        print(vars(self))
