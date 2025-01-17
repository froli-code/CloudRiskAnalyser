# CloudRiskAnalyser
Assessses the risk to data confidentiality when using particular cloud storage services.


![Tests](https://github.com/froli-code/CloudRiskAnalyser/actions/workflows/tests.yml/badge.svg)

# Requirements

* This project uses the gemini API as a large language model. A valid API key is required. It has to be placed in an environment-variable `GEMINI_API_KEY`.
Example for setting the environement-variable under linux:
`echo "export GEMINI_API_KEY='yourkey'" >> ~/.zshrc`

* This project uses playwright for accessing the gemini API. Install it with `playwright install`.
