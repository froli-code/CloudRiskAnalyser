# CloudRiskAnalyser

Assessses the risk to data confidentiality when using particular cloud storage services.

![Tests](https://github.com/froli-code/CloudRiskAnalyser/actions/workflows/tests.yml/badge.svg)

# Requirements

* This project uses the gemini API as a large language model and requires access to the google search-API. Valid API keys for those API-endpoints are required. The following three environment variables have to be configured:
  `GEMINI_API_KEY`: Access to google Gemini API
  `GOOGLE_API_KEY`: Access to google Search API
  `GOOGLE_CSE_ID`: Google Project id, for Search-API

  Example for setting the environement-variable under linux:
  `echo "export GEMINI_API_KEY='yourkey'" >> ~/.zshrc`


* This project uses playwright for accessing the gemini API. Install it with `playwright install`.
