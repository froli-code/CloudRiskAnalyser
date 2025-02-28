# CloudRiskAnalyser

Assessses the risk to data confidentiality when using particular cloud storage services.

![Tests](https://github.com/froli-code/CloudRiskAnalyser/actions/workflows/tests.yml/badge.svg)

## Requirements & setup

* The project was built and tested under a linux operating system (Debian 12). While it should be platform independent, this was not tested and is currently not supported.

* This project is built to work with Python 3.12

* The automated tests of this project use *playwright*. Install it with `playwright install`. If it is not yet installed on your system, consider playwright's [documentation](https://playwright.dev/docs/intro).

* This project uses the *Generative Language API* and the *Custom Search API* from Google Cloud. Valid API keys for those API-endpoints are required. The following three environment variables have to be configured:
  + `GEMINI_API_KEY`: Access to google `Generative Language API`
  + `GOOGLE_API_KEY`: Access to google `Custom Search API`
  + `GOOGLE_CSE_ID`: Google Project id, required for `Custom Search API`

  Example for setting the environement-variable under linux and zsh:
  ```
  echo "export GEMINI_API_KEY='your_key'" >> ~/.zshrc
  echo "export GOOGLE_API_KEY='your_key'" >> ~/.zshrc
  echo "export GOOGLE_CSE_ID='your_id'" >> ~/.zshrc
  ```

* The usage of the *Custom Search API* is not free. For testing the project, it might be necessary to setup a free testing account which provides free credits.