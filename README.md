# TrustLink: Safeguarding Against Deceptive URLs

This project implements an AI-powered URL Phishing Detection System that classifies URLs as benign, phishing, or malware using machine learning. It extracts key features from URLs such as length, special characters, domain patterns, and more. A trained model predicts whether a URL is safe or suspicious. The system also integrates with a browser extension (Tampermonkey) to alert users in real-time. Known malicious URLs are blocked instantly using a dataset, while the model analyzes unknown ones. A user-friendly interface displays alerts and logs suspicious activity for further analysis.


## Project Overview
TrustLink utilizes a combination of static and dynamic analysis to examine URLs for potential threats, categorizing them into labels such as phishing, malware, benign, or defacement. The project incorporates diverse data sources, including curated host lists and a pre-trained text classification model, to offer a robust defense against deceptive URLs.

## Technology Stack

- **Flask:** Python-based web framework for developing the backend logic and the API of the TrustLink project.
- **Transformers Library:** Utilized for the ML model, providing a pre-trained text classification model for analyzing URLs.
- **Python:** Primary programming language for scripting and backend development.
- **Streamlit**: Utilized for the web application, allowing users to input URLs and receive classification results.
- **Tampermonkey Script:** A Tampermonkey script is provided for enabling real-time threat detection directly in the browser.

## Workflow
1. **User Input:** Users input a URL into the TrustLink web application or Use Tampermonkey Chrome extension for automatic detection and blocking.
2. **Static Analysis:** Comparison against pre-loaded data from various host lists to identify patterns associated with malicious behavior.
3. **Dynamic Analysis:** Utilization of a pre-trained text classification model for dynamic analysis if the URL is not found in host lists.
4. **Classification Results:** Display of classification results on the webapp, including labels such as phishing, malware, benign, or defacement, along with corresponding scores.

## How to Use TrustLink
1. Clone the repository.
2. Install the required dependencies using `requirements.txt`.
3. Run the Flask API (`flask_api.py`) to set up the backend logic for URL classification.
4. Run the Streamlit app (`streamlit_app.py`) to input a URL and view the classification results.
5. Optionally, install the Tampermonkey script in your browser to experience real-time threat detection.



## Future Prospects
TrustLink aims to expand its capabilities in the following areas:
- Protection against Typosquatting attacks.
- Protections against IDN Homograph attacks.
- Enriching the machine learning dataset with additional features, such as comprehensive Whois information and the age of the website.

## Acknowledgments
We extend our gratitude to the Delhi Police Cyber Hackathon for providing a platform to develop and showcase TrustLink, as well as to all organizations and individuals contributing to the project's datasets and resources.


