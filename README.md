# TrustLink: Safeguarding Against Deceptive URLs

Welcome to TrustLink, a project developed during the Delhi Police Cyber Hackathon, aimed at enhancing online security by detecting and safeguarding against deceptive URLs. TrustLink leverages machine learning models, data analysis, and dynamic classification techniques to provide users with a reliable solution to identify and avoid malicious links, contributing to a safer online experience.

## Team Members
- [Ujjawal Saini](https://github.com/spignelon/)
- [Divyanshu Shukla](https://github.com/Divyanshushukla1)
- [Alorika Jain](https://github.com/BLACKACE13)
- [Dev Bhardwaj](https://github.com/DBhardwaj21)

## Project Overview
TrustLink utilizes a combination of static and dynamic analysis to examine URLs for potential threats, categorizing them into labels such as phishing, malware, benign, or defacement. The project incorporates diverse data sources, including curated host lists and a pre-trained text classification model, to offer a robust defense against deceptive URLs.

## Technology Stack
<img width="96" height="96" src="https://img.icons8.com/color/96/python--v1.png" alt="python--v1"/> <img width="96" height="96" src="https://img.icons8.com/nolan/96/flask.png" alt="flask"/> <img width="96" height="96" src="https://huggingface.co/front/assets/huggingface_logo-noborder.svg" alt="transformers"/> <img width="96" height="96" src="https://www.tampermonkey.net/images/ape.svg" alt="Tampermonkey"/> <img width="96" height="96" src="https://img.icons8.com/color/96/json--v1.png" alt="json"/> <img width="96" height="96" src="https://streamlit.io/images/brand/streamlit-mark-color.svg" alt="streamlit"/>

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

## Presentation
For a detailed overview of the TrustLink project, including its objectives, workflow, technology stack, and future aspects, please refer to the [Delhi Police Cyber Hackathon Project Presentation (PDF)](TrustLink_presentation.pdf).

## Future Prospects
TrustLink aims to expand its capabilities in the following areas:
- Protection against Typosquatting attacks.
- Protections against IDN Homograph attacks.
- Enriching the machine learning dataset with additional features, such as comprehensive Whois information and the age of the website.

## Acknowledgments
We extend our gratitude to the Delhi Police Cyber Hackathon for providing a platform to develop and showcase TrustLink, as well as to all organizations and individuals contributing to the project's datasets and resources.

## License
[![GNU GPLv3 Image](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.en.html)
   This project is licensed under the [GNU General Public License v3.0](LICENSE).
