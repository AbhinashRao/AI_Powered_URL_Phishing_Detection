import gradio as gr # type: ignore
from transformers import pipeline

# Load the text classification pipeline
pipe = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs")

# Function to perform analysis on the provided URL
def analyze_url(url):
    result = pipe(url)
    if bool(url)==0:
        return "Error"
    label = result[0]['label']
    score = result[0]['score']
    return f"The URL is classified as {label} with a confidence score of {score:.2%}"

# Gradio Interface
iface = gr.Interface(
    fn=analyze_url,
    inputs=gr.Textbox(label="Enter URL", placeholder="e.g., https://example.com"),
    outputs=gr.Textbox("Result", label="Analysis Result"),
    live=False,
    title="Malicious URL Detector",
    description="Enter a URL to check if it's malicious.",
    theme='derekzen/stardust',
)

iface.launch(share=True)
