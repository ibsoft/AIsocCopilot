from flask import Flask, render_template, request, jsonify
import requests
import json
import re
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def generate_response(prompt, temperature=0):
    url = "http://localhost:11434/api/generate"
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": "tinyllama",
        "prompt": prompt,
        "temperature": temperature
    }

    try:
        logging.debug(f"Sending prompt to model: {prompt}")
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()  # Raises an error for HTTP errors
        
        # Collecting all fragments of the response
        response_lines = response.text.strip().split('\n')
        response_text = ''.join(
            [json.loads(line)["response"] for line in response_lines if line]
        )
        return response_text

    except (requests.RequestException, json.decoder.JSONDecodeError, KeyError) as e:
        logging.error(f"Error in generating response: {e}")
        return None

def format_response_to_html(response_text, user_ioc):
    # Split the response into sections based on line breaks
    sections = response_text.split('\n\n')  # Double newline indicates a new section
    formatted_sections = []

    # Add title at the beginning
    formatted_sections.append('<div class="text-center"><h1>IOC Analysis</h1></div>')  # Add centered title

    formatted_sections.append("<h2>Incident Details:</h2>")  # Add subheading for incident details

    for section in sections:
        # Format based on content type
        if section.startswith("Nature of Threat:"):
            formatted_sections.append(f"<h3>Nature of Threat:</h3><p>{section.split(': ', 1)[1]}</p>")
        elif section.startswith("Impact:"):
            formatted_sections.append(f"<h3>Impact:</h3><p style='font-size: 1.2em; color: red;'>{section.split(': ', 1)[1]}</p>")
        elif section.startswith("Mitigation Strategies:"):
            formatted_sections.append("<h3>Mitigation Strategies:</h3>")  # Heading for mitigation strategies
            # Assuming strategies are listed with numbers or bullets
            strategies = re.findall(r'(\d+\.\s+.*?)(?=\n|$)', section, re.DOTALL)  # Match numbered items
            bullet_strategies = re.findall(r'-\s+(.*?)(?=\n|$)', section, re.DOTALL)  # Match bullet items
            if strategies or bullet_strategies:
                formatted_sections.append("<ol>")
                for strategy in strategies:
                    formatted_sections.append(f"<li><strong>{strategy}</strong></li>")
                for bullet in bullet_strategies:
                    formatted_sections.append(f"<li>{bullet.strip()}</li>")  # Use <li> for bullet points
                formatted_sections.append("</ol>")
        else:
            # Default to a paragraph for unrecognized sections
            formatted_sections.append(f"<p>{section}</p>")

    return ''.join(formatted_sections)  # Return the sections joined as a single HTML string


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    query = request.json.get('query')  # Get query from JSON payload
    user_ioc = request.json.get('ioc')  # Get user IOC input from JSON payload
    if not query:
        return jsonify({'error': 'No query provided'}), 400

    logging.debug(f"Received query: {query}")

    # Prepare the SOC analyst prompt
    prompt = (
        f"Conduct a comprehensive analysis of the following incident data to identify potential security threats. "
        f"Please pinpoint date, timem any impacted systems and provide a detailed technical analysis of the threat, "
        f"including the nature of the threat, its potential impact, and recommended mitigation strategies. "
        f"The incident details are as follows: {query}"
        )


    # Use the generate_response function with temperature set to 0
    response = generate_response(prompt, temperature=0)  # Explicitly setting temperature to 0
    if response is None:
        return jsonify({'error': 'Failed to get a response from the model'}), 500

    # Format the response as plain text, including user IOC
    formatted_response = format_response_to_html(response, user_ioc)  # Format dynamically

    logging.debug(f"Formatted response: {formatted_response}")

    return jsonify({'response': formatted_response})

if __name__ == '__main__':
    app.run(debug=True)  # Set to False in production
