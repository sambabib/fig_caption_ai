from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from PIL import Image
import io
import logging
from dotenv import load_dotenv
import secrets
import time
from functools import wraps

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Constants
HUGGINGFACE_API_URL = "https://api-inference.huggingface.co/models/Salesforce/blip-image-captioning-base"
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
PLUGIN_SECRET = os.getenv("PLUGIN_SECRET", "your-plugin-secret")  # Shared secret with plugin
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Store for temporary session tokens
# In production, use Redis or a proper database
active_sessions = {}

def create_session_token():
    token = secrets.token_urlsafe(32)
    expiry = time.time() + 3600  # 1 hour expiry
    active_sessions[token] = expiry
    return token

def verify_session(token):
    if token in active_sessions:
        if time.time() < active_sessions[token]:
            return True
        else:
            del active_sessions[token]
    return False

def require_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Session-Token')
        if not token or not verify_session(token):
            return jsonify({"error": "Invalid or expired session"}), 401
        return f(*args, **kwargs)
    return decorated

def verify_api_key():
    api_key = request.headers.get('X-API-Key')
    if not api_key or api_key != PLUGIN_SECRET:
        return False
    return True

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return jsonify({"status": "healthy", "message": "Image Captioning API is running!"})

@app.route("/auth", methods=["POST"])
def authenticate():
    try:
        # Verify plugin secret
        data = request.get_json()
        if not data or data.get('secret') != PLUGIN_SECRET:
            return jsonify({"error": "Unauthorized"}), 401

        # Create session token
        token = create_session_token()
        return jsonify({"token": token})

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return jsonify({"error": "Authentication failed"}), 500

@app.route("/generate-caption", methods=["POST"])
@require_session
def generate_caption():
    try:
        if "image" not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        image_file = request.files["image"]
        if not allowed_file(image_file.filename):
            return jsonify({"error": "Invalid file type"}), 400

        # Get style parameter
        style = request.form.get('style', 'professional')

        # Read and validate image
        image_data = image_file.read()
        if len(image_data) > MAX_IMAGE_SIZE:
            return jsonify({"error": "Image too large (max 10MB)"}), 400

        # Style-specific prompts
        style_prompts = {
            'professional': 'Provide a clear, formal description of this image: ',
            'creative': 'Describe this image in an artistic and imaginative way: ',
            'friendly': 'Describe this image in a casual, approachable way: '
        }

        # Prepare headers for Hugging Face API
        headers = {
            "Authorization": f"Bearer {HUGGINGFACE_API_KEY}"
        }

        # Send request to Hugging Face
        try:
            response = requests.post(
                HUGGINGFACE_API_URL,
                headers=headers,
                data=image_data,
                params={"prompt": style_prompts.get(style, style_prompts['professional'])}
            )
            response.raise_for_status()
            
            caption = response.json()[0]['generated_text']

            # Remove the prompt from the generated caption if it appears
            prompt = style_prompts.get(style, style_prompts['professional'])
            if caption.startswith(prompt):
                caption = caption[len(prompt):].strip()

            return jsonify({"caption": caption})

        except requests.exceptions.RequestException as e:
            logger.error(f"Hugging Face API error: {str(e)}")
            return jsonify({"error": "Failed to generate caption"}), 500

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.getenv('PORT', 5000))
    app.run(
        host=os.getenv('HOST', '0.0.0.0'),
        port=port,
        debug=os.getenv('FLASK_ENV') == 'development'
    )
