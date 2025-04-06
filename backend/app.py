from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from PIL import Image # Requires Pillow installation: pip install Pillow
import io
import logging
from dotenv import load_dotenv
import secrets
import time # Not strictly used now, but good practice
from functools import wraps
from supabase import create_client, Client
from datetime import datetime, timezone, timedelta

# Configure logging first
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment-specific variables
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
env_file = '.env.production' if FLASK_ENV == 'production' else '.env.development'
load_dotenv(env_file)

# Log which environment was loaded
logger.info(f'Loaded environment: {FLASK_ENV} from {env_file}')

app = Flask(__name__)
CORS(app) # Consider restricting origins in production: CORS(app, origins=["your_figma_plugin_origin"])

# Constants
HUGGINGFACE_API_URL = "https://api-inference.huggingface.co/models/Salesforce/blip-image-captioning-base"
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
PLUGIN_SECRET = os.getenv("PLUGIN_SECRET") # Ensure this is set in your .env file!
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Rate limiting configuration
MAX_REQUESTS_PER_DAY = 10  # Per token/user limit
GLOBAL_HF_REQUESTS_PER_MIN = 60  # Global Hugging Face API limit
SESSION_EXPIRY_HOURS = 24
RENEWAL_THRESHOLD_HOURS = 1  # Renew session if less than 1 hour left

# Global request tracking
HF_REQUEST_TIMESTAMPS = []  # List to track timestamps of HF API requests

# Error responses
AUTH_ERROR = {"error": "Invalid authentication"}
SERVER_ERROR = {"error": "Internal server error"}
SESSION_ERROR_MISSING = {"error": "No session token provided"}
RATE_LIMIT_ERROR = {"error": "Rate limit exceeded"}
RENEWAL_FAILED_ERROR = {"error": "Failed to renew session"}

# Supabase connection
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY') # Use the service_role key for backend operations

if not all([SUPABASE_URL, SUPABASE_KEY, HUGGINGFACE_API_KEY, PLUGIN_SECRET]):
    logger.error("Missing one or more critical environment variables: SUPABASE_URL, SUPABASE_KEY, HUGGINGFACE_API_KEY, PLUGIN_SECRET")


try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    logger.info("Supabase client initialized successfully.")
except Exception as e:
    logger.exception(f"Failed to initialize Supabase client or SQL functions: {e}")
    # Depending on your deployment, you might want to exit here
    # sys.exit("Supabase client initialization failed.")


# Session configuration
SESSION_EXPIRY_HOURS = 24  # Sessions expire after 24 hours
RENEWAL_THRESHOLD_HOURS = 1 # Renew if less than 1 hour remaining
CLEANUP_BATCH_SIZE = 100   # Number of expired sessions to delete in one batch (Consider background job)

# Rate limiting configuration
MAX_REQUESTS_PER_DAY = 100  # Limit requests per day (as defined in RPC call)
RATE_LIMIT_ERROR = {"error": f"Rate limit exceeded. Maximum {MAX_REQUESTS_PER_DAY} requests per day allowed."}
SESSION_ERROR_INVALID = {"error": "Invalid or expired session"}
SESSION_ERROR_MISSING = {"error": "No session token provided"}
AUTH_ERROR = {"error": "Unauthorized"}
SERVER_ERROR = {"error": "Internal server error"}
RENEWAL_FAILED_ERROR = {"error": "Failed to renew session"}

# --- Session Management Functions ---

def create_session_token():
    """Creates a new session token and stores it in Supabase."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=SESSION_EXPIRY_HOURS)

    try:
        # Insert new session. Initial count/reset time set by DB defaults or function.
        response = supabase.table('sessions').insert({
            'token': token,
            'created_at': now.isoformat(),
            'expiry': expiry.isoformat(),
            'last_used_at': now.isoformat(),
            'last_request_reset': now.isoformat(), # Explicitly set initial reset time
            'request_count': 0 # Explicitly set initial count
        }).execute()
        logger.info(f"Created session {token[:8]}...")
        return token
    except Exception as e:
        logger.error(f'Failed to create session: {str(e)}')
        # Check for potential duplicate token collision (rare)
        if "duplicate key value violates unique constraint" in str(e):
             logger.warning("Token collision detected, generating a new token.")
             return create_session_token() # Retry with a new token
        raise # Re-raise other errors

def verify_session(token):
    """
    Verifies session token using the Supabase RPC function for rate limiting.
    Returns: True (valid), 'RATE_LIMITED', 'RENEW', False (invalid/expired/error)
    """
    if not token:
        return False

    now = datetime.now(timezone.utc)
    try:
        # Call the database function
        rpc_params = {
            'session_token': token,
            'max_requests': MAX_REQUESTS_PER_DAY,
            'now_timestamp': now.isoformat() # Pass current time
        }
        # Note: Ensure 'increment_session_request_count' exactly matches the function name in SQL
        result = supabase.rpc('increment_session_request_count', rpc_params).execute()

        # Check Supabase client response structure (might vary slightly)
        if not hasattr(result, 'data'):
             logger.error(f"RPC call for token {token[:8]}... returned unexpected response structure: {result}")
             return False # Treat unexpected structure as error

        status = result.data
        logger.info(f"RPC call for token {token[:8]}... status: {status}")

        if status == 'OK':
            # RPC handled rate limit OK. Now check if renewal is needed.
            try:
                # This adds one extra read ONLY on successful requests needing renewal check.
                session_data = supabase.table('sessions').select('expiry').eq('token', token).maybe_single().execute()
                # maybe_single() returns None if not found, doesn't raise error like single()

                if session_data.data:
                    expiry = datetime.fromisoformat(session_data.data['expiry'].replace('Z', '+00:00'))
                    if expiry - now < timedelta(hours=RENEWAL_THRESHOLD_HOURS):
                        logger.info(f"Token {token[:8]}... requires renewal.")
                        return 'RENEW'
                    return True # Valid, no renewal needed
                else:
                    # Session vanished between RPC call and expiry check (unlikely)
                    logger.warning(f"Token {token[:8]}... passed RPC but not found for renewal check.")
                    return False
            except Exception as e:
                 logger.error(f"Error checking renewal status for {token[:8]}...: {str(e)}")
                 return False # Treat error during renewal check as failure

        elif status == 'RATE_LIMITED':
            return 'RATE_LIMITED'
        elif status == 'EXPIRED':
            # Consider triggering cleanup less frequently or via background task
            # cleanup_expired_sessions()
            logger.info(f"Token {token[:8]}... expired.")
            return False
        elif status == 'NOT_FOUND':
            logger.info(f"Token {token[:8]}... not found.")
            return False
        else: # Handles 'ERROR' or unexpected status strings from RPC
            logger.error(f"RPC call failed or returned unexpected status '{status}' for token {token[:8]}...")
            return False

    except Exception as e:
        # Handle exceptions during the RPC call itself or Supabase client issues
        logger.error(f'Exception during verify_session for {token[:8]}...: {str(e)}')
        return False


def cleanup_expired_sessions():
    """Deletes expired sessions from the database."""
    # Caution: Running this synchronously within a request (like verify_session)
    # can add latency. Best run as a periodic background task/cron job.
    logger.info("Attempting to clean up expired sessions...")
    try:
        now = datetime.now(timezone.utc)
        # Delete expired sessions in batches
        response = supabase.table('sessions')\
            .delete()\
            .lt('expiry', now.isoformat())\
            .execute() # Default limit might apply, check Supabase settings

        # Supabase delete response often contains the deleted data
        deleted_count = len(response.data) if hasattr(response, 'data') else 'unknown'
        logger.info(f'Cleaned up {deleted_count} expired sessions')

    except Exception as e:
        logger.error(f'Failed to cleanup sessions: {str(e)}')

# --- Decorator for Session Requirement ---

def require_session(f):
    """Decorator to enforce valid session token and handle rate limiting/renewal."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Session-Token')
        if not token:
            return jsonify(SESSION_ERROR_MISSING), 401

        # First check if the session exists and is valid
        session_data = supabase.table('sessions').select('*').eq('token', token).maybe_single().execute()
        if not session_data.data:
            return jsonify(SESSION_ERROR_INVALID), 401

        # Check rate limit before processing
        verify_result = verify_session(token)
        # Log the current request count
        session_data = supabase.table('sessions').select('request_count').eq('token', token).maybe_single().execute()
        if session_data.data:
            logger.info(f"Current request count for session {token[:8]}: {session_data.data.get('request_count')}")

        if verify_result == 'RATE_LIMITED':
            return jsonify(RATE_LIMIT_ERROR), 429

        # Handle renewal if needed
        new_token = None
        if verify_result == 'RENEW':
            new_token = create_session_token()

        # Now run the actual request handler
        try:
            original_response = f(*args, **kwargs)
        except Exception as e:
            # If request fails, we should decrement the counter since verify_session already incremented it
            logger.error(f"Request failed, error: {str(e)}")
            raise

        # Process the response
        response_data, status_code = None, None
        if isinstance(original_response, tuple):
            response_data = original_response[0]
            status_code = original_response[1]
        elif isinstance(original_response, dict):
            response_data = jsonify(original_response)
            status_code = 200
        elif hasattr(original_response, 'json'):
            response_data = original_response
            status_code = original_response.status_code
        else:
            logger.error(f"Unexpected response type from wrapped function: {type(original_response)}")
            return jsonify(SERVER_ERROR), 500

        # If we have a new token (from renewal), add it to response
        if new_token:
            current_data = response_data.get_json() if hasattr(response_data, 'get_json') else response_data
            if isinstance(current_data, dict):
                current_data['new_token'] = new_token
                response_data = jsonify(current_data)
            else:
                response_data = jsonify({"data": current_data, "new_token": new_token})

            # Delete the old session after successful renewal
            try:
                supabase.table('sessions').delete().eq('token', token).execute()
                logger.info(f"Old session {token[:8]}... deleted after renewal.")
            except Exception as e:
                logger.error(f"Failed to delete old session {token[:8]}... during renewal: {str(e)}")
                # Don't fail the request, but log the error.

            return response_data, status_code

        # Return the response for non-renewal cases
        return response_data, status_code

    return decorated

# --- Utility Functions ---

def allowed_file(filename):
    """Checks if the filename has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Flask Routes ---

@app.route("/")
def home():
    return jsonify({"status": "healthy", "message": "Image Captioning API is running!"})

@app.route("/auth", methods=["POST"])
def authenticate():
    """Authenticates the plugin and returns a session token."""
    try:
        # Verify plugin secret from JSON body
        data = request.get_json()
        logger.info(f"Auth request received. Data: {data}")
        logger.info(f"Expected secret: {PLUGIN_SECRET}, Received secret: {data.get('secret') if data else None}")
        if not data or data.get('secret') != PLUGIN_SECRET:
            logger.warning("Authentication attempt failed: Invalid or missing secret.")
            return jsonify(AUTH_ERROR), 401

        # Create session token
        token = create_session_token()
        return jsonify({"token": token}), 200

    except Exception as e:
        logger.exception(f"Authentication error: {str(e)}")
        return jsonify({"error": "Authentication failed"}), 500

def check_global_rate_limit():
    """Check if we're within global Hugging Face API rate limits"""
    current_time = datetime.now(timezone.utc)
    one_minute_ago = current_time - timedelta(minutes=1)
    
    # Remove timestamps older than 1 minute
    while HF_REQUEST_TIMESTAMPS and HF_REQUEST_TIMESTAMPS[0] < one_minute_ago:
        HF_REQUEST_TIMESTAMPS.popleft()
    
    # Count requests in the last minute
    recent_requests = len([ts for ts in HF_REQUEST_TIMESTAMPS if ts > one_minute_ago])
    return recent_requests < GLOBAL_HF_REQUESTS_PER_MIN

@app.route("/generate-caption", methods=["POST"])
@require_session # Apply the session check decorator
def generate_caption():
    """Generates a caption for the uploaded image."""
    try:
        # Check global rate limit
        if not check_global_rate_limit():
            logger.warning("Global Hugging Face API rate limit reached")
            return jsonify({"error": "Server is experiencing high load. Please try again later."}), 429

        # Get raw image data from request body
        image_data = request.get_data()
        if not image_data:
            return jsonify({"error": "No image data provided"}), 400

        if len(image_data) > MAX_IMAGE_SIZE:
            return jsonify({"error": f"Image too large (max {MAX_IMAGE_SIZE // (1024*1024)}MB)"}), 400

        # Validate image content using Pillow
        try:
            with Image.open(io.BytesIO(image_data)) as img:
                img.verify() # Verify that it's a valid image file
            # Re-open after verify
            with Image.open(io.BytesIO(image_data)) as img:
                logger.info(f"Received valid image: {img.format} format, {img.size} dimensions.")
        except (IOError, SyntaxError) as e:
            logger.warning(f"Invalid image data received: {e}")
            return jsonify({"error": "Invalid image file data"}), 400

        # Prepare headers for Hugging Face API
        headers = {
            "Authorization": f"Bearer {HUGGINGFACE_API_KEY}",
            "Content-Type": "application/octet-stream"
        }

        # Send request to Hugging Face
        logger.info("Sending image to Hugging Face API...")
        # Track this request
        HF_REQUEST_TIMESTAMPS.append(datetime.now(timezone.utc))
        
        hf_response = requests.post(
            HUGGINGFACE_API_URL,
            headers=headers,
            data=image_data
        )
        hf_response.raise_for_status()

        # Process Hugging Face response
        hf_data = hf_response.json()
        if isinstance(hf_data, list) and len(hf_data) > 0 and 'generated_text' in hf_data[0]:
            caption = hf_data[0]['generated_text']
            logger.info(f"Caption generated successfully.")
            return jsonify({"caption": caption.strip()}), 200
        else:
            logger.error(f"Unexpected response format from Hugging Face: {hf_data}")
            return jsonify({"error": "Failed to parse caption from AI service"}), 500

    except requests.exceptions.RequestException as e:
        logger.error(f"Hugging Face API request error: {str(e)}")
        error_detail = str(e)
        if e.response is not None:
            error_detail = f"Status {e.response.status_code}: {e.response.text}"
        return jsonify({"error": f"Failed to generate caption due to AI service error: {error_detail}"}), 502
    except Exception as e:
        logger.exception(f"Unexpected error in /generate-caption: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

# --- Application Runner ---
if __name__ == "__main__":
    # Run cleanup job once on startup (optional, consider moving to scheduler)
    # cleanup_expired_sessions()

    port = int(os.getenv('PORT', 5000))
    # Debug mode should be False in production
    debug_mode = (FLASK_ENV == 'development')
    logger.info(f"Starting Flask app on port {port} with debug mode: {debug_mode}")
    app.run(
        host=os.getenv('HOST', '0.0.0.0'),
        port=port,
        debug=debug_mode
    )