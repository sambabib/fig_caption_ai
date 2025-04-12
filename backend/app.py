from flask import Flask, request, jsonify, make_response
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
from collections import deque

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

# Special handling for Figma plugin's null origin
# Instead of using Flask-CORS, we'll manually set CORS headers for all responses
@app.after_request
def add_cors_headers(response):
    # Get allowed origins from environment variable
    allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "null").split(",")
    origin = request.headers.get('Origin', '')

    # Always allow preflight requests
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Session-Token'
        response.headers['Access-Control-Max-Age'] = '86400'  # 24 hours
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    # For non-OPTIONS requests, check if origin is allowed
    origin_allowed = origin == 'null' or origin in allowed_origins
    if origin_allowed:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Session-Token'

    logger.debug(f"after_request CORS headers set for origin: {origin}")
    return response

# Handle OPTIONS requests explicitly and set preflight headers directly
@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    # Explicitly create a response for OPTIONS requests
    response = make_response() # Create an empty response
    origin = request.headers.get('Origin', '')
    allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "null").split(",")

    # Set CORS headers specifically for the preflight response
    origin_allowed = False
    if origin == 'null' or origin in allowed_origins:
         origin_allowed = True
    else:
         for allowed in allowed_origins:
             if allowed == '*': # Handle wildcard if needed
                 origin_allowed = True
                 break

    if origin_allowed:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        # Add other necessary CORS headers for preflight ONLY if origin allowed
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Session-Token'
        response.headers['Access-Control-Max-Age'] = '86400' # 24 hours

    logger.debug(f"OPTIONS request handled for origin: {origin}, setting preflight headers")
    # Return 204 No Content for preflight
    return response, 204

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
HF_REQUEST_TIMESTAMPS = deque(maxlen=GLOBAL_HF_REQUESTS_PER_MIN)  # Use a deque to limit size

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
# Session renewal disabled to enforce strict rate limits
# RENEWAL_THRESHOLD_HOURS = 1 # Renew if less than 1 hour remaining
CLEANUP_BATCH_SIZE = 100   # Number of expired sessions to delete in one batch (Consider background job)

# Rate limiting configuration
MAX_REQUESTS_PER_DAY = 5  # Strict limit of 5 requests per day per user
RATE_LIMIT_ERROR = {"error": f"Rate limit exceeded. Maximum {MAX_REQUESTS_PER_DAY} requests per day allowed."}
SESSION_ERROR_INVALID = {"error": "Invalid or expired session"}
SESSION_ERROR_MISSING = {"error": "No session token provided"}
AUTH_ERROR = {"error": "Unauthorized"}
SERVER_ERROR = {"error": "Internal server error"}
RENEWAL_FAILED_ERROR = {"error": "Failed to renew session"}

# --- Session Management Functions ---

def create_session_token(user_id: str):
    """Creates a new session token and stores it in Supabase."""
    # First, invalidate any existing active sessions for this user
    now = datetime.now(timezone.utc)
    try:
        supabase.table('sessions').update({'expiry': now.isoformat()}).eq('user_id', user_id).gte('expiry', now.isoformat()).execute()
    except Exception as e:
        logger.warning(f'Failed to invalidate existing sessions for user {user_id}: {str(e)}')

    token = secrets.token_urlsafe(32)
    expiry = now + timedelta(hours=SESSION_EXPIRY_HOURS)

    try:
        # Insert new session. Initial count/reset time set by DB defaults or function.
        response = supabase.table('sessions').insert({
            'token': token,
            'user_id': user_id,
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
    Verifies session token and checks user-based rate limits.
    Returns: 
        - dict with {'status': status, 'session_data': data} for valid sessions
        - string 'RATE_LIMITED' for rate-limited sessions
        - False for invalid/expired/error sessions
    """
    if not token:
        return False

    now = datetime.now(timezone.utc)
    try:
        # Get session data including user_id
        session = supabase.table('sessions').select('*').eq('token', token).maybe_single().execute()
        
        if not session.data or now >= datetime.fromisoformat(session.data.get('expiry')):
            logger.warning(f"Token {token[:8]}... invalid or expired")
            return False
            
        user_id = session.data.get('user_id')
        if not user_id:
            logger.warning(f"Token {token[:8]}... has no user_id")
            return False

        # Get or create user request data
        user_requests = supabase.table('user_requests').select('*').eq('user_id', user_id).maybe_single().execute()
        
        if not user_requests.data:
            # Create new user_requests record
            user_requests = supabase.table('user_requests').insert({
                'user_id': user_id,
                'request_count': 1,
                'last_reset': now.isoformat()
            }).execute()
            logger.info(f"Created new request tracking for user {user_id}")
        else:
            # Check if we need to reset count (it's past midnight UTC from last reset)
            last_reset = datetime.fromisoformat(user_requests.data['last_reset'])
            next_reset = (last_reset + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            
            if now >= next_reset:
                # Reset count
                user_requests = supabase.table('user_requests').update({
                    'request_count': 1,
                    'last_reset': now.isoformat()
                }).eq('user_id', user_id).execute()
                logger.info(f"Reset request count for user {user_id}")
            elif user_requests.data['request_count'] >= MAX_REQUESTS_PER_DAY:
                logger.warning(f"User {user_id} has hit rate limit")
                return 'RATE_LIMITED'
            else:
                # Increment count
                user_requests = supabase.table('user_requests').update({
                    'request_count': user_requests.data['request_count'] + 1
                }).eq('user_id', user_id).execute()
                logger.info(f"Incremented request count for user {user_id}")
        
        # Calculate time until next reset
        last_reset = datetime.fromisoformat(user_requests.data['last_reset'])
        next_reset = (last_reset + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        time_until_reset = next_reset - now
        
        response = {'status': 'OK', 'session_data': session.data}
        
        # Only add warning when 1 request remaining
        request_count = user_requests.data['request_count']
        if request_count == MAX_REQUESTS_PER_DAY - 1:
            hours = int(time_until_reset.total_seconds() // 3600)
            minutes = int((time_until_reset.total_seconds() % 3600) // 60)
            response['warning'] = f'You have 1 request left until {hours}h {minutes}m from now'
        
        logger.info(f"User {user_id} request count: {request_count}")
        return response

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

        # Check session validity and rate limit in one step
        verify_result = verify_session(token)
        
        # Handle different verification results
        if verify_result == False:
            return jsonify(SESSION_ERROR_INVALID), 401
        elif verify_result == 'RATE_LIMITED':
            return jsonify(RATE_LIMIT_ERROR), 429
            
        # For valid sessions, we now have the session data
        session_data = verify_result.get('session_data', {})
        # Log the current request count
        if session_data:
            logger.info(f"Current request count for session {token[:8]}: {session_data.get('request_count')}")
            
        # Session renewal is disabled to enforce strict rate limits
        # No need to check for renewal status

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

        # Session renewal is disabled to enforce strict rate limits
        # No token renewal logic needed

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
        # Verify plugin secret and user ID from JSON body
        data = request.get_json()
        logger.info(f"Auth request received. Data: {data}")
        
        if not data or data.get('secret') != PLUGIN_SECRET:
            logger.warning("Authentication attempt failed: Invalid or missing secret.")
            return jsonify({"error": "Invalid secret"}), 401

        user_id = data.get('userId')
        if not user_id:
            logger.warning("Authentication attempt failed: Missing user ID")
            return jsonify({"error": "User ID required"}), 400

        # Create session token with user ID
        token = create_session_token(user_id)
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
        logger.debug(f"Received Hugging Face response data: {hf_data}") # Log the raw response

        # Check response format more carefully
        caption = None
        if isinstance(hf_data, list) and len(hf_data) > 0:
            if isinstance(hf_data[0], dict) and 'generated_text' in hf_data[0]:
                caption = hf_data[0]['generated_text']
            else:
                logger.warning(f"Unexpected item format in Hugging Face list response: {hf_data[0]}")
        elif isinstance(hf_data, dict) and 'generated_text' in hf_data: # Handle if response is a dict
             caption = hf_data['generated_text']
        elif isinstance(hf_data, dict) and 'error' in hf_data: # Handle HF API error messages
            logger.error(f"Hugging Face API returned an error: {hf_data['error']}")
            return jsonify({"error": f"AI service error: {hf_data['error']}"}), 502

        if caption:
            logger.info(f"Caption generated successfully.")
            return jsonify({"caption": caption.strip()}), 200
        else:
            logger.error(f"Could not extract caption from Hugging Face response: {hf_data}")
            return jsonify({"error": "Failed to parse caption from AI service response"}), 500

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