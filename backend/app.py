from flask import Flask, request, jsonify, make_response
from flask_cors import CORS, cross_origin
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

# CORS configuration
ALLOWED_ORIGINS = [
    "https://sambabib.github.io",  # GitHub Pages proxy
    "https://www.figma.com",       # Figma plugin iframe
    "null"                         # Figma plugin sandboxed iframe
]

logger.info(f'Configuring app-wide CORS with allowed origins: {ALLOWED_ORIGINS}')
CORS(app,
     origins=ALLOWED_ORIGINS,
     supports_credentials=True,
     expose_headers=['Content-Type', 'Authorization', 'X-Session-Token'],
     allow_headers=['Content-Type', 'Authorization', 'X-Session-Token'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     max_age=86400,
     automatic_options=True)

# Add detailed logging for all responses to help debug CORS issues
@app.after_request
def log_response_headers(response):
    origin = request.headers.get('Origin', '')
    # Log detailed information about the request and response
    logger.info(f"CORS: {request.method} {request.path} from origin '{origin}' → Status {response.status_code}")
    
    # For OPTIONS requests (preflight), log the full headers to help debug CORS issues
    if request.method == 'OPTIONS':
        logger.info(f"Preflight response headers (from @app.after_request): {dict(response.headers)}")
        # Add Access-Control-Allow-Private-Network if requested
        if request.headers.get('Access-Control-Request-Private-Network') == 'true':
            response.headers['Access-Control-Allow-Private-Network'] = 'true'
            logger.info("Added Access-Control-Allow-Private-Network header.")
    
    # Log authentication-related headers (without exposing sensitive data)
    auth_header = request.headers.get('Authorization', '')
    session_token = request.headers.get('X-Session-Token', '')
    if auth_header or session_token:
        logger.info(f"Auth headers present: Authorization={bool(auth_header)}, X-Session-Token={bool(session_token)}")
    
    return response

# Constants
# The 'base' model can be flaky on the inference API. Using 'large' is more reliable.
HUGGINGFACE_API_URL = "https://api-inference.huggingface.co/models/Salesforce/blip-image-captioning-large"
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
PLUGIN_SECRET = os.getenv("PLUGIN_SECRET")
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


# Initialize Supabase client with retry logic
def initialize_supabase(max_retries=3, retry_delay=2):
    global supabase
    
    for attempt in range(max_retries):
        try:
            supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
            logger.info("Supabase client initialized successfully.")
            return True
        except Exception as e:
            logger.warning(f"Supabase initialization attempt {attempt+1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logger.exception(f"Failed to initialize Supabase client after {max_retries} attempts: {e}")
                return False

# Initialize on startup
supabase = None
supabase_initialized = initialize_supabase()

# Fallback mode if Supabase fails to initialize
if not supabase_initialized:
    logger.warning("Running in fallback mode without Supabase. Some features may be limited.")


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
    try:
        # Check if Supabase is available
        if not supabase:
            logger.warning("Supabase not available, using fallback token generation")
            # Generate a fallback token that works without Supabase
            return f"fallback_{secrets.token_hex(16)}_{user_id}"
            
        # First, invalidate any existing sessions for this user
        try:
            response = supabase.table('sessions').select('id').eq('user_id', user_id).execute()
            if response.data:
                for session in response.data:
                    supabase.table('sessions').delete().eq('id', session['id']).execute()
                logger.info(f"Invalidated {len(response.data)} existing sessions for user {user_id}")
        except Exception as e:
            logger.warning(f"Failed to invalidate existing sessions for user {user_id}: {e}")

        # Generate a new token
        token = secrets.token_hex(32)  # 64-character hex string
        
        # Calculate expiry time
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(hours=SESSION_EXPIRY_HOURS)
        
        # Store in Supabase
        supabase.table('sessions').insert({
            'token': token,
            'user_id': user_id,
            'created_at': now.isoformat(),
            'expires_at': expiry.isoformat(),
            'request_count': 0
        }).execute()
        
        logger.info(f"Created new session token for user {user_id}")
        return token
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        # Return a fallback token that works without Supabase
        return f"fallback_{secrets.token_hex(16)}_{user_id}"

def verify_session(token):
    """
    Verifies session token and checks user-based rate limits.
    Returns: 
        - dict with {'status': status, 'session_data': data} for valid sessions
        - string 'RATE_LIMITED' for rate-limited sessions
        - False for invalid/expired/error sessions
    """
    # Handle fallback tokens (created when Supabase is unavailable)
    if token and token.startswith('fallback_'):
        logger.info(f"Processing fallback token: {token[:15]}...")
        return {
            'status': 'valid',
            'session_data': {
                'user_id': token.split('_')[-1],
                'request_count': 0,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'expires_at': (datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRY_HOURS)).isoformat()
            },
            'renewed': False
        }
        
    # If Supabase is not available, accept any token in development mode
    if not supabase:
        if FLASK_ENV == 'development':
            logger.warning("Supabase unavailable, accepting all tokens in development mode")
            return {
                'status': 'valid',
                'session_data': {
                    'user_id': 'dev_user',
                    'request_count': 0
                },
                'renewed': False
            }
        else:
            logger.error("Supabase unavailable in production mode")
            return False
    
    try:
        # Fetch session data
        response = supabase.table('sessions').select('*').eq('token', token).execute()
        
        if not response.data or len(response.data) == 0:
            logger.warning(f"Session token not found: {token[:10]}...")
            return False
        
        session_data = response.data[0]
        
        # Check if session is expired
        expires_at = datetime.fromisoformat(session_data['expires_at'].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        if now > expires_at:
            logger.warning(f"Session token expired: {token[:10]}...")
            # Optionally delete expired session
            supabase.table('sessions').delete().eq('id', session_data['id']).execute()
            return False
        
        # Check if approaching expiry and needs renewal
        renewal_threshold = now + timedelta(hours=RENEWAL_THRESHOLD_HOURS)
        needs_renewal = expires_at < renewal_threshold
        
        # Check rate limits
        request_count = session_data['request_count']
        if request_count >= MAX_REQUESTS_PER_DAY:
            logger.warning(f"Rate limit exceeded for token {token[:10]}...: {request_count} requests")
            return 'RATE_LIMITED'
        
        # Update request count and last_used
        supabase.table('sessions').update({
            'request_count': request_count + 1,
            'last_used': now.isoformat()
        }).eq('id', session_data['id']).execute()
        
        # Renew session if needed
        if needs_renewal:
            try:
                new_expiry = now + timedelta(hours=SESSION_EXPIRY_HOURS)
                supabase.table('sessions').update({
                    'expires_at': new_expiry.isoformat()
                }).eq('id', session_data['id']).execute()
                logger.info(f"Renewed session token: {token[:10]}...")
                session_data['expires_at'] = new_expiry.isoformat()
            except Exception as e:
                logger.error(f"Failed to renew session: {e}")
                # Continue with the existing session data
        
        return {
            'status': 'valid',
            'session_data': session_data,
            'renewed': needs_renewal
        }
    except Exception as e:
        logger.exception(f"Error verifying session token: {e}")
        # In development mode, be more forgiving with errors
        if FLASK_ENV == 'development':
            logger.warning("Allowing request despite verification error in development mode")
            return {
                'status': 'valid',
                'session_data': {
                    'user_id': 'error_recovery_user',
                    'request_count': 0
                },
                'renewed': False
            }
        return False


def cleanup_expired_sessions():
    """Deletes expired sessions from the database."""
    # Caution: Running this synchronously within a request (like verify_session)
    # can add latency. Best run as a periodic background task/cron job.
    logger.info("Attempting to clean up expired sessions...")
    try:
        # Skip if Supabase is not available
        if not supabase:
            logger.warning("Skipping cleanup_expired_sessions: Supabase not available")
            return
            
        now = datetime.now(timezone.utc)
        # Delete expired sessions in batches
        response = supabase.table('sessions')\
            .delete()\
            .lt('expires_at', now.isoformat())\
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

@app.route("/auth", methods=["POST", "OPTIONS"])
# No @cross_origin decorator for this debugging step
def authenticate():
    if request.method == "OPTIONS":
        logger.info(f"/auth OPTIONS: Handling preflight request explicitly.")
        response = make_response() 
        response.status_code = 204

        request_origin = request.headers.get('Origin')
        logger.info(f"/auth OPTIONS: Request Origin Header: '{request_origin}'")
        logger.info(f"/auth OPTIONS: ALLOWED_ORIGINS list: {ALLOWED_ORIGINS}")

        if request_origin in ALLOWED_ORIGINS:
            logger.info(f"/auth OPTIONS: Origin '{request_origin}' IS in ALLOWED_ORIGINS. Setting ACAO header.")
            response.headers['Access-Control-Allow-Origin'] = request_origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
        else:
            logger.warning(f"/auth OPTIONS: Origin '{request_origin}' IS NOT in ALLOWED_ORIGINS. ACAO header NOT set.")

        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Session-Token'
        response.headers['Access-Control-Max-Age'] = '86400'
        
        logger.info(f"/auth OPTIONS: Explicitly set response headers: {dict(response.headers)}")
        return response

    # --- Actual POST logic starts here ---
    logger.info("/auth POST: Handling actual authentication request.")
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

        # In development mode, bypass Supabase and return a static token
        if FLASK_ENV == 'development':
            logger.info("Development mode: Bypassing Supabase session creation")
            dev_token = f"dev_{secrets.token_hex(16)}"
            return jsonify({"token": dev_token}), 200
            
        # In production, create a real session token with user ID
        token = create_session_token(user_id)
        return jsonify({"token": token}), 200

    except Exception as e:
        logger.exception(f"Authentication error: {str(e)}")
        return jsonify({"error": "Authentication failed"}), 500

def check_global_rate_limit():
    """Check if we're within global Hugging Face API rate limits"""
    one_minute_ago = datetime.now(timezone.utc) - timedelta(minutes=1)
    recent_requests = len([ts for ts in HF_REQUEST_TIMESTAMPS if ts > one_minute_ago])
    return recent_requests < GLOBAL_HF_REQUESTS_PER_MIN

@app.route("/generate-caption", methods=["POST"])
# Only require session in production mode
def generate_caption():
    # Log the request details to help with debugging
    content_type = request.headers.get('Content-Type', 'none')
    content_length = request.headers.get('Content-Length', 'unknown')
    logger.info(f"Generate caption request received: Content-Type={content_type}, Content-Length={content_length}")
    
    # In development mode, bypass session verification
    if FLASK_ENV != 'development':
        # Verify session token
        token = request.headers.get('X-Session-Token')
        if not token:
            logger.warning("Missing session token")
            return jsonify(SESSION_ERROR_MISSING), 401
            
        # Verify the session
        session_result = verify_session(token)
        if session_result == False:
            logger.warning(f"Invalid or expired session token {token[:10]}...")
            return jsonify(AUTH_ERROR), 401
        elif session_result == 'RATE_LIMITED':
            logger.warning(f"Rate limit exceeded for token {token[:10]}...")
            return jsonify(RATE_LIMIT_ERROR), 429
            
    # Process the image
    """Generates a caption for the uploaded image."""
    try:
        # Check global rate limit
        if not check_global_rate_limit():
            logger.warning("Global Hugging Face API rate limit reached")
            return jsonify({"error": "Server is experiencing high load. Please try again later."}), 429

        # Get raw image data from request body
        image_data = request.get_data()
        if not image_data:
            logger.warning("No image data received in request body")
            return jsonify({"error": "No image data provided"}), 400

        logger.info(f"Received image data: {len(image_data)} bytes")
        if len(image_data) > MAX_IMAGE_SIZE:
            logger.warning(f"Image too large: {len(image_data)} bytes (max {MAX_IMAGE_SIZE} bytes)")
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
    host = os.getenv('HOST', '0.0.0.0')
    logger.info(f"Starting Flask app on https://{host}:{port} with debug mode: {debug_mode}")
    app.run(
        host=host,
        port=port,
        debug=debug_mode,
        ssl_context='adhoc'  # Enable HTTPS with a self-signed certificate
    )