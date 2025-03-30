import pytest
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from app import app, verify_session, check_global_rate_limit, HF_REQUEST_TIMESTAMPS

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_supabase():
    with patch('app.supabase') as mock:
        yield mock

def test_per_token_rate_limit(client, mock_supabase):
    """Test that per-token rate limiting works correctly"""
    # Mock session data for a token
    session_data = {
        'token': 'test_token',
        'request_count': 9,  # Just under the limit of 10
        'created_at': datetime.now(timezone.utc).isoformat(),
        'expiry': (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    }
    
    # Mock initial session data
    mock_supabase.table().select('*').eq('token', 'test_token').maybe_single().execute.return_value = MagicMock(data=session_data)
    mock_supabase.table().select('request_count').eq('token', 'test_token').maybe_single().execute.return_value = MagicMock(data=session_data)
    mock_supabase.rpc().execute.return_value = MagicMock(data='OK')
    
    # First request should succeed (request count = 9)
    mock_supabase.rpc().execute.return_value = MagicMock(data='OK')
    response = client.post('/generate-caption', 
                         headers={'X-Session-Token': 'test_token'},
                         json={'test': True})
    assert response.status_code != 429
    
    # Update mock to show we're at the limit
    session_data['request_count'] = 10
    mock_supabase.table().select('*').eq('token', 'test_token').maybe_single().execute.return_value = MagicMock(data=session_data)
    mock_supabase.table().select('request_count').eq('token', 'test_token').maybe_single().execute.return_value = MagicMock(data=session_data)
    mock_supabase.rpc().execute.return_value = MagicMock(data='RATE_LIMITED')
    
    # Next request should be rate limited
    response = client.post('/generate-caption',
                         headers={'X-Session-Token': 'test_token'},
                         json={'test': True})
    assert response.status_code == 429
    assert b'Rate limit exceeded' in response.data

def test_global_rate_limit(client):
    """Test that global rate limiting works correctly"""
    # Clear any existing timestamps
    HF_REQUEST_TIMESTAMPS.clear()
    
    # Add timestamps just under the limit (59 requests in last minute)
    current_time = datetime.now(timezone.utc)
    for i in range(59):
        HF_REQUEST_TIMESTAMPS.append(current_time - timedelta(seconds=i))
    
    # Should still allow one more request
    assert check_global_rate_limit() == True
    
    # Add one more timestamp to hit the limit
    HF_REQUEST_TIMESTAMPS.append(current_time)
    
    # Should now be rate limited
    assert check_global_rate_limit() == False
    
    # After waiting (or requests expire), should allow requests again
    HF_REQUEST_TIMESTAMPS.clear()
    assert check_global_rate_limit() == True

def test_rate_limit_expiry(client, mock_supabase):
    """Test that rate limits reset after 24 hours"""
    # Mock old session data (>24 hours old)
    old_time = datetime.now(timezone.utc) - timedelta(hours=25)
    session_data = {
        'token': 'test_token',
        'request_count': 10,  # At the limit
        'created_at': old_time.isoformat(),
        'expiry': (old_time + timedelta(hours=24)).isoformat()
    }
    
    # Mock Supabase responses
    mock_supabase.table().select().eq().maybe_single().execute.return_value = MagicMock(data=session_data)
    
    # Should create a new session since the old one expired
    response = client.post('/generate-caption',
                         headers={'X-Session-Token': 'test_token'},
                         json={'test': True})
    assert response.status_code != 429  # Should not be rate limited

def test_global_rate_limit_rolling_window(client):
    """Test that global rate limit uses a rolling 60-second window"""
    HF_REQUEST_TIMESTAMPS.clear()
    current_time = datetime.now(timezone.utc)
    
    # Add 30 timestamps spread over 2 minutes (one every 4 seconds)
    for i in range(30):
        HF_REQUEST_TIMESTAMPS.append(current_time - timedelta(seconds=i*4))
    
    # Should allow requests since they're spread out
    assert check_global_rate_limit() == True
    
    # Add 60 timestamps all within the last minute
    HF_REQUEST_TIMESTAMPS.clear()
    for i in range(60):
        HF_REQUEST_TIMESTAMPS.append(current_time - timedelta(seconds=i))
    
    # Should be rate limited
    assert check_global_rate_limit() == False
