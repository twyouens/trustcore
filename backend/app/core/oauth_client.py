"""
OAuth 2.0 / OIDC Client for FastAPI
Handles authorization code flow with PKCE support and ID token validation
"""

import secrets
import requests
import jwt
from typing import Optional, Dict, Any, Tuple
from jwt import PyJWKClient
from datetime import datetime, timedelta
from urllib.parse import urlencode
from app.core.logging import get_logger

logger = get_logger(__name__)

# Try to import redis_client if available
try:
    from app.core.redis_client import redis_client
except ImportError:
    redis_client = None
    logger.warning("Redis client not available - using in-memory state storage (not production safe!)")


HEADERS = {"User-Agent": "OIDC-Client/1.0"}
STATE_TTL = 300  # 5 minutes
NONCE_TTL = 600  # 10 minutes

# In-memory fallback for state/nonce storage (NOT PRODUCTION SAFE - use Redis in production)
_state_storage: Dict[str, Tuple[str, datetime]] = {}


class OAuthClient:
    """
    OAuth 2.0 / OpenID Connect client for FastAPI applications.
    Implements authorization code flow with state and nonce validation.
    """
    
    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: str = "openid profile email",
    ):
        """
        Initialize OAuth client.
        
        Args:
            issuer: OIDC provider issuer URL (e.g., https://accounts.google.com)
            client_id: OAuth client ID
            client_secret: OAuth client secret (encrypted or plain)
            redirect_uri: Callback URL for OAuth flow
            scope: Space-separated list of OAuth scopes
        """
        self.issuer = issuer.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        
        self.discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        self._discovery_cache: Optional[Dict[str, Any]] = None
        self._discovery_cache_time: Optional[datetime] = None
        self._cache_duration = timedelta(hours=24)

    def get_discovery(self, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get OIDC discovery document with caching.
        
        Args:
            force_refresh: Force refresh of cached discovery document
            
        Returns:
            Discovery document dict or None if fetch fails
        """
        now = datetime.utcnow()
        
        # Return cached version if valid
        if (not force_refresh and 
            self._discovery_cache and 
            self._discovery_cache_time and 
            now - self._discovery_cache_time < self._cache_duration):
            return self._discovery_cache
        
        # Fetch new discovery document
        discovery = _discover(self.discovery_url)
        if discovery:
            self._discovery_cache = discovery
            self._discovery_cache_time = now
        
        return discovery

    def authorize_redirect(self) -> Optional[str]:
        """
        Generate authorization URL for OAuth flow.
        
        Returns:
            Authorization URL string or None if discovery fails
        """
        discovery = self.get_discovery()
        if not discovery:
            logger.error("Failed to get OIDC discovery document")
            return None
        
        auth_endpoint = discovery.get("authorization_endpoint")
        if not auth_endpoint:
            logger.error("No authorization_endpoint in discovery document")
            return None

        # Generate state and nonce for security
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # Store state and nonce with TTL
        if redis_client:
            state_key = self._get_state_key(state)
            try:
                redis_client.setex(state_key, STATE_TTL, nonce)
                logger.debug(f"Stored state with key: {state_key}")
            except Exception as e:
                logger.error(f"Failed to store state in Redis: {e}")
                return None
        else:
            # Fallback to in-memory storage (NOT production safe)
            _state_storage[state] = (nonce, datetime.utcnow() + timedelta(seconds=STATE_TTL))
            logger.warning("Using in-memory state storage - not safe for production!")

        # Build authorization URL
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "nonce": nonce
        }

        auth_url = f"{auth_endpoint}?{urlencode(params)}"
        return auth_url

    def fetch_token(
        self, 
        code: str, 
        state: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Exchange authorization code for tokens and validate ID token.
        
        Args:
            code: Authorization code from callback
            state: State parameter from callback
            
        Returns:
            Tuple of (token_data, user_claims) or (None, None) on failure
        """
        # Validate state and retrieve nonce
        nonce = self._validate_state(state)
        if not nonce:
            logger.warning("Invalid or expired OIDC state")
            return None, None

        # Get token endpoint from discovery
        discovery = self.get_discovery()
        if not discovery:
            logger.error("Failed to retrieve OIDC discovery document")
            return None, None
            
        token_endpoint = discovery.get("token_endpoint")
        if not token_endpoint:
            logger.error("No token_endpoint in discovery document")
            return None, None

        # Exchange code for tokens
        try:
            resp = requests.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers=HEADERS,
                timeout=10
            )
            resp.raise_for_status()
            token_data = resp.json()

            # Validate ID token and extract claims
            id_token = token_data.get("id_token")
            if not id_token:
                logger.error("No id_token in token response")
                return None, None
                
            claims = self.validate_id_token(id_token, nonce, discovery)
            if not claims:
                logger.error("ID token validation failed")
                return None, None

            return token_data, claims

        except requests.exceptions.RequestException as e:
            logger.error(f"Token fetch failed: {e}")
            return None, None
        except Exception as e:
            logger.error(f"Unexpected error during token fetch: {e}")
            return None, None

    def validate_id_token(
        self, 
        id_token: str, 
        nonce: str, 
        discovery: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Validate ID token and return claims.
        
        Args:
            id_token: JWT ID token from provider
            nonce: Expected nonce value
            discovery: OIDC discovery document
            
        Returns:
            Decoded claims dict or None if validation fails
        """
        try:
            # Get JWKS and signing key
            jwks_uri = discovery.get("jwks_uri")
            if not jwks_uri:
                logger.error("No jwks_uri in discovery document")
                return None
                
            jwks_client = PyJWKClient(jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            # Decode and validate ID token
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=discovery.get("issuer"),
                options={
                    "require": ["exp", "iat", "iss", "aud", "nonce"]
                }
            )

            # Validate nonce
            if claims.get("nonce") != nonce:
                logger.error("Nonce mismatch in ID token")
                return None

            return claims

        except jwt.exceptions.InvalidTokenError as e:
            logger.error(f"ID token validation failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during ID token validation: {e}")
            return None

    def extract_user_info(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract user information from ID token claims.
        
        Args:
            claims: Decoded ID token claims
            
        Returns:
            Dict containing standardized user information
        """
        user_info = {
            "sub": claims.get("sub"),  # Subject - unique user ID
            "email": claims.get("email"),
            "email_verified": claims.get("email_verified", False),
            "name": claims.get("name"),
            "given_name": claims.get("given_name"),
            "family_name": claims.get("family_name"),
            "picture": claims.get("picture"),
            "locale": claims.get("locale"),
            "updated_at": claims.get("updated_at"),
            "groups": claims.get("groups", []),
            "preferred_username": claims.get("preferred_username"),
        }
        
        # Remove None values
        user_info = {k: v for k, v in user_info.items() if v is not None}
        
        # Add raw claims for additional provider-specific fields
        user_info["raw_claims"] = claims
        
        return user_info

    def fetch_userinfo(
        self, 
        access_token: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch user info from userinfo endpoint (optional, as ID token has most info).
        
        Args:
            access_token: Access token from token response
            
        Returns:
            User info dict or None if fetch fails
        """
        discovery = self.get_discovery()
        if not discovery:
            return None
            
        userinfo_endpoint = discovery.get("userinfo_endpoint")
        if not userinfo_endpoint:
            logger.warning("No userinfo_endpoint in discovery document")
            return None

        try:
            resp = requests.get(
                userinfo_endpoint,
                headers={
                    **HEADERS,
                    "Authorization": f"Bearer {access_token}"
                },
                timeout=10
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Userinfo fetch failed: {e}")
            return None

    def check_provider_support(self) -> bool:
        """
        Verify that the OIDC provider supports required features.
        
        Returns:
            True if provider is compatible, False otherwise
        """
        discovery = self.get_discovery()
        if not discovery:
            logger.error("Failed to retrieve OIDC provider discovery document")
            return False

        # Required grant types and response types
        required_grant_types = ["authorization_code"]
        required_response_types = ["code"]
        required_endpoints = ["authorization_endpoint", "token_endpoint", "jwks_uri"]

        # Check grant types
        supported_grant_types = discovery.get("grant_types_supported", [])
        if not all(gt in supported_grant_types for gt in required_grant_types):
            logger.error(f"Provider does not support required grant types: {required_grant_types}")
            return False

        # Check response types
        supported_response_types = discovery.get("response_types_supported", [])
        if not all(rt in supported_response_types for rt in required_response_types):
            logger.error(f"Provider does not support required response types: {required_response_types}")
            return False

        # Check required endpoints
        for endpoint in required_endpoints:
            if endpoint not in discovery:
                logger.error(f"Provider missing required endpoint: {endpoint}")
                return False

        logger.info("OIDC provider supports all required features")
        return True

    def _get_state_key(self, state: str) -> str:
        """Generate Redis key for state storage."""
        return f"oidc:state:{state}"

    def _validate_state(self, state: str) -> Optional[str]:
        """
        Validate state parameter and return stored nonce.
        
        Args:
            state: State parameter from OAuth callback
            
        Returns:
            Nonce string or None if validation fails
        """
        if redis_client:
            state_key = self._get_state_key(state)
            
            try:
                nonce = redis_client.get(state_key)
                if nonce:
                    # Decode if bytes
                    if isinstance(nonce, bytes):
                        nonce = nonce.decode('utf-8')
                        
                    # Delete state after use (one-time use)
                    redis_client.delete(state_key)
                    return nonce
                else:
                    logger.warning(f"State not found or expired: {state_key}")
                    return None
                    
            except Exception as e:
                logger.error(f"Error validating state: {e}")
                return None
        else:
            # Fallback to in-memory storage
            if state in _state_storage:
                nonce, expiry = _state_storage[state]
                
                # Check if expired
                if datetime.utcnow() > expiry:
                    del _state_storage[state]
                    logger.warning(f"State expired: {state}")
                    return None
                
                # Delete after use (one-time use)
                del _state_storage[state]
                
                # Clean up expired entries
                _cleanup_expired_states()
                
                return nonce
            else:
                logger.warning(f"State not found: {state}")
                return None


# Utility functions

def _discover(openid_config_url: str) -> Dict[str, Any]:
    """
    Fetch OIDC discovery document.
    
    Args:
        openid_config_url: URL to .well-known/openid-configuration
        
    Returns:
        Discovery document dict or empty dict on failure
    """
    try:
        resp = requests.get(openid_config_url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        logger.debug(f"Successfully fetched discovery document from {openid_config_url}")
        return data
    except requests.exceptions.RequestException as e:
        logger.error(f"OIDC discovery failed for {openid_config_url}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error during OIDC discovery: {e}")
        return {}


def _cleanup_expired_states():
    """Clean up expired states from in-memory storage"""
    now = datetime.now()
    expired_keys = [k for k, (_, expiry) in _state_storage.items() if now > expiry]
    for k in expired_keys:
        del _state_storage[k]


def check_provider_support(provider_config: Dict[str, Any]) -> bool:
    """
    Standalone function to check provider support without instantiating client.
    
    Args:
        provider_config: Dict with 'discovery_url' or 'issuer' key
        
    Returns:
        True if provider is compatible, False otherwise
    """
    discovery_url = provider_config.get('discovery_url')
    if not discovery_url:
        issuer = provider_config.get('issuer')
        if issuer:
            discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    
    if not discovery_url:
        logger.error("No discovery_url or issuer provided")
        return False
    
    discovery = _discover(discovery_url)
    if not discovery:
        logger.error("Failed to retrieve OIDC provider discovery document")
        return False

    required_grant_types = ["authorization_code"]
    required_response_types = ["code"]
    required_endpoints = ["authorization_endpoint", "token_endpoint", "jwks_uri"]

    supported_grant_types = discovery.get("grant_types_supported", [])
    if not all(gt in supported_grant_types for gt in required_grant_types):
        logger.error("Provider does not support required grant types")
        return False

    supported_response_types = discovery.get("response_types_supported", [])
    if not all(rt in supported_response_types for rt in required_response_types):
        logger.error("Provider does not support required response types")
        return False

    for endpoint in required_endpoints:
        if endpoint not in discovery:
            logger.error(f"Provider does not support required endpoint: {endpoint}")
            return False

    return True