"""
Redis client for OAuth state storage
This is optional - the OAuth client will fall back to in-memory storage if Redis is not available
"""

import redis
import logging
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

redis_client: Optional[redis.Redis] = None

try:
    # Try to connect to Redis if REDIS_URL is configured
    redis_url = getattr(settings, 'REDIS_URL', None)
    
    if redis_url:
        redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        
        # Test connection
        redis_client.ping()
        logger.info("Redis client connected successfully")
    else:
        logger.info("REDIS_URL not configured - OAuth will use in-memory state storage")
        
except redis.ConnectionError as e:
    logger.warning(f"Could not connect to Redis: {e}. OAuth will use in-memory state storage")
    redis_client = None
except Exception as e:
    logger.warning(f"Redis client initialization failed: {e}. OAuth will use in-memory state storage")
    redis_client = None