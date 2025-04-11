import logging
from typing import Dict, Any, List, Optional, Union, Tuple
import json
import aioredis
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class RedisClient:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None

    async def initialize(self):
        """Initialize Redis connection."""
        try:
            self.client = aioredis.from_url(
                f"redis://{self.config['host']}:{self.config['port']}",
                password=self.config.get("password"),
                db=self.config.get("db", 0),
                encoding="utf-8",
                decode_responses=True
            )
            
            # Test connection
            await self.client.ping()
        except Exception as e:
            logger.error(f"Error initializing Redis: {str(e)}")
            raise

    async def close(self):
        """Close Redis connection."""
        if self.client:
            await self.client.close()

    # Cache Operations
    async def set(
        self,
        key: str,
        value: Union[str, Dict, List],
        expire: Optional[int] = None
    ):
        """Set a key with optional expiration."""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            
            await self.client.set(key, value)
            if expire:
                await self.client.expire(key, expire)
        except Exception as e:
            logger.error(f"Error setting Redis key {key}: {str(e)}")
            raise

    async def get(self, key: str) -> Optional[Union[str, Dict, List]]:
        """Get a value by key."""
        try:
            value = await self.client.get(key)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except Exception as e:
            logger.error(f"Error getting Redis key {key}: {str(e)}")
            raise

    async def delete(self, key: str):
        """Delete a key."""
        try:
            await self.client.delete(key)
        except Exception as e:
            logger.error(f"Error deleting Redis key {key}: {str(e)}")
            raise

    # List Operations
    async def lpush(self, key: str, value: Union[str, Dict, List]):
        """Push a value to the left of a list."""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.client.lpush(key, value)
        except Exception as e:
            logger.error(f"Error pushing to Redis list {key}: {str(e)}")
            raise

    async def rpush(self, key: str, value: Union[str, Dict, List]):
        """Push a value to the right of a list."""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.client.rpush(key, value)
        except Exception as e:
            logger.error(f"Error pushing to Redis list {key}: {str(e)}")
            raise

    async def lrange(self, key: str, start: int, end: int) -> List[Any]:
        """Get a range of values from a list."""
        try:
            values = await self.client.lrange(key, start, end)
            return [
                json.loads(value) if value.startswith(("{", "[")) else value
                for value in values
            ]
        except Exception as e:
            logger.error(f"Error getting range from Redis list {key}: {str(e)}")
            raise

    # Set Operations
    async def sadd(self, key: str, value: Union[str, Dict, List]):
        """Add a value to a set."""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.client.sadd(key, value)
        except Exception as e:
            logger.error(f"Error adding to Redis set {key}: {str(e)}")
            raise

    async def smembers(self, key: str) -> List[Any]:
        """Get all members of a set."""
        try:
            values = await self.client.smembers(key)
            return [
                json.loads(value) if value.startswith(("{", "[")) else value
                for value in values
            ]
        except Exception as e:
            logger.error(f"Error getting members from Redis set {key}: {str(e)}")
            raise

    # Hash Operations
    async def hset(self, key: str, field: str, value: Union[str, Dict, List]):
        """Set a field in a hash."""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.client.hset(key, field, value)
        except Exception as e:
            logger.error(f"Error setting Redis hash field {key}.{field}: {str(e)}")
            raise

    async def hget(self, key: str, field: str) -> Optional[Union[str, Dict, List]]:
        """Get a field from a hash."""
        try:
            value = await self.client.hget(key, field)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except Exception as e:
            logger.error(f"Error getting Redis hash field {key}.{field}: {str(e)}")
            raise

    async def hgetall(self, key: str) -> Dict[str, Any]:
        """Get all fields from a hash."""
        try:
            values = await self.client.hgetall(key)
            return {
                k: json.loads(v) if v.startswith(("{", "[")) else v
                for k, v in values.items()
            }
        except Exception as e:
            logger.error(f"Error getting all Redis hash fields {key}: {str(e)}")
            raise

    # Rate Limiting
    async def increment_counter(
        self,
        key: str,
        window_seconds: int,
        max_count: int
    ) -> Tuple[int, bool]:
        """
        Increment a rate limit counter and check if limit is exceeded.
        
        Returns:
            Tuple[int, bool]: (current count, whether limit is exceeded)
        """
        try:
            pipe = self.client.pipeline()
            now = datetime.utcnow().timestamp()
            
            # Remove old entries
            pipe.zremrangebyscore(
                key,
                "-inf",
                now - window_seconds
            )
            
            # Add new entry
            pipe.zadd(key, {str(now): now})
            
            # Get current count
            pipe.zcard(key)
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            results = await pipe.execute()
            current_count = results[2]
            
            return current_count, current_count > max_count
        except Exception as e:
            logger.error(f"Error incrementing rate limit counter {key}: {str(e)}")
            raise

    # Pub/Sub
    async def publish(self, channel: str, message: Union[str, Dict, List]):
        """Publish a message to a channel."""
        try:
            if isinstance(message, (dict, list)):
                message = json.dumps(message)
            await self.client.publish(channel, message)
        except Exception as e:
            logger.error(f"Error publishing to Redis channel {channel}: {str(e)}")
            raise

    async def subscribe(self, *channels: str):
        """Subscribe to one or more channels."""
        try:
            pubsub = self.client.pubsub()
            await pubsub.subscribe(*channels)
            return pubsub
        except Exception as e:
            logger.error(f"Error subscribing to Redis channels: {str(e)}")
            raise 