#!/usr/bin/env python3

"""
A script to fetch tweets from a specific Twitter username using the twikit library.
This script provides functionality to retrieve and display tweets from a given user's timeline.
"""

from typing import List, Optional
from dataclasses import dataclass
import sys
import argparse
import asyncio
from twikit import Client

@dataclass
class Tweet:
    """Represents a simplified tweet object with essential information."""
    id: str
    text: str
    created_at: str
    retweet_count: int
    like_count: int

async def fetch_user_tweets(username: str, limit: Optional[int] = None) -> List[Tweet]:
    """
    Fetch tweets from a specific Twitter username.

    Args:
        username: The Twitter username (without '@' symbol)
        limit: Maximum number of tweets to fetch (None for all available)

    Returns:
        List of Tweet objects containing the user's tweets

    Raises:
        Exception: If there's an error accessing the Twitter API
    """
    client = Client('en-US')  # Initialize client with English locale
    tweets = []
    
    try:
        # Fetch user's timeline
        timeline = await client.get_user_tweets(username, "Tweets")
        
        # Process tweets up to the limit if specified
        for tweet in timeline:
            tweet_obj = Tweet(
                id=tweet.id,
                text=tweet.text,
                created_at=str(tweet.created_at),
                retweet_count=tweet.retweet_count,
                like_count=tweet.like_count
            )
            tweets.append(tweet_obj)
            
            # Break if we've reached the limit
            if limit and len(tweets) >= limit:
                break
            
        return tweets[:limit] if limit else tweets
    
    except Exception as e:
        print(f"Error fetching tweets: {str(e)}", file=sys.stderr)
        raise

def display_tweets(tweets: List[Tweet]) -> None:
    """
    Display tweets in a formatted manner.

    Args:
        tweets: List of Tweet objects to display
    """
    for tweet in tweets:
        print(f"\n{'='*80}")
        print(f"Tweet ID: {tweet.id}")
        print(f"Created at: {tweet.created_at}")
        print(f"Text: {tweet.text}")
        print(f"Retweets: {tweet.retweet_count}")
        print(f"Likes: {tweet.like_count}")

async def main() -> None:
    """Main function to handle command line arguments and execute the tweet fetching."""
    parser = argparse.ArgumentParser(description="Fetch tweets from a specific Twitter username")
    parser.add_argument("username", nargs='?', default="kanyewest", help="Twitter username (without '@' symbol)")
    parser.add_argument("--limit", type=int, help="Maximum number of tweets to fetch", default=10)
    
    args = parser.parse_args()
    
    try:
        tweets = await fetch_user_tweets(args.username, args.limit)
        display_tweets(tweets)
        print(f"\nSuccessfully fetched {len(tweets)} tweets from @{args.username}")
    
    except Exception as e:
        print(f"Failed to fetch tweets: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 