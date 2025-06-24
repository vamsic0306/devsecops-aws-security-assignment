"""
AWS Configuration and Common Settings
"""
import boto3
from typing import Optional
import logging

class AWSConfig:
    """AWS Configuration and session management"""
    
    def __init__(self, region: str = 'us-east-1', profile: Optional[str] = None):
        self.region = region
        self.profile = profile
        self.session = self._create_session()
        
    def _create_session(self) -> boto3.Session:
        """Create and return AWS session"""
        try:
            if self.profile:
                session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                session = boto3.Session(region_name=self.region)
            
            # Test the session
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            logging.info(f"Connected to AWS as: {identity.get('Arn', 'Unknown')}")
            
            return session
        except Exception as e:
            logging.error(f"Failed to create AWS session: {str(e)}")
            raise
    
    def get_client(self, service: str):
        """Get AWS service client"""
        return self.session.client(service, region_name=self.region)
    
    def get_resource(self, service: str):
        """Get AWS service resource"""
        return self.session.resource(service, region_name=self.region)

# Default regions for multi-region operations
DEFAULT_REGIONS = [
    'us-east-1', 'us-west-2', 'eu-west-1', 
    'ap-southeast-1', 'ap-northeast-1'
]