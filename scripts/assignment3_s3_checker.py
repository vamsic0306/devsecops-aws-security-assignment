#!/usr/bin/env python3
"""
Assignment 3: S3 Bucket Policy & Encryption Checker
Author: Vamsi
Description: Validate S3 security best practices
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
import logging
from datetime import datetime
from typing import List, Dict, Any
from config.aws_config import AWSConfig
from utils.common import setup_logging, save_to_json, save_to_csv, validate_aws_response, SecurityViolation

class S3SecurityChecker:
    """S3 Security Compliance Checker"""
    
    def __init__(self, aws_config: AWSConfig):
        self.aws_config = aws_config
        self.s3_client = aws_config.get_client('s3')
        self.s3_resource = aws_config.get_resource('s3')
        self.logger = logging.getLogger(__name__)
    
    def get_all_buckets(self) -> List[Dict]:
        """Get all S3 buckets"""
        try:
            response = self.s3_client.list_buckets()
            
            if not validate_aws_response(response):
                raise Exception("Failed to list S3 buckets")
            
            buckets = response.get('Buckets', [])
            self.logger.info(f"Found {len(buckets)} S3 buckets")
            return buckets
            
        except Exception as e:
            self.logger.error(f"Error listing S3 buckets: {str(e)}")
            return []
    
    def check_bucket_public_access(self, bucket_name: str) -> Dict:
        """Check bucket public access settings"""
        try:
            # Check public access block
            try:
                response = self.s3_client.get_public_access_block(Bucket=bucket_name)
                public_access_block = response.get('PublicAccessBlockConfiguration', {})
            except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                public_access_block = {}
            except Exception:
                public_access_block = {}
            
            # Check bucket ACL
            try:
                acl_response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                grants = acl_response.get('Grants', [])
                
                public_read = False
                public_write = False
                
                for grant in grants:
                    grantee = grant.get('Grantee', {})
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        permission = grant.get('Permission', '')
                        
                        if 'AllUsers' in uri:
                            if permission in ['READ', 'FULL_CONTROL']:
                                public_read = True
                            if permission in ['WRITE', 'FULL_CONTROL']:
                                public_write = True
                
                acl_info = {
                    'public_read': public_read,
                    'public_write': public_write
                }
                
            except Exception as e:
                self.logger.debug(f"Error checking ACL for {bucket_name}: {str(e)}")
                acl_info = {'public_read': False, 'public_write': False}
            
            # Check bucket policy for public access
            bucket_policy_public = False
            try:
                policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = policy_response.get('Policy', '')
                
                # Simple check for common public policy patterns
                if '"Principal": "*"' in policy or '"Principal":"*"' in policy:
                    bucket_policy_public = True
                    
            except self.s3_client.exceptions.NoSuchBucketPolicy:
                pass
            except Exception as e:
                self.logger.debug(f"Error checking bucket policy for {bucket_name}: {str(e)}")
            
            return {
                'block_public_acls': public_access_block.get('BlockPublicAcls', False),
                'ignore_public_acls': public_access_block.get('IgnorePublicAcls', False),
                'block_public_policy': public_access_block.get('BlockPublicPolicy', False),
                'restrict_public_buckets': public_access_block.get('RestrictPublicBuckets', False),
                'acl_public_read': acl_info['public_read'],
                'acl_public_write': acl_info['public_write'],
                'policy_public': bucket_policy_public,
                'is_public': (
                    acl_info['public_read'] or 
                    acl_info['public_write'] or 
                    bucket_policy_public or
                    not all([
                        public_access_block.get('BlockPublicAcls', False),
                        public_access_block.get('IgnorePublicAcls', False),
                        public_access_block.get('BlockPublicPolicy', False),
                        public_access_block.get('RestrictPublicBuckets', False)
                    ])
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error checking public access for bucket {bucket_name}: {str(e)}")
            return {'is_public': True, 'error': str(e)}  # Assume public on error for safety
    
    def check_bucket_encryption(self, bucket_name: str) -> Dict:
        """Check bucket encryption settings"""
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            
            if not validate_aws_response(response):
                return {'encrypted': False, 'error': 'Invalid API response'}
            
            encryption_config = response.get('ServerSideEncryptionConfiguration', {})
            rules = encryption_config.get('Rules', [])
            
            if rules:
                rule = rules[0]  # Take first rule
                sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                kms_key_id = rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
                
                return {
                    'encrypted': True,
                    'algorithm': sse_algorithm,
                    'kms_key_id': kms_key_id,
                    'bucket_key_enabled': rule.get('BucketKeyEnabled', False)
                }
            else:
                return {'encrypted': False}
                
        except self.s3_client.exceptions.NoSuchBucket:
            return {'encrypted': False, 'error': 'Bucket does not exist'}
        except Exception as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                return {'encrypted': False}
            else:
                self.logger.debug(f"Error checking encryption for {bucket_name}: {str(e)}")
                return {'encrypted': False, 'error': str(e)}
    
    def check_bucket_versioning(self, bucket_name: str) -> Dict:
        """Check bucket versioning settings"""
        try:
            response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            
            if not validate_aws_response(response):
                return {'versioning_enabled': False, 'error': 'Invalid API response'}
            
            status = response.get('Status', 'Disabled')
            mfa_delete = response.get('MfaDelete', 'Disabled')
            
            return {
                'versioning_enabled': status == 'Enabled',
                'versioning_status': status,
                'mfa_delete': mfa_delete == 'Enabled'
            }
            
        except Exception as e:
            self.logger.debug(f"Error checking versioning for {bucket_name}: {str(e)}")
            return {'versioning_enabled': False, 'error': str(e)}
    
    def check_bucket_logging(self, bucket_name: str) -> Dict:
        """Check bucket access logging"""
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            
            if not validate_aws_response(response):
                return {'logging_enabled': False, 'error': 'Invalid API response'}
            
            logging_config = response.get('LoggingEnabled', {})
            
            if logging_config:
                return {
                    'logging_enabled': True,
                    'target_bucket': logging_config.get('TargetBucket'),
                    'target_prefix': logging_config.get('TargetPrefix')
                }
            else:
                return {'logging_enabled': False}
                
        except Exception as e:
            self.logger.debug(f"Error checking logging for {bucket_name}: {str(e)}")
            return {'logging_enabled': False, 'error': str(e)}
    
    def audit_bucket(self, bucket_name: str) -> Dict:
        """Perform comprehensive bucket audit"""
        
        self.logger.debug(f"Auditing bucket: {bucket_name}")
        
        # Get bucket location
        try:
            location_response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            region = location_response.get('LocationConstraint') or 'us-east-1'
        except Exception:
            region = 'unknown'
        
        # Perform all checks
        public_access = self.check_bucket_public_access(bucket_name)
        encryption = self.check_bucket_encryption(bucket_name)
        versioning = self.check_bucket_versioning(bucket_name)
        logging = self.check_bucket_logging(bucket_name)
        
        # Identify violations
        violations = []
        
        if public_access.get('is_public', False):
            violations.append(SecurityViolation(
                'S3 Bucket', bucket_name, 'Public Access', 'HIGH',
                'Bucket allows public access'
            ))
        
        if not encryption.get('encrypted', False):
            violations.append(SecurityViolation(
                'S3 Bucket', bucket_name, 'No Encryption', 'HIGH',
                'Bucket does not have server-side encryption enabled'
            ))
        
        if not versioning.get('versioning_enabled', False):
            violations.append(SecurityViolation(
                'S3 Bucket', bucket_name, 'No Versioning', 'MEDIUM',
                'Bucket does not have versioning enabled'
            ))
        
        if not logging.get('logging_enabled', False):
            violations.append(SecurityViolation(
                'S3 Bucket', bucket_name, 'No Access Logging', 'LOW',
                'Bucket does not have access logging enabled'
            ))
        
        return {
            'bucket_name': bucket_name,
            'region': region,
            'public_access': public_access,
            'encryption': encryption,
            'versioning': versioning,
            'logging': logging,
            'violations': [v.to_dict() for v in violations],
            'compliance_score': max(0, 100 - (len(violations) * 25))
        }
    
    def audit_all_buckets(self) -> Dict:
        """Audit all S3 buckets"""
        
        buckets = self.get_all_buckets()
        audit_results = {
            'total_buckets': len(buckets),
            'audit_timestamp': datetime.now().isoformat(),
            'bucket_audits': [],
            'violations_summary': {
                'public_buckets': 0,
                'unencrypted_buckets': 0,
                'no_versioning': 0,
                'no_logging': 0
            },
            'total_violations': 0
        }
        
        self.logger.info(f"Starting audit of {len(buckets)} S3 buckets...")
        
        for bucket in buckets:
            bucket_name = bucket.get('Name')
            bucket_audit = self.audit_bucket(bucket_name)
            audit_results['bucket_audits'].append(bucket_audit)
            
            # Update summary
            for violation in bucket_audit['violations']:
                audit_results['total_violations'] += 1
                violation_type = violation['violation_type']
                
                if 'Public Access' in violation_type:
                    audit_results['violations_summary']['public_buckets'] += 1
                elif 'No Encryption' in violation_type:
                    audit_results['violations_summary']['unencrypted_buckets'] += 1
                elif 'No Versioning' in violation_type:
                    audit_results['violations_summary']['no_versioning'] += 1
                elif 'No Access Logging' in violation_type:
                    audit_results['violations_summary']['no_logging'] += 1
        
        return audit_results
    
    def generate_csv_report(self, audit_results: Dict) -> List[Dict]:
        """Generate CSV-friendly report data"""
        
        csv_data = []
        
        for bucket_audit in audit_results['bucket_audits']:
            row = {
                'bucket_name': bucket_audit['bucket_name'],
                'region': bucket_audit['region'],
                'is_public': bucket_audit['public_access'].get('is_public', False),
                'encrypted': bucket_audit['encryption'].get('encrypted', False),
                'encryption_algorithm': bucket_audit['encryption'].get('algorithm', 'None'),
                'versioning_enabled': bucket_audit['versioning'].get('versioning_enabled', False),
                'logging_enabled': bucket_audit['logging'].get('logging_enabled', False),
                'violation_count': len(bucket_audit['violations']),
                'compliance_score': bucket_audit['compliance_score'],
                'violations': '; '.join([v['violation_type'] for v in bucket_audit['violations']])
            }
            csv_data.append(row)
        
        return csv_data

@click.command()
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--profile', help='AWS profile name')
@click.option('--output-format', default='json', 
              type=click.Choice(['json', 'csv', 'both']), help='Output format')
@click.option('--log-level', default='INFO', help='Logging level')
def main(region: str, profile: str, output_format: str, log_level: str):
    """Main function for S3 security audit"""
    
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting S3 Security Audit")
        
        # Initialize AWS configuration
        aws_config = AWSConfig(region=region, profile=profile)
        s3_checker = S3SecurityChecker(aws_config)
        
        # Perform audit
        audit_results = s3_checker.audit_all_buckets()
        
        # Generate timestamp for files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save results based on format
        if output_format in ['json', 'both']:
            json_filename = f"s3_security_audit_{timestamp}.json"
            save_to_json(audit_results, json_filename)
            print(f"JSON report saved to /tmp/{json_filename}")
        
        if output_format in ['csv', 'both']:
            csv_data = s3_checker.generate_csv_report(audit_results)
            csv_filename = f"s3_security_audit_{timestamp}.csv"
            save_to_csv(csv_data, csv_filename)
            print(f"CSV report saved to /tmp/{csv_filename}")
        
        # Print summary
        print(f"\nS3 Security Audit Summary:")
        print(f"=" * 40)
        print(f"Total Buckets: {audit_results['total_buckets']}")
        print(f"Total Violations: {audit_results['total_violations']}")
        print(f"")
        print(f"Violation Breakdown:")
        print(f"  🔴 Public Buckets: {audit_results['violations_summary']['public_buckets']}")
        print(f"  🔴 Unencrypted Buckets: {audit_results['violations_summary']['unencrypted_buckets']}")
        print(f"  🟡 No Versioning: {audit_results['violations_summary']['no_versioning']}")
        print(f"  🟡 No Logging: {audit_results['violations_summary']['no_logging']}")
        
        # Show top violators
        violating_buckets = [b for b in audit_results['bucket_audits'] if b['violations']]
        if violating_buckets:
            print(f"\nTop Security Issues:")
            for bucket in sorted(violating_buckets, key=lambda x: len(x['violations']), reverse=True)[:5]:
                print(f"  {bucket['bucket_name']}: {len(bucket['violations'])} violations")
        
        logger.info("S3 security audit completed successfully")
        
    except Exception as e:
        logger.error(f"S3 security audit failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()