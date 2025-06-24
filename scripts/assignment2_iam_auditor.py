#!/usr/bin/env python3
"""
Assignment 2: IAM Security Compliance Auditor
Author: Vamsi
Description: Detect inactive or risky IAM accounts
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from tabulate import tabulate
from config.aws_config import AWSConfig
from utils.common import setup_logging, save_to_json, days_between, validate_aws_response

class IAMAuditor:
    """IAM Security Compliance Auditor"""
    
    def __init__(self, aws_config: AWSConfig):
        self.aws_config = aws_config
        self.iam = aws_config.get_client('iam')
        self.logger = logging.getLogger(__name__)
    
    def get_all_users(self) -> List[Dict]:
        """Get all IAM users"""
        try:
            users = []
            paginator = self.iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                if validate_aws_response(page):
                    users.extend(page.get('Users', []))
            
            self.logger.info(f"Retrieved {len(users)} IAM users")
            return users
            
        except Exception as e:
            self.logger.error(f"Error retrieving IAM users: {str(e)}")
            return []
    
    def check_user_mfa(self, username: str) -> bool:
        """Check if user has MFA enabled"""
        try:
            response = self.iam.list_mfa_devices(UserName=username)
            
            if not validate_aws_response(response):
                return False
            
            mfa_devices = response.get('MFADevices', [])
            return len(mfa_devices) > 0
            
        except Exception as e:
            self.logger.debug(f"Error checking MFA for user {username}: {str(e)}")
            return False
    
    def get_user_access_keys(self, username: str) -> List[Dict]:
        """Get user access keys with age information"""
        try:
            response = self.iam.list_access_keys(UserName=username)
            
            if not validate_aws_response(response):
                return []
            
            access_keys = []
            for key_metadata in response.get('AccessKeyMetadata', []):
                key_age = days_between(key_metadata.get('CreateDate'))
                access_keys.append({
                    'access_key_id': key_metadata.get('AccessKeyId'),
                    'status': key_metadata.get('Status'),
                    'create_date': key_metadata.get('CreateDate'),
                    'age_days': key_age
                })
            
            return access_keys
            
        except Exception as e:
            self.logger.debug(f"Error getting access keys for user {username}: {str(e)}")
            return []
    
    def get_user_last_activity(self, username: str) -> Dict:
        """Get user's last activity information"""
        try:
            response = self.iam.get_user(UserName=username)
            
            if not validate_aws_response(response):
                return {}
            
            user_info = response.get('User', {})
            
            # Get password last used
            password_last_used = user_info.get('PasswordLastUsed')
            
            # Get access key last used (this requires additional API calls)
            access_keys = self.get_user_access_keys(username)
            last_access_key_used = None
            
            for key in access_keys:
                try:
                    key_response = self.iam.get_access_key_last_used(
                        AccessKeyId=key['access_key_id']
                    )
                    
                    if validate_aws_response(key_response):
                        last_used_info = key_response.get('AccessKeyLastUsed', {})
                        last_used_date = last_used_info.get('LastUsedDate')
                        
                        if last_used_date:
                            if not last_access_key_used or last_used_date > last_access_key_used:
                                last_access_key_used = last_used_date
                                
                except Exception as e:
                    self.logger.debug(f"Error getting last used for key {key['access_key_id']}: {str(e)}")
            
            # Determine the most recent activity
            last_activity = None
            activity_type = "Never"
            
            if password_last_used and last_access_key_used:
                last_activity = max(password_last_used, last_access_key_used)
                activity_type = "Console/API"
            elif password_last_used:
                last_activity = password_last_used
                activity_type = "Console"
            elif last_access_key_used:
                last_activity = last_access_key_used
                activity_type = "API"
            
            return {
                'last_activity': last_activity,
                'activity_type': activity_type,
                'days_since_last_activity': days_between(last_activity) if last_activity else None
            }
            
        except Exception as e:
            self.logger.debug(f"Error getting last activity for user {username}: {str(e)}")
            return {}
    
    def audit_users(self, inactive_days: int = 90, old_key_days: int = 90) -> Dict:
        """Perform comprehensive IAM user audit"""
        
        users = self.get_all_users()
        audit_results = {
            'total_users': len(users),
            'users_without_mfa': [],
            'users_with_old_keys': [],
            'inactive_users': [],
            'compliant_users': [],
            'audit_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        self.logger.info(f"Starting audit of {len(users)} users...")
        
        for user in users:
            username = user.get('UserName')
            user_created = user.get('CreateDate')
            
            self.logger.debug(f"Auditing user: {username}")
            
            # Check MFA
            has_mfa = self.check_user_mfa(username)
            
            # Check access keys
            access_keys = self.get_user_access_keys(username)
            old_keys = [key for key in access_keys if key['age_days'] > old_key_days]
            
            # Check last activity
            activity_info = self.get_user_last_activity(username)
            days_inactive = activity_info.get('days_since_last_activity')
            
            # Prepare user audit data
            user_audit = {
                'username': username,
                'created_date': user_created,
                'has_mfa': has_mfa,
                'access_keys_count': len(access_keys),
                'old_keys_count': len(old_keys),
                'last_activity': activity_info.get('last_activity'),
                'activity_type': activity_info.get('activity_type'),
                'days_inactive': days_inactive,
                'violations': []
            }
            
            # Identify violations
            if not has_mfa:
                user_audit['violations'].append('No MFA')
                audit_results['users_without_mfa'].append(user_audit.copy())
            
            if old_keys:
                user_audit['violations'].append(f'{len(old_keys)} old access keys')
                audit_results['users_with_old_keys'].append(user_audit.copy())
            
            if days_inactive is not None and days_inactive > inactive_days:
                user_audit['violations'].append(f'Inactive for {days_inactive} days')
                audit_results['inactive_users'].append(user_audit.copy())
            elif days_inactive is None:
                user_audit['violations'].append('Never used')
                audit_results['inactive_users'].append(user_audit.copy())
            
            if not user_audit['violations']:
                audit_results['compliant_users'].append(user_audit)
        
        return audit_results
    
    def generate_report(self, audit_results: Dict, format_type: str = 'table') -> str:
        """Generate audit report"""
        
        report_lines = []
        report_lines.append("IAM Security Audit Report")
        report_lines.append("=" * 50)
        report_lines.append(f"Audit Date: {audit_results['audit_timestamp']}")
        report_lines.append(f"Total Users: {audit_results['total_users']}")
        report_lines.append("")
        
        # Summary
        report_lines.append("SUMMARY:")
        report_lines.append(f"  Users without MFA: {len(audit_results['users_without_mfa'])}")
        report_lines.append(f"  Users with old access keys: {len(audit_results['users_with_old_keys'])}")
        report_lines.append(f"  Inactive users: {len(audit_results['inactive_users'])}")
        report_lines.append(f"  Compliant users: {len(audit_results['compliant_users'])}")
        report_lines.append("")
        
        if format_type == 'table':
            # Detailed tables for each violation type
            if audit_results['users_without_mfa']:
                report_lines.append("USERS WITHOUT MFA:")
                table_data = []
                for user in audit_results['users_without_mfa']:
                    table_data.append([
                        user['username'],
                        user['created_date'].strftime('%Y-%m-%d') if user['created_date'] else 'N/A',
                        user['days_inactive'] or 'Never used'
                    ])
                
                report_lines.append(tabulate(
                    table_data,
                    headers=['Username', 'Created Date', 'Days Inactive'],
                    tablefmt='grid'
                ))
                report_lines.append("")
            
            if audit_results['users_with_old_keys']:
                report_lines.append("USERS WITH OLD ACCESS KEYS:")
                table_data = []
                for user in audit_results['users_with_old_keys']:
                    table_data.append([
                        user['username'],
                        user['old_keys_count'],
                        user['access_keys_count'],
                        user['days_inactive'] or 'Never used'
                    ])
                
                report_lines.append(tabulate(
                    table_data,
                    headers=['Username', 'Old Keys', 'Total Keys', 'Days Inactive'],
                    tablefmt='grid'
                ))
                report_lines.append("")
            
            if audit_results['inactive_users']:
                report_lines.append("INACTIVE USERS:")
                table_data = []
                for user in audit_results['inactive_users']:
                    table_data.append([
                        user['username'],
                        user['activity_type'],
                        user['days_inactive'] or 'Never',
                        ', '.join(user['violations'])
                    ])
                
                report_lines.append(tabulate(
                    table_data,
                    headers=['Username', 'Last Activity Type', 'Days Inactive', 'Violations'],
                    tablefmt='grid'
                ))
        
        return '\n'.join(report_lines)

@click.command()
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--profile', help='AWS profile name')
@click.option('--inactive-days', default=90, help='Days to consider user inactive')
@click.option('--old-key-days', default=90, help='Days to consider access key old')
@click.option('--format', 'output_format', default='table', 
              type=click.Choice(['table', 'json']), help='Output format')
@click.option('--log-level', default='INFO', help='Logging level')
def main(region: str, profile: str, inactive_days: int, old_key_days: int, 
         output_format: str, log_level: str):
    """Main function for IAM security audit"""
    
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting IAM Security Audit")
        
        # Initialize AWS configuration
        aws_config = AWSConfig(region=region, profile=profile)
        iam_auditor = IAMAuditor(aws_config)
        
        # Perform audit
        audit_results = iam_auditor.audit_users(inactive_days, old_key_days)
        
        # Generate and display report
        if output_format == 'table':
            report = iam_auditor.generate_report(audit_results, 'table')
            print(report)
        else:
            # Save as JSON
            filename = f"iam_audit_report_{region}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_to_json(audit_results, filename)
            print(f"Audit results saved to /tmp/{filename}")
        
        # Print quick summary
        print(f"\nQuick Summary:")
        print(f"🔴 Critical Issues: {len(audit_results['users_without_mfa']) + len(audit_results['inactive_users'])}")
        print(f"🟡 Warning Issues: {len(audit_results['users_with_old_keys'])}")
        print(f"🟢 Compliant Users: {len(audit_results['compliant_users'])}")
        
        logger.info("IAM audit completed successfully")
        
    except Exception as e:
        logger.error(f"IAM audit failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()