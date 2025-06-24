#!/usr/bin/env python3
"""
Assignment 1: AWS GuardDuty Setup & Scan Script
Author: Vamsi
Description: Automate enabling GuardDuty and exporting findings
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
import logging
from typing import List, Dict, Any
from config.aws_config import AWSConfig
from utils.common import setup_logging, save_to_json, validate_aws_response

class GuardDutyManager:
    """Manage GuardDuty operations"""
    
    def __init__(self, aws_config: AWSConfig):
        self.aws_config = aws_config
        self.guardduty = aws_config.get_client('guardduty')
        self.logger = logging.getLogger(__name__)
    
    def check_guardduty_status(self) -> tuple[bool, str]:
        """Check if GuardDuty is enabled"""
        try:
            response = self.guardduty.list_detectors()
            
            if not validate_aws_response(response):
                raise Exception("Invalid API response")
            
            detectors = response.get('DetectorIds', [])
            
            if detectors:
                detector_id = detectors[0]
                detector_response = self.guardduty.get_detector(DetectorId=detector_id)
                
                if detector_response.get('Status') == 'ENABLED':
                    self.logger.info(f"GuardDuty is enabled with detector ID: {detector_id}")
                    return True, detector_id
                else:
                    self.logger.warning(f"GuardDuty detector exists but is disabled: {detector_id}")
                    return False, detector_id
            else:
                self.logger.info("No GuardDuty detectors found")
                return False, ""
                
        except Exception as e:
            self.logger.error(f"Error checking GuardDuty status: {str(e)}")
            return False, ""
    
    def enable_guardduty(self) -> str:
        """Enable GuardDuty"""
        try:
            response = self.guardduty.create_detector(
                Enable=True,
                FindingPublishingFrequency='FIFTEEN_MINUTES'
            )
            
            if not validate_aws_response(response):
                raise Exception("Failed to create GuardDuty detector")
            
            detector_id = response.get('DetectorId')
            self.logger.info(f"GuardDuty enabled successfully with detector ID: {detector_id}")
            return detector_id
            
        except Exception as e:
            self.logger.error(f"Failed to enable GuardDuty: {str(e)}")
            raise
    
    def get_findings(self, detector_id: str, max_results: int = 50) -> List[Dict]:
        """Get GuardDuty findings"""
        try:
            # Get finding IDs
            findings_response = self.guardduty.list_findings(
                DetectorId=detector_id,
                MaxResults=max_results
            )
            
            if not validate_aws_response(findings_response):
                raise Exception("Failed to list findings")
            
            finding_ids = findings_response.get('FindingIds', [])
            
            if not finding_ids:
                self.logger.info("No GuardDuty findings found")
                return []
            
            # Get detailed findings
            details_response = self.guardduty.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )
            
            if not validate_aws_response(details_response):
                raise Exception("Failed to get finding details")
            
            findings = details_response.get('Findings', [])
            self.logger.info(f"Retrieved {len(findings)} GuardDuty findings")
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error retrieving findings: {str(e)}")
            return []
    
    def process_findings(self, findings: List[Dict]) -> List[Dict]:
        """Process and format findings"""
        processed_findings = []
        
        for finding in findings:
            processed_finding = {
                'id': finding.get('Id'),
                'type': finding.get('Type'),
                'severity': finding.get('Severity'),
                'title': finding.get('Title'),
                'description': finding.get('Description'),
                'created_at': finding.get('CreatedAt'),
                'updated_at': finding.get('UpdatedAt'),
                'region': finding.get('Region'),
                'account_id': finding.get('AccountId'),
                'service': finding.get('Service', {}).get('ServiceName'),
                'resource_type': finding.get('Resource', {}).get('ResourceType'),
                'instance_id': finding.get('Resource', {}).get('InstanceDetails', {}).get('InstanceId'),
                'confidence': finding.get('Confidence')
            }
            processed_findings.append(processed_finding)
        
        return processed_findings

@click.command()
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--profile', help='AWS profile name')
@click.option('--max-findings', default=50, help='Maximum number of findings to retrieve')
@click.option('--log-level', default='INFO', help='Logging level')
def main(region: str, profile: str, max_findings: int, log_level: str):
    """Main function for GuardDuty automation"""
    
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting GuardDuty automation script")
        
        # Initialize AWS configuration
        aws_config = AWSConfig(region=region, profile=profile)
        guardduty_manager = GuardDutyManager(aws_config)
        
        # Check GuardDuty status
        is_enabled, detector_id = guardduty_manager.check_guardduty_status()
        
        # Enable GuardDuty if not enabled
        if not is_enabled:
            logger.info("Enabling GuardDuty...")
            detector_id = guardduty_manager.enable_guardduty()
        
        # Get findings
        logger.info("Retrieving GuardDuty findings...")
        findings = guardduty_manager.get_findings(detector_id, max_findings)
        
        # Process findings
        processed_findings = guardduty_manager.process_findings(findings)
        
        # Save findings to JSON
        if processed_findings:
            filename = f"guardduty_findings_{region}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_to_json(processed_findings, filename)
            
            logger.info(f"Summary: Found {len(processed_findings)} findings")
            
            # Print summary
            severity_count = {}
            for finding in processed_findings:
                severity = finding.get('severity', 'Unknown')
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            print("\nGuardDuty Findings Summary:")
            print("=" * 30)
            for severity, count in severity_count.items():
                print(f"{severity}: {count}")
        else:
            logger.info("No findings to save")
            print("\nNo GuardDuty findings found - your account looks secure!")
        
        logger.info("GuardDuty automation completed successfully")
        
    except Exception as e:
        logger.error(f"Script execution failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    from datetime import datetime
    main()