#!/usr/bin/env python3
"""
Assignment 5: CloudWatch Alert Setup for Unauthorized API Activity
Author: Vamsi
Description: Automatically detect and alert for potential unauthorized access attempts
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from config.aws_config import AWSConfig
from utils.common import setup_logging, save_to_json, validate_aws_response

class CloudWatchAlertsManager:
    """CloudWatch Alerts Manager for Security Events"""
    
    def __init__(self, aws_config: AWSConfig):
        self.aws_config = aws_config
        self.cloudwatch = aws_config.get_client('cloudwatch')
        self.events = aws_config.get_client('events')
        self.sns = aws_config.get_client('sns')
        self.logs = aws_config.get_client('logs')
        self.logger = logging.getLogger(__name__)
        
        # Define security event patterns
        self.security_events = {
            'console_login_failures': {
                'name': 'AWS-Console-Login-Failures',
                'description': 'Detect failed console login attempts',
                'pattern': {
                    'source': ['aws.signin'],
                    'detail-type': ['AWS Console Sign In via CloudTrail'],
                    'detail': {
                        'responseElements': {
                            'ConsoleLogin': ['Failure']
                        }
                    }
                }
            },
            'unauthorized_api_calls': {
                'name': 'AWS-Unauthorized-API-Calls',
                'description': 'Detect unauthorized API operation attempts',
                'pattern': {
                    'source': ['aws.cloudtrail'],
                    'detail-type': ['AWS API Call via CloudTrail'],
                    'detail': {
                        'errorCode': ['UnauthorizedOperation', 'AccessDenied', 'Forbidden']
                    }
                }
            },
            'root_account_usage': {
                'name': 'AWS-Root-Account-Usage',
                'description': 'Detect root account usage',
                'pattern': {
                    'source': ['aws.cloudtrail'],
                    'detail-type': ['AWS API Call via CloudTrail'],
                    'detail': {
                        'userIdentity': {
                            'type': ['Root']
                        }
                    }
                }
            },
            'mfa_delete_attempts': {
                'name': 'AWS-MFA-Delete-Attempts',
                'description': 'Detect attempts to delete MFA devices',
                'pattern': {
                    'source': ['aws.cloudtrail'],
                    'detail-type': ['AWS API Call via CloudTrail'],
                    'detail': {
                        'eventName': ['DeleteVirtualMFADevice', 'DeactivateMFADevice']
                    }
                }
            },
            'iam_policy_changes': {
                'name': 'AWS-IAM-Policy-Changes',
                'description': 'Detect critical IAM policy changes',
                'pattern': {
                    'source': ['aws.cloudtrail'],
                    'detail-type': ['AWS API Call via CloudTrail'],
                    'detail': {
                        'eventName': [
                            'AttachUserPolicy', 'DetachUserPolicy',
                            'AttachRolePolicy', 'DetachRolePolicy',
                            'AttachGroupPolicy', 'DetachGroupPolicy',
                            'CreatePolicy', 'DeletePolicy',
                            'CreateRole', 'DeleteRole'
                        ]
                    }
                }
            }
        }
    
    def create_sns_topic(self, topic_name: str) -> str:
        """Create SNS topic for alerts"""
        try:
            response = self.sns.create_topic(Name=topic_name)
            
            if not validate_aws_response(response):
                raise Exception("Failed to create SNS topic")
            
            topic_arn = response.get('TopicArn')
            self.logger.info(f"Created SNS topic: {topic_arn}")
            
            # Set topic attributes for security
            self.sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName='DisplayName',
                AttributeValue=f'AWS Security Alerts - {topic_name}'
            )
            
            return topic_arn
            
        except Exception as e:
            if 'already exists' in str(e).lower():
                # Topic already exists, get ARN
                topics_response = self.sns.list_topics()
                for topic in topics_response.get('Topics', []):
                    if topic_name in topic['TopicArn']:
                        self.logger.info(f"Using existing SNS topic: {topic['TopicArn']}")
                        return topic['TopicArn']
            
            self.logger.error(f"Error creating SNS topic: {str(e)}")
            raise
    
    def create_cloudwatch_log_group(self, log_group_name: str) -> bool:
        """Create CloudWatch log group for security events"""
        try:
            self.logs.create_log_group(logGroupName=log_group_name)
            self.logger.info(f"Created CloudWatch log group: {log_group_name}")
            return True
            
        except self.logs.exceptions.ResourceAlreadyExistsException:
            self.logger.info(f"Log group already exists: {log_group_name}")
            return True
        except Exception as e:
            self.logger.error(f"Error creating log group: {str(e)}")
            return False
    
    def create_metric_filter(self, log_group_name: str, filter_name: str, 
                           filter_pattern: str, metric_name: str, 
                           metric_namespace: str) -> bool:
        """Create CloudWatch metric filter"""
        try:
            self.logs.put_metric_filter(
                logGroupName=log_group_name,
                filterName=filter_name,
                filterPattern=filter_pattern,
                metricTransformations=[
                    {
                        'metricName': metric_name,
                        'metricNamespace': metric_namespace,
                        'metricValue': '1',
                        'defaultValue': 0
                    }
                ]
            )
            self.logger.info(f"Created metric filter: {filter_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating metric filter {filter_name}: {str(e)}")
            return False
    
    def create_cloudwatch_alarm(self, alarm_name: str, metric_name: str, 
                              metric_namespace: str, topic_arn: str, 
                              description: str) -> bool:
        """Create CloudWatch alarm"""
        try:
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                ComparisonOperator='GreaterThanOrEqualToThreshold',
                EvaluationPeriods=1,
                MetricName=metric_name,
                Namespace=metric_namespace,
                Period=300,  # 5 minutes
                Statistic='Sum',
                Threshold=1.0,
                ActionsEnabled=True,
                AlarmActions=[topic_arn],
                AlarmDescription=description,
                Unit='Count',
                TreatMissingData='notBreaching'
            )
            self.logger.info(f"Created CloudWatch alarm: {alarm_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating alarm {alarm_name}: {str(e)}")
            return False
    
    def create_event_rule(self, rule_name: str, event_pattern: Dict, 
                         target_arn: str, description: str) -> bool:
        """Create EventBridge rule"""
        try:
            # Create the rule
            self.events.put_rule(
                Name=rule_name,
                EventPattern=json.dumps(event_pattern),
                State='ENABLED',
                Description=description
            )
            
            # Add target to the rule
            self.events.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        'Id': '1',
                        'Arn': target_arn
                    }
                ]
            )
            
            self.logger.info(f"Created EventBridge rule: {rule_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating event rule {rule_name}: {str(e)}")
            return False
    
    def setup_cloudtrail_monitoring(self, topic_arn: str) -> Dict:
        """Setup CloudTrail-based monitoring"""
        
        results = {
            'log_group_created': False,
            'metric_filters_created': [],
            'alarms_created': []
        }
        
        # Create log group for CloudTrail
        log_group_name = '/aws/cloudtrail/security-events'
        results['log_group_created'] = self.create_cloudwatch_log_group(log_group_name)
        
        # Define metric filters and alarms
        security_metrics = [
            {
                'name': 'ConsoleLoginFailures',
                'filter_pattern': '{ ($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = Failure) }',
                'description': 'Failed console login attempts'
            },
            {
                'name': 'UnauthorizedAPICalls',
                'filter_pattern': '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
                'description': 'Unauthorized API calls'
            },
            {
                'name': 'RootAccountUsage',
                'filter_pattern': '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
                'description': 'Root account usage'
            },
            {
                'name': 'IAMPolicyChanges',
                'filter_pattern': '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }',
                'description': 'IAM policy changes'
            }
        ]
        
        metric_namespace = 'SecurityMetrics'
        
        for metric in security_metrics:
            # Create metric filter
            filter_created = self.create_metric_filter(
                log_group_name=log_group_name,
                filter_name=f"{metric['name']}Filter",
                filter_pattern=metric['filter_pattern'],
                metric_name=metric['name'],
                metric_namespace=metric_namespace
            )
            
            if filter_created:
                results['metric_filters_created'].append(metric['name'])
                
                # Create alarm
                alarm_created = self.create_cloudwatch_alarm(
                    alarm_name=f"{metric['name']}Alarm",
                    metric_name=metric['name'],
                    metric_namespace=metric_namespace,
                    topic_arn=topic_arn,
                    description=metric['description']
                )
                
                if alarm_created:
                    results['alarms_created'].append(metric['name'])
        
        return results
    
    def setup_eventbridge_rules(self, topic_arn: str) -> Dict:
        """Setup EventBridge rules for real-time monitoring"""
        
        results = {
            'rules_created': []
        }
        
        for event_key, event_config in self.security_events.items():
            rule_created = self.create_event_rule(
                rule_name=event_config['name'],
                event_pattern=event_config['pattern'],
                target_arn=topic_arn,
                description=event_config['description']
            )
            
            if rule_created:
                results['rules_created'].append(event_config['name'])
        
        return results
    
    def setup_sns_topic_policy(self, topic_arn: str) -> bool:
        """Setup SNS topic policy to allow CloudWatch and EventBridge to publish"""
        try:
            # Get account ID
            account_id = topic_arn.split(':')[4]
            
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
                        },
                        "Action": "SNS:Publish",
                        "Resource": topic_arn,
                        "Condition": {
                            "StringEquals": {
                                "aws:SourceAccount": account_id
                            }
                        }
                    }
                ]
            }
            
            self.sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName='Policy',
                AttributeValue=json.dumps(policy)
            )
            
            self.logger.info("Updated SNS topic policy for CloudWatch and EventBridge access")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting SNS topic policy: {str(e)}")
            return False
    
    def setup_security_monitoring(self, email_endpoint: str = None) -> Dict:
        """Setup comprehensive security monitoring"""
        
        setup_results = {
            'timestamp': datetime.now().isoformat(),
            'topic_arn': '',
            'email_subscription': False,
            'cloudtrail_monitoring': {},
            'eventbridge_rules': {},
            'policy_updated': False,
            'recommendations': []
        }
        
        try:
            # Create SNS topic
            topic_name = f"aws-security-alerts-{datetime.now().strftime('%Y%m%d')}"
            topic_arn = self.create_sns_topic(topic_name)
            setup_results['topic_arn'] = topic_arn
            
            # Subscribe email if provided
            if email_endpoint:
                try:
                    self.sns.subscribe(
                        TopicArn=topic_arn,
                        Protocol='email',
                        Endpoint=email_endpoint
                    )
                    setup_results['email_subscription'] = True
                    self.logger.info(f"Created email subscription for {email_endpoint}")
                    setup_results['recommendations'].append(f"Check {email_endpoint} to confirm subscription")
                except Exception as e:
                    self.logger.warning(f"Failed to create email subscription: {str(e)}")
            
            # Setup CloudTrail monitoring
            cloudtrail_results = self.setup_cloudtrail_monitoring(topic_arn)
            setup_results['cloudtrail_monitoring'] = cloudtrail_results
            
            # Setup EventBridge rules
            eventbridge_results = self.setup_eventbridge_rules(topic_arn)
            setup_results['eventbridge_rules'] = eventbridge_results
            
            # Update SNS topic policy
            policy_updated = self.setup_sns_topic_policy(topic_arn)
            setup_results['policy_updated'] = policy_updated
            
            # Generate recommendations
            recommendations = [
                "✅ Security monitoring has been configured",
                f"📧 SNS Topic created: {topic_arn}",
                "🔍 Monitor the following security events:",
                "   - Failed console login attempts",
                "   - Unauthorized API calls",
                "   - Root account usage",
                "   - IAM policy changes",
                "   - MFA device deletions"
            ]
            
            if not email_endpoint:
                recommendations.append("⚠️ Consider adding email notifications by running with --email parameter")
            
            recommendations.extend([
                "🛡️ Additional recommendations:",
                "   - Enable CloudTrail in all regions if not already enabled",
                "   - Configure CloudTrail to send logs to CloudWatch Logs",
                "   - Enable MFA for all IAM users",
                "   - Regularly review CloudWatch alerts and tune thresholds",
                "   - Consider integrating with AWS Security Hub for centralized findings"
            ])
            
            setup_results['recommendations'] = recommendations
            
            return setup_results
            
        except Exception as e:
            self.logger.error(f"Error setting up security monitoring: {str(e)}")
            raise
    
    def test_alert_system(self, topic_arn: str) -> bool:
        """Send test message to verify alert system"""
        try:
            test_message = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'TEST',
                'message': 'This is a test alert from AWS Security Monitoring System',
                'details': 'If you receive this message, your security alert system is working correctly.'
            }
            
            self.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(test_message, indent=2),
                Subject='AWS Security Alert - Test Message'
            )
            
            self.logger.info("Test alert sent successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending test alert: {str(e)}")
            return False

@click.command()
@click.option('--region', default='us-east-1', help='AWS region')
@click.option('--profile', help='AWS profile name')
@click.option('--email', help='Email address for alert notifications')
@click.option('--test-alerts', is_flag=True, help='Send test alert after setup')
@click.option('--log-level', default='INFO', help='Logging level')
def main(region: str, profile: str, email: str, test_alerts: bool, log_level: str):
    """Main function for CloudWatch alerts setup"""
    
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting CloudWatch Security Alerts Setup")
        
        # Initialize AWS configuration
        aws_config = AWSConfig(region=region, profile=profile)
        alerts_manager = CloudWatchAlertsManager(aws_config)
        
        # Setup security monitoring
        setup_results = alerts_manager.setup_security_monitoring(email)
        
        # Send test alert if requested
        if test_alerts and setup_results['topic_arn']:
            test_sent = alerts_manager.test_alert_system(setup_results['topic_arn'])
            setup_results['test_alert_sent'] = test_sent
        
        # Save setup results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"cloudwatch_alerts_setup_{region}_{timestamp}.json"
        save_to_json(setup_results, filename)
        
        # Print summary
        print(f"\nCloudWatch Security Monitoring Setup Complete!")
        print(f"=" * 55)
        print(f"Region: {region}")
        print(f"SNS Topic: {setup_results['topic_arn']}")
        print(f"")
        
        cloudtrail = setup_results['cloudtrail_monitoring']
        print(f"CloudTrail Monitoring:")
        print(f"  Log Group Created: {'✅' if cloudtrail['log_group_created'] else '❌'}")
        print(f"  Metric Filters: {len(cloudtrail['metric_filters_created'])}")
        print(f"  Alarms Created: {len(cloudtrail['alarms_created'])}")
        print(f"")
        
        eventbridge = setup_results['eventbridge_rules']
        print(f"EventBridge Rules:")
        print(f"  Rules Created: {len(eventbridge['rules_created'])}")
        print(f"")
        
        if setup_results['email_subscription']:
            print(f"📧 Email notifications configured for: {email}")
            print(f"   Please check your email and confirm the subscription!")
        print(f"")
        
        # Print recommendations
        for recommendation in setup_results['recommendations']:
            print(recommendation)
        
        print(f"\nSetup details saved to: /tmp/{filename}")
        
        logger.info("CloudWatch alerts setup completed successfully")
        
    except Exception as e:
        logger.error(f"CloudWatch alerts setup failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()