# DevSecOps AWS Security Assignment

This repository contains a comprehensive DevSecOps solution for AWS security automation using Python and Boto3. The solution consists of 5 main scripts that automate key security checks and monitoring across various AWS services.

## 🎯 Assignment Overview

This project addresses critical AWS security automation tasks:

1. **AWS GuardDuty Setup & Scan Script** - Automate GuardDuty enabling and findings export
2. **IAM Security Compliance Auditor** - Detect inactive or risky IAM accounts
3. **S3 Bucket Policy & Encryption Checker** - Validate S3 security best practices
4. **EC2 Security Group Inspector** - Identify risky security group configurations
5. **CloudWatch Alert Setup** - Automated security monitoring and alerting

## 🏗️ Project Structure

```
├── README.md
├── requirements.txt
├── config/
│   └── aws_config.py          # AWS configuration and session management
├── utils/
│   └── common.py             # Common utilities and helper functions
└── scripts/
    ├── assignment1_guardduty.py
    ├── assignment2_iam_auditor.py
    ├── assignment3_s3_checker.py
    ├── assignment4_sg_inspector.py
    └── assignment5_cloudwatch_alerts.py
```

## 🚀 Setup Instructions

### Prerequisites

- Python 3.8 or higher
- AWS CLI configured with appropriate credentials
- IAM permissions for the services being audited

### Installation

1. **Clone or download this repository**

2. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure AWS credentials** (choose one method):
   ```bash
   # Method 1: AWS CLI
   aws configure
   
   # Method 2: Environment variables
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   
   # Method 3: IAM roles (if running on EC2)
   ```

### Required IAM Permissions

The scripts require the following IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "guardduty:*",
                "iam:List*",
                "iam:Get*",
                "s3:*",
                "ec2:DescribeSecurityGroups",
                "logs:*",
                "cloudwatch:*",
                "events:*",
                "sns:*"
            ],
            "Resource": "*"
        }
    ]
}
```

## 📋 Usage Instructions

### Assignment 1: GuardDuty Automation

```bash
# Basic usage
python scripts/assignment1_guardduty.py

# With specific region and profile
python scripts/assignment1_guardduty.py --region us-west-2 --profile my-profile

# Limit number of findings
python scripts/assignment1_guardduty.py --max-findings 100
```

**Output:** JSON file with GuardDuty findings saved to `/tmp/`

### Assignment 2: IAM Security Audit

```bash
# Basic audit
python scripts/assignment2_iam_auditor.py

# Custom thresholds
python scripts/assignment2_iam_auditor.py --inactive-days 60 --old-key-days 120

# JSON output format
python scripts/assignment2_iam_auditor.py --format json
```

**Output:** Table format in console or JSON file with detailed audit results

### Assignment 3: S3 Security Check

```bash
# Basic S3 audit
python scripts/assignment3_s3_checker.py

# CSV output
python scripts/assignment3_s3_checker.py --output-format csv

# Both JSON and CSV
python scripts/assignment3_s3_checker.py --output-format both
```

**Output:** JSON/CSV files with S3 bucket security analysis

### Assignment 4: Security Group Inspection

```bash
# Basic inspection
python scripts/assignment4_sg_inspector.py

# Specific region with CSV output
python scripts/assignment4_sg_inspector.py --region eu-west-1 --output-format csv
```

**Output:** Detailed security group risk analysis with recommendations

### Assignment 5: CloudWatch Alerts Setup

```bash
# Basic setup
python scripts/assignment5_cloudwatch_alerts.py

# With email notifications
python scripts/assignment5_cloudwatch_alerts.py --email your-email@example.com

# Test alerts after setup
python scripts/assignment5_cloudwatch_alerts.py --email your-email@example.com --test-alerts
```

**Output:** Configured CloudWatch alarms and EventBridge rules for security monitoring

## 📊 Sample Output Examples

### GuardDuty Findings Sample
```json
{
  "id": "12345678901234567890",
  "type": "Backdoor:EC2/C&CActivity.B!DNS",
  "severity": 8.5,
  "title": "EC2 instance is querying a domain name associated with a known Command & Control server",
  "region": "us-east-1",
  "confidence": 5.0
}
```

### IAM Audit Sample
```
IAM Security Audit Report
=========================
Total Users: 25

SUMMARY:
  Users without MFA: 5
  Users with old access keys: 3
  Inactive users: 7
  Compliant users: 10
```

### S3 Security Issues Sample
```
S3 Security Audit Summary:
==========================
Total Buckets: 15
Total Violations: 8

Violation Breakdown:
  🔴 Public Buckets: 2
  🔴 Unencrypted Buckets: 4
  🟡 No Versioning: 8
  🟡 No Logging: 6
```

## 🔧 Key Features

### Robust Error Handling
- Comprehensive exception handling with detailed logging
- Graceful degradation when services are not available
- Validation of AWS API responses

### Security Best Practices
- Principle of least privilege in recommendations
- Industry-standard security checks
- Risk-based prioritization of findings

### Production-Ready Code
- Type hints for better code maintainability
- Modular design with reusable components
- Comprehensive logging and monitoring

### Flexible Output Formats
- JSON for programmatic processing
- CSV for spreadsheet analysis
- Formatted tables for human readability

## 🤔 Assignment Questions - Answers

### 1. How do you rate yourself for writing scripts in Python (1–10)?
**Rating: 7/10**

I have extensive experience writing Python applications, including enterprise-level automation tools, data processing pipelines, and cloud infrastructure scripts. I'm comfortable with advanced Python concepts like decorators, context managers, metaclasses, and async/await patterns.

### 2. Have you used the Boto3 library before? What did you use it for?
**Yes, extensively.** I've used Boto3 for:
- Infrastructure automation and deployment scripts
- Security compliance auditing and reporting
- Cost optimization and resource management
- Data pipeline orchestration with S3, Lambda, and Step Functions
- Multi-account AWS organization management
- Backup and disaster recovery automation

### 3. How do you validate if your API calls were successful in a script?
I use multiple validation approaches:

```python
def validate_aws_response(response: Dict) -> bool:
    """Validate AWS API response"""
    return (
        response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200
    )

# Usage example
try:
    response = s3_client.list_buckets()
    
    if not validate_aws_response(response):
        raise Exception("API call failed")
        
    buckets = response.get('Buckets', [])
    logger.info(f"Successfully retrieved {len(buckets)} buckets")
    
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == 'AccessDenied':
        logger.error("Insufficient permissions")
    else:
        logger.error(f"AWS API error: {error_code}")
except Exception as e:
    logger.error(f"Unexpected error: {str(e)}")
```

### 4. How do you handle exceptions in Python? (Please give an example using API calls)

I use a layered exception handling approach:

```python
from botocore.exceptions import ClientError, NoCredentialsError
import logging

def safe_aws_operation(self, operation_func, *args, **kwargs):
    """Safely execute AWS operations with comprehensive error handling"""
    try:
        response = operation_func(*args, **kwargs)
        
        # Validate response
        if not self.validate_response(response):
            raise Exception("Invalid API response received")
            
        return response
        
    except NoCredentialsError:
        self.logger.error("AWS credentials not found or expired")
        raise
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            self.logger.error(f"Insufficient permissions: {error_message}")
        elif error_code == 'ThrottlingException':
            self.logger.warning("API throttling detected, implementing backoff")
            time.sleep(2)  # Simple backoff
        else:
            self.logger.error(f"AWS API error {error_code}: {error_message}")
        
        raise
        
    except Exception as e:
        self.logger.error(f"Unexpected error in {operation_func.__name__}: {str(e)}")
        raise

# Usage
try:
    buckets = self.safe_aws_operation(self.s3_client.list_buckets)
except Exception as e:
    # Handle at application level
    return {'error': str(e), 'buckets': []}
```

### 5. Have you automated any AWS native security services (e.g., GuardDuty, Macie)? If yes, please share details.

**Yes, extensively.** I've implemented automation for multiple AWS security services:

**GuardDuty Automation:**
- Automated multi-region GuardDuty deployment across AWS Organizations
- Custom finding processing and enrichment with threat intelligence
- Integration with Slack/PagerDuty for real-time alerting
- Automated remediation workflows for common findings

**AWS Config Rules:**
- Deployed custom and managed config rules for compliance monitoring
- Automated remediation actions using Lambda functions
- Cost optimization through resource lifecycle management

**Security Hub Integration:**
- Centralized security findings aggregation from multiple services
- Custom insights and dashboards for executive reporting
- JIRA integration for security finding workflows

**CloudTrail Analysis:**
- Real-time log analysis for anomaly detection
- Automated forensic data collection for security incidents
- Compliance reporting for SOC 2 and ISO 27001 audits

**AWS Systems Manager:**
- Automated patch management and compliance scanning
- Configuration drift detection and remediation
- Secrets rotation automation

## 🛡️ Security Considerations

- All scripts follow AWS security best practices
- Sensitive information is never logged or exposed
- Least privilege access principle applied
- Comprehensive input validation and sanitization

## 📝 Notes and Assumptions

1. **CloudTrail Requirement**: Assignment 5 assumes CloudTrail is enabled and configured to send logs to CloudWatch Logs
2. **Permissions**: Scripts require read access to most services and write access for GuardDuty and CloudWatch setup
3. **Regions**: Most scripts work with single regions, but can be easily extended for multi-region support
4. **Cost Awareness**: GuardDuty and CloudWatch alarms incur AWS charges
5. **Rate Limiting**: Scripts implement basic retry logic for API throttling

## 🔄 Future Enhancements

- Multi-region support for all scripts
- Integration with AWS Organizations for multi-account auditing
- Custom remediation actions for identified issues
- Dashboard creation for visualization of security metrics
- Integration with external SIEM systems

## 📞 Support

For questions or issues with this implementation, please review the comprehensive logging output and error messages. Each script provides detailed debug information when run with `--log-level DEBUG`.

---

**Author:** Vamsi  
**Email:** vamsic2244@gmail.com  
**Assignment:** DevSecOps - Python + Boto3 + AWS Security  
**Duration:** ~90 minutes  
**Company:** Nebula Tech Solutions Client
