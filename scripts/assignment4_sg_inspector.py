#!/usr/bin/env python3
"""
Assignment 4: EC2 Security Group Inspector
Author: Vamsi
Description: Identify risky security group configurations
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple
from config.aws_config import AWSConfig
from utils.common import setup_logging, save_to_json, save_to_csv, validate_aws_response, SecurityViolation

class SecurityGroupInspector:
    """EC2 Security Group Inspector"""
    
    def __init__(self, aws_config: AWSConfig):
        self.aws_config = aws_config
        self.ec2 = aws_config.get_client('ec2')
        self.logger = logging.getLogger(__name__)
        
        # Define risky ports and their descriptions
        self.risky_ports = {
            22: {'name': 'SSH', 'risk': 'HIGH', 'description': 'SSH access from anywhere'},
            3389: {'name': 'RDP', 'risk': 'HIGH', 'description': 'RDP access from anywhere'},
            80: {'name': 'HTTP', 'risk': 'MEDIUM', 'description': 'HTTP access from anywhere'},
            443: {'name': 'HTTPS', 'risk': 'LOW', 'description': 'HTTPS access from anywhere'},
            21: {'name': 'FTP', 'risk': 'HIGH', 'description': 'FTP access from anywhere'},
            23: {'name': 'Telnet', 'risk': 'HIGH', 'description': 'Telnet access from anywhere'},
            25: {'name': 'SMTP', 'risk': 'MEDIUM', 'description': 'SMTP access from anywhere'},
            53: {'name': 'DNS', 'risk': 'MEDIUM', 'description': 'DNS access from anywhere'},
            135: {'name': 'RPC', 'risk': 'HIGH', 'description': 'RPC access from anywhere'},
            139: {'name': 'NetBIOS', 'risk': 'HIGH', 'description': 'NetBIOS access from anywhere'},
            445: {'name': 'SMB', 'risk': 'HIGH', 'description': 'SMB access from anywhere'},
            1433: {'name': 'SQL Server', 'risk': 'HIGH', 'description': 'SQL Server access from anywhere'},
            3306: {'name': 'MySQL', 'risk': 'HIGH', 'description': 'MySQL access from anywhere'},
            5432: {'name': 'PostgreSQL', 'risk': 'HIGH', 'description': 'PostgreSQL access from anywhere'},
            6379: {'name': 'Redis', 'risk': 'HIGH', 'description': 'Redis access from anywhere'},
            27017: {'name': 'MongoDB', 'risk': 'HIGH', 'description': 'MongoDB access from anywhere'}
        }
    
    def get_all_security_groups(self) -> List[Dict]:
        """Get all security groups"""
        try:
            response = self.ec2.describe_security_groups()
            
            if not validate_aws_response(response):
                raise Exception("Failed to describe security groups")
            
            security_groups = response.get('SecurityGroups', [])
            self.logger.info(f"Retrieved {len(security_groups)} security groups")
            return security_groups
            
        except Exception as e:
            self.logger.error(f"Error retrieving security groups: {str(e)}")
            return []
    
    def is_open_to_world(self, ip_ranges: List[Dict], ipv6_ranges: List[Dict] = None) -> bool:
        """Check if rule allows access from anywhere"""
        # Check IPv4 ranges
        for ip_range in ip_ranges:
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
        
        # Check IPv6 ranges
        if ipv6_ranges:
            for ipv6_range in ipv6_ranges:
                if ipv6_range.get('CidrIpv6') == '::/0':
                    return True
        
        return False
    
    def analyze_ingress_rule(self, rule: Dict) -> Tuple[List[SecurityViolation], List[Dict]]:
        """Analyze a single ingress rule for security violations"""
        violations = []
        findings = []
        
        ip_protocol = rule.get('IpProtocol', '')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        ip_ranges = rule.get('IpRanges', [])
        ipv6_ranges = rule.get('Ipv6Ranges', [])
        
        is_world_accessible = self.is_open_to_world(ip_ranges, ipv6_ranges)
        
        if not is_world_accessible:
            return violations, findings
        
        # Check for all ports open
        if ip_protocol == '-1':  # All protocols
            violation = SecurityViolation(
                'Security Group', '', 'All Protocols Open', 'CRITICAL',
                'Security group allows all protocols and ports from 0.0.0.0/0'
            )
            violations.append(violation)
            
            finding = {
                'rule_type': 'All Protocols',
                'protocol': 'All',
                'port_range': 'All',
                'risk_level': 'CRITICAL',
                'description': 'All protocols and ports are open to the world'
            }
            findings.append(finding)
        
        # Check specific port ranges
        elif ip_protocol in ['tcp', 'udp']:
            # Handle port ranges
            if from_port == to_port:
                # Single port
                port = from_port
                if port in self.risky_ports:
                    port_info = self.risky_ports[port]
                    
                    violation = SecurityViolation(
                        'Security Group', '', f'{port_info["name"]} Open', port_info['risk'],
                        f'{port_info["description"]} (port {port})'
                    )
                    violations.append(violation)
                    
                    finding = {
                        'rule_type': 'Risky Port',
                        'protocol': ip_protocol.upper(),
                        'port_range': str(port),
                        'port_name': port_info['name'],
                        'risk_level': port_info['risk'],
                        'description': port_info['description']
                    }
                    findings.append(finding)
                else:
                    # Non-standard port open to world
                    finding = {
                        'rule_type': 'Open Port',
                        'protocol': ip_protocol.upper(),
                        'port_range': str(port),
                        'port_name': 'Custom',
                        'risk_level': 'MEDIUM',
                        'description': f'Custom port {port} open to the world'
                    }
                    findings.append(finding)
            
            else:
                # Port range
                port_range = f"{from_port}-{to_port}"
                
                # Check if range includes risky ports
                risky_ports_in_range = []
                for port in range(from_port, to_port + 1):
                    if port in self.risky_ports:
                        risky_ports_in_range.append(port)
                
                if risky_ports_in_range:
                    violation = SecurityViolation(
                        'Security Group', '', 'Risky Port Range', 'HIGH',
                        f'Port range {port_range} includes risky ports: {risky_ports_in_range}'
                    )
                    violations.append(violation)
                
                finding = {
                    'rule_type': 'Port Range',
                    'protocol': ip_protocol.upper(),
                    'port_range': port_range,
                    'port_name': 'Range',
                    'risk_level': 'HIGH' if risky_ports_in_range else 'MEDIUM',
                    'description': f'Port range {port_range} open to the world'
                }
                findings.append(finding)
        
        return violations, findings
    
    def inspect_security_group(self, sg: Dict) -> Dict:
        """Inspect a single security group"""
        
        group_id = sg.get('GroupId')
        group_name = sg.get('GroupName', '')
        description = sg.get('Description', '')
        vpc_id = sg.get('VpcId', 'N/A')
        
        self.logger.debug(f"Inspecting security group: {group_id}")
        
        inspection_result = {
            'group_id': group_id,
            'group_name': group_name,
            'description': description,
            'vpc_id': vpc_id,
            'ingress_rules': [],
            'violations': [],
            'findings': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        # Analyze ingress rules
        ingress_rules = sg.get('IpPermissions', [])
        
        for rule in ingress_rules:
            rule_violations, rule_findings = self.analyze_ingress_rule(rule)
            
            # Store rule details
            rule_info = {
                'protocol': rule.get('IpProtocol', ''),
                'from_port': rule.get('FromPort'),
                'to_port': rule.get('ToPort'),
                'ip_ranges': rule.get('IpRanges', []),
                'ipv6_ranges': rule.get('Ipv6Ranges', []),
                'user_id_group_pairs': rule.get('UserIdGroupPairs', []),
                'prefix_list_ids': rule.get('PrefixListIds', [])
            }
            inspection_result['ingress_rules'].append(rule_info)
            
            # Add violations and findings
            for violation in rule_violations:
                violation.resource_id = group_id
                inspection_result['violations'].append(violation.to_dict())
            
            inspection_result['findings'].extend(rule_findings)
        
        # Calculate risk score
        risk_scores = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 5, 'CRITICAL': 10}
        total_risk = sum(risk_scores.get(f.get('risk_level', 'LOW'), 1) for f in inspection_result['findings'])
        inspection_result['risk_score'] = min(total_risk, 100)
        
        # Generate recommendations
        recommendations = []
        
        if inspection_result['violations']:
            recommendations.append("🔴 URGENT: This security group has critical security violations")
            
            for violation in inspection_result['violations']:
                violation_type = violation['violation_type']
                
                if 'SSH' in violation_type:
                    recommendations.append("- Restrict SSH access to specific IP ranges or use VPN/bastion host")
                elif 'RDP' in violation_type:
                    recommendations.append("- Restrict RDP access to specific IP ranges or use VPN")
                elif 'All Protocols' in violation_type:
                    recommendations.append("- Remove rule allowing all protocols, specify only required ports")
                elif 'Database' in violation_type or any(db in violation_type for db in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
                    recommendations.append("- Database ports should never be open to the internet, use private subnets")
        
        if inspection_result['findings']:
            open_ports = [f for f in inspection_result['findings'] if f['rule_type'] in ['Open Port', 'Port Range']]
            if open_ports:
                recommendations.append("- Review if all open ports are actually required")
                recommendations.append("- Consider using Application Load Balancer for web traffic")
        
        if not recommendations:
            recommendations.append("✅ This security group appears to follow security best practices")
        
        inspection_result['recommendations'] = recommendations
        
        return inspection_result
    
    def inspect_all_security_groups(self) -> Dict:
        """Inspect all security groups"""
        
        security_groups = self.get_all_security_groups()
        
        inspection_results = {
            'total_security_groups': len(security_groups),
            'inspection_timestamp': datetime.now().isoformat(),
            'security_group_inspections': [],
            'summary': {
                'critical_violations': 0,
                'high_risk_groups': 0,
                'medium_risk_groups': 0,
                'low_risk_groups': 0,
                'compliant_groups': 0,
                'common_violations': {}
            }
        }
        
        self.logger.info(f"Starting inspection of {len(security_groups)} security groups...")
        
        for sg in security_groups:
            inspection = self.inspect_security_group(sg)
            inspection_results['security_group_inspections'].append(inspection)
            
            # Update summary
            risk_score = inspection['risk_score']
            violation_count = len(inspection['violations'])
            
            if violation_count > 0:
                # Count violation types
                for violation in inspection['violations']:
                    violation_type = violation['violation_type']
                    inspection_results['summary']['common_violations'][violation_type] = \
                        inspection_results['summary']['common_violations'].get(violation_type, 0) + 1
                
                # Categorize by risk
                if any(v['severity'] == 'CRITICAL' for v in inspection['violations']):
                    inspection_results['summary']['critical_violations'] += 1
                elif risk_score >= 10:
                    inspection_results['summary']['high_risk_groups'] += 1
                elif risk_score >= 5:
                    inspection_results['summary']['medium_risk_groups'] += 1
                else:
                    inspection_results['summary']['low_risk_groups'] += 1
            else:
                inspection_results['summary']['compliant_groups'] += 1
        
        return inspection_results
    
    def generate_csv_report(self, inspection_results: Dict) -> List[Dict]:
        """Generate CSV-friendly report data"""
        
        csv_data = []
        
        for inspection in inspection_results['security_group_inspections']:
            
            # Create summary row for each security group
            violations_summary = '; '.join([v['violation_type'] for v in inspection['violations']])
            findings_summary = '; '.join([f"{f['protocol']}/{f['port_range']}" for f in inspection['findings']])
            
            row = {
                'group_id': inspection['group_id'],
                'group_name': inspection['group_name'],
                'vpc_id': inspection['vpc_id'],
                'violation_count': len(inspection['violations']),
                'finding_count': len(inspection['findings']),
                'risk_score': inspection['risk_score'],
                'violations': violations_summary,
                'open_ports': findings_summary,
                'recommendations_count': len(inspection['recommendations'])
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
    """Main function for Security Group inspection"""
    
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Starting Security Group Inspection")
        
        # Initialize AWS configuration
        aws_config = AWSConfig(region=region, profile=profile)
        sg_inspector = SecurityGroupInspector(aws_config)
        
        # Perform inspection
        inspection_results = sg_inspector.inspect_all_security_groups()
        
        # Generate timestamp for files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save results based on format
        if output_format in ['json', 'both']:
            json_filename = f"security_group_inspection_{region}_{timestamp}.json"
            save_to_json(inspection_results, json_filename)
            print(f"JSON report saved to /tmp/{json_filename}")
        
        if output_format in ['csv', 'both']:
            csv_data = sg_inspector.generate_csv_report(inspection_results)
            csv_filename = f"security_group_inspection_{region}_{timestamp}.csv"
            save_to_csv(csv_data, csv_filename)
            print(f"CSV report saved to /tmp/{csv_filename}")
        
        # Print summary
        summary = inspection_results['summary']
        print(f"\nSecurity Group Inspection Summary:")
        print(f"=" * 45)
        print(f"Total Security Groups: {inspection_results['total_security_groups']}")
        print(f"")
        print(f"Risk Assessment:")
        print(f"  🔴 Critical Violations: {summary['critical_violations']}")
        print(f"  🟠 High Risk Groups: {summary['high_risk_groups']}")
        print(f"  🟡 Medium Risk Groups: {summary['medium_risk_groups']}")
        print(f"  🟢 Low Risk Groups: {summary['low_risk_groups']}")
        print(f"  ✅ Compliant Groups: {summary['compliant_groups']}")
        
        # Show common violations
        if summary['common_violations']:
            print(f"\nMost Common Violations:")
            sorted_violations = sorted(summary['common_violations'].items(), 
                                     key=lambda x: x[1], reverse=True)
            for violation_type, count in sorted_violations[:5]:
                print(f"  {violation_type}: {count} groups")
        
        # Show most risky groups
        risky_groups = [sg for sg in inspection_results['security_group_inspections'] 
                       if sg['violations']]
        if risky_groups:
            print(f"\nTop Risky Security Groups:")
            sorted_risky = sorted(risky_groups, key=lambda x: x['risk_score'], reverse=True)
            for sg in sorted_risky[:5]:
                print(f"  {sg['group_id']} ({sg['group_name']}): Risk Score {sg['risk_score']}")
        
        logger.info("Security Group inspection completed successfully")
        
    except Exception as e:
        logger.error(f"Security Group inspection failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()