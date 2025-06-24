#!/usr/bin/env python3
"""
Run All Security Audits Script
Convenience script to run all security audits in sequence
"""

import subprocess
import sys
import os
from datetime import datetime

def run_script(script_path, args=None):
    """Run a script and return success status"""
    try:
        cmd = [sys.executable, script_path]
        if args:
            cmd.extend(args)
        
        print(f"\n{'='*60}")
        print(f"Running: {' '.join(cmd)}")
        print(f"{'='*60}")
        
        result = subprocess.run(cmd, capture_output=False, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running {script_path}: {str(e)}")
        return False

def main():
    """Run all security audit scripts"""
    
    print("AWS Security Audit Suite")
    print("=" * 50)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Define scripts to run
    scripts = [
        {
            'path': 'scripts/assignment1_guardduty.py',
            'name': 'GuardDuty Audit',
            'args': ['--max-findings', '50']
        },
        {
            'path': 'scripts/assignment2_iam_auditor.py',
            'name': 'IAM Security Audit',
            'args': ['--format', 'table']
        },
        {
            'path': 'scripts/assignment3_s3_checker.py',
            'name': 'S3 Security Check',
            'args': ['--output-format', 'both']
        },
        {
            'path': 'scripts/assignment4_sg_inspector.py',
            'name': 'Security Group Inspection',
            'args': ['--output-format', 'both']
        }
    ]
    
    results = {}
    
    # Run each script
    for script in scripts:
        print(f"\n🔍 Starting {script['name']}...")
        success = run_script(script['path'], script.get('args'))
        results[script['name']] = success
        
        if success:
            print(f"✅ {script['name']} completed successfully")
        else:
            print(f"❌ {script['name']} failed")
    
    # Summary
    print(f"\n{'='*60}")
    print("AUDIT SUMMARY")
    print(f"{'='*60}")
    
    for script_name, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{script_name:<30} {status}")
    
    successful_audits = sum(1 for success in results.values() if success)
    total_audits = len(results)
    
    print(f"\nCompleted: {successful_audits}/{total_audits} audits successful")
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Note about CloudWatch setup
    print(f"\n📝 Note: Run assignment5_cloudwatch_alerts.py separately with email parameter:")
    print(f"python scripts/assignment5_cloudwatch_alerts.py --email your-email@example.com")

if __name__ == "__main__":
    main()