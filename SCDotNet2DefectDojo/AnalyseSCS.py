__author__="SPoint42"
__version__="1.0"

import sys
import argparse
import re
import json
import requests

DEBUG=True


def get_num_sev(severity):
    if severity == 'Critical':
        return 'S0'
    elif severity == 'High':
        return 'S1'
    elif severity == 'Medium':
        return 'S2'
    elif severity == 'Low':
        return 'S3'
    elif severity == 'Info':
        return 'S4'
    else:
        return 'S5'


## Send to defectDojo
def send2defect(findings, DD_URL, DD_ENG, DD_API):
    print ("Sending to DefectDojo")
    findings_URL = DD_URL + "/api/v2/findings/"
    test_URL = DD_URL + "/api/v2/tests/"

    headers = {'content-type': 'application/json',
               'Authorization': 'Token ' + DD_API}

    SEVERITY = {
        'error': "High",
        'warning': "Medium",
        'low': "Low"
    }

    # Create specific test in the engagement
    payload =  {
        "engagement": DD_ENG,
        "title": "Static Security Check with Security-CodeScan.NET",
        "target_start": "2021-01-01T00:01",
        "target_end": "2021-12-31T23:59",
        "percent_complete": 0,
        "test_type": 2 # this is a static check
    }
    try:
        print("Create Test")
        r = requests.post(test_URL, headers=headers, verify=True, data=json.dumps(payload))
        test_id = json.loads(r.content)['id']
        r.close()
        print("Test sucessfully created")
    except Exception as e:
        print(e)
        r.close()
        return





    for finding in findings:
        #Matching defectdojo Sev and Security Code Scan Seb
        severity = SEVERITY[finding[3]['finding_severity']]

        payload =  {
            "test": test_id, # mandatory
            "found_by": [2], # mandatory here static test
            "title": finding[2]['finding_short_text'], # mandatory
            "severity": severity, # obligatoire
            "description": finding[2]['finding_short_text'], # mandatory
            "numerical_severity": get_num_sev(severity),
            "mitigation": "N/A", # mandatory
            "impact": "N/A", # mandatory
            "active": True,
            "duplicate": False,
            "false_p": False,
            "static_finding": True,
            "dynamic_finding": False,
            "verified": False,
            "sast_source_line":finding[5]['source_line'],
            "sast_source_file_path" :finding[4]['source_file'],
            "line":finding[5]['source_line'],
            "file_path" :finding[4]['source_file'],
        }


        try:
            r = requests.post(findings_URL, headers=headers, verify=True, data=json.dumps(payload))
            if DEBUG:
                print (json.dumps (payload))
                print (r.status_code)
                print (r.content)
            r.close()
        except:
            r.close()
            return


def main(argv):
    try:
        parser = argparse.ArgumentParser(description='Analyze output of SecurityCodeScan(https://security-code-scan.github.io) and send to a DefectDojoInstance\n If you just provide the reportfile, print all in a JSON compatible output ', allow_abbrev=True)
        parser.add_argument('--file', type=str , help='the file to parse', required='True')
        parser.add_argument('--defectURL', type=str , help='URL of the defectDojo (ex : https://owasp.defectdojo.io)')
        parser.add_argument('--testID', type=str , help='DefectDojo engagement')
        parser.add_argument('--APIKey', type=str , help='DefectDojo API Key to put the finding')
        args = parser.parse_args()

    except:
        sys.exit(1)

    try:
        print ("Analyzing: "  + str(args.file))
        fichier = open(args.file, "r")
        lines = fichier.readlines()

        # Pattern to find
        # Security Code Scan: /directory/file.cs(37,24): error SCS0012: Controller method is potentially vulnerable to authorization bypass.
        finding_regexp = re.compile ("^(Security Code Scan): (?P<source_file>.*)(\((?P<source_line>[0-9]+),([0-9]+)\)): (?P<finding_severity>\w+) (?P<finding_error>.*): (?P<finding_short_text>.*)$")

        i=0;
        findings = list()
        for line in lines:
            m=re.match(finding_regexp,line)
            if m is not None:
                if DEBUG:
                    #TODO : check the CWE from securityscancode, see PR #185 at https://github.com/security-code-scan/security-code-scan/pull/185
                    print (json.dumps ([i,
                                        {"error" : m.group ('finding_error')},
                                        {"finding_short_text" : m.group ('finding_short_text')},
                                        {"finding_severity" : m.group ('finding_severity')},
                                        {"source_file" : m.group ('source_file')},
                                        {"source_line" : m.group ('source_line')}
                                        ]))
                findings.append(
                    ((i,
                      {"error" : m.group ('finding_error')},
                      {"finding_short_text" : m.group ('finding_short_text')},
                      {"finding_severity" : m.group ('finding_severity')},
                      {"source_file" : m.group ('source_file')},
                      {"source_line" : m.group ('source_line')}
                      )
                    ))
                i = i+1

        if (args.defectURL) is not None:
            send2defect(findings, args.defectURL, args.testID, args.APIKey)
        else:
            print (findings)

    except Exception as e :
        fichier.close()
        print (e)
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])