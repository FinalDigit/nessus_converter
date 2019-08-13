#!/usr/bin/python
import sys, csv  
import xml.etree.ElementTree as ET 

if for arg in sys.

# CSV Sheet Header 
headers = 'id, ip, hostName, operatingSystem, systemType, macAddress, netbiosName, port, service, protocol,\
    severity, severityNumber, pluginID, pluginName, pluginFamily, vulnerabilityPublicationDate, solution, riskFactor, description, pluginPublicationDate,\
    cvssVector, synopsis, pluginType, patchPublicationDate, pluginModificationDate, stigSeverity, cvssBaseScore, pluginVersion, sourceTool, exploit_available,\
    exploit_framework_metasploit, exploitability_ease, metasploit_name, vulnerability_fixed, vulnerability_fixed_date, cvss_temporal_score, see_also, plugin_output, exploit_framework_canvas, canvas_package,\
    compliance_info, compliance_result, compliance_actual_value, compliance_check_id, compliance_audit_file, compliance_check_name, fqdn, cve_numbers, bid_numbers, compliance_policy_value,\
    ipSortValue, cvss3Vector, Location, Path, Response, Request, IssueBackground, IssueDetail, RemediationBackground, RemediationDetail,\
    Confidence, SerialNumber, Type, Name, cvss3BaseScore, osvdb_numbers, cvss3_temporal_score, exploited_by_nessus, cpe, inTheNews,\
    cvssTemporalVector, cvss3TemporalVector, merge_history'

# Namicsoft Sqlite Headers 
namicsoft_headers = 'id, ip, hostName, operatingSystem, systemType, macAddress, netbiosName, port, service, protocol,\
    severity, severityNumber, pluginID, pluginName, pluginFamily, vulnerabilityPublicationDate, solution, riskFactor, description, pluginPublicationDate,\
    cvssVector, synopsis, pluginType, patchPublicationDate, pluginModificationDate, stigSeverity, cvssBaseScore, pluginVersion, sourceTool, exploit_available,\
    exploit_framework_metasploit, exploitability_ease, metasploit_name, vulnerability_fixed, vulnerability_fixed_date, cvss_temporal_score, see_also, plugin_output, exploit_framework_canvas, canvas_package,\
    compliance_info, compliance_result, compliance_actual_value, compliance_check_id, compliance_audit_file, compliance_check_name, fqdn, cve_numbers, bid_numbers, compliance_policy_value,\
    ipSortValue, cvss3Vector, Location, Path, Response, Request, IssueBackground, IssueDetail, RemediationBackground, RemediationDetail,\
    Confidence, SerialNumber, Type, Name, cvss3BaseScore, osvdb_numbers, cvss3_temporal_score, exploited_by_nessus, cpe, inTheNews,\
    cvssTemporalVector, cvss3TemporalVector, merge_history'
    
# Finds XML Elements for Headers as they appear in Nessus file - risk_factor(Element from Nessus) = RiskFactor(New Header)
nessus_headers = 'id, ip, hostName, os, system-type, macAddress, netbiosName, port, svc_name, protocol,\
    severity, severityNumber, pluginID, pluginName, pluginFamily, vuln_publication_date, solution, risk_factor, description, plugin_publication_date,\
    cvss_vector, synopsis, plugin_type, patchPublicationDate, plugin_modification_date, stigSeverity, cvss_base_score, pluginVersion, sourceTool, exploit_available,\
    exploit_framework_metasploit, exploitability_ease, metasploit_name, vulnerability_fixed, vulnerability_fixed_date, cvss_temporal_score, see_also, plugin_output, exploit_framework_canvas, canvas_package,\
    compliance_info, compliance_result, compliance_actual_value, compliance_check_id, compliance_audit_file, compliance_check_name, host_fqdn, cve, bid, compliance_policy_value,\
    ipSortValue, cvss3_vector, Location, Path, Response, Request, IssueBackground, IssueDetail, RemediationBackground, RemediationDetail,\
    Confidence, SerialNumber, Type, Name, cvss3_base_score, osvdb_numbers, cvss3_temporal_score, exploited_by_nessus, cpe, in_the_news,\
    cvss_temporal_vector, cvss3_temporal_vector, merge_history'

results = {}
limit_results = False
limit_number = 5
flag = False

root = ET.parse('file.nessus').getroot()
print("tag=%s, attrib=%s" % (root.tag, root.attrib))

Reports = root.find('Report')
print(Reports.tag, Reports.attrib)

id = 1
for ReportHost in Reports:
    print ReportHost.tag, ReportHost.attrib  # IP
    ip = ReportHost.attrib['name']
     
    # Get HostProperties data to add for each Rows IP
    HostProperties = ReportHost.find('HostProperties')
    for HostProperty in HostProperties:
        #print("%s=%s" % (HostProperty.attrib, HostProperty.text))
        print("HostPropert Attrib: %s" % HostProperty.attrib['name'])
        
        if HostProperty.attrib['name'] == 'os':  # operatingSystem
            os = HostProperty.text
            
        if HostProperty.attrib['name'] == 'system-type':  # systemType
            systemType = HostProperty.text
        else: systemType = None

    # Get All Items under ReportItems for IP
    ReportItems = ReportHost.findall('ReportItem')

    ip_cnt = 0    
    for ReportItem in ReportItems:    

        # START BUILD row of data
        ip_key = ('%s_%s' % (ip, ip_cnt))
        results[ip_key] = {'id': id}   
        results[ip_key]['ip'] = ip         
        results[ip_key]['hostName'] = ip  # hostName
        
        ipSortValue = (int(ip.split('.')[0]) * 16777216) + (int(ip.split('.')[1]) * 65536) + (int(ip.split('.')[2]) * 256) + (int(ip.split('.')[3]))
        results[ip_key]['ipSortValue'] = ipSortValue # ipSortValue
        results[ip_key]['operatingSystem'] = os 
        results[ip_key]['systemType'] = systemType  
        results[ip_key]['macAddress'] = ''
        results[ip_key]['netbiosName'] = ''
        
        # Report Item Attributes #
        print("%s=%s" % (ReportItem.tag, ReportItem.attrib))
        results[ip_key]['port']= ReportItem.attrib['port']  # port
        results[ip_key]['service']= ReportItem.attrib['svc_name']  # service
        results[ip_key]['protocol']= ReportItem.attrib['protocol']  # protocol
        
        # Severity Parent #
        severityNumber = ReportItem.attrib['severity']
        if severityNumber == '0':
            severityNumber = '4'
        if severityNumber == '1':
            severityNumber = '3'           
        if severityNumber == '2':
            severityNumber = '2'
        if severityNumber == '3':
            severityNumber = '1'
            
        results[ip_key]['severityNumber'] = severityNumber # severityNumber
        if severityNumber == '4':
            severity = 'Informational'
        if severityNumber == '3':
            severity = 'Low'
        if severityNumber == '3':
            severity = 'Medium'
        if severityNumber == '2':
            severity = 'High'
        if severityNumber == '1':
            severity = 'Critical'
            
        results[ip_key]['severity'] =  severity  # severity
        
        results[ip_key]['pluginID']= ReportItem.attrib['pluginID']  # pluginID
        results[ip_key]['pluginName']= ReportItem.attrib['pluginName']  # pluginName
        if ReportItem.attrib['pluginName'] == 'SMB Signing not require': flag = True
        results[ip_key]['pluginFamily']= ReportItem.attrib['pluginFamily']  # pluginFamily
        
        
        # Report Item Children
        element_cnt = 0
        for header in nessus_headers.split(','):
            print('%s -------------------------------------' % header.strip())
            if ReportItem.find('%s' % header.strip()) is not None:
                #results[ip_key][header] = ReportItem.find(key).text
                print('[*] Nessus XML Header Found: %s' % header)
                print('[*] Converted to NamicSoft Header: %s' % namicsoft_headers.split(',')[element_cnt].strip())
                key = ('%s' % namicsoft_headers.split(',')[element_cnt].strip())
                results[ip_key][key] = ReportItem.find(header.strip()).text
            element_cnt += 1
        element_cnt = 0

        
        # Start New Row        
        id += 1
        ip_cnt += 1
        if limit_results:
            if ip_cnt >= limit_number: 
                break               


print('')                
for k,v in results.iteritems():
    print k,v


def create_csv():
    print('[*] Creating .csv file')
    with open('csv_nessus.csv', 'w') as f:
        for column in headers.split(','):
            f.write(column + ',')
        f.write('\n')
        
        for k,v in results.iteritems():
            for column in v.values():
                f.write(column + ',')
            f.write('\n')


def create_sqlite():
    import sqlite3

    def create():
        c.execute('''DROP TABLE IF EXISTS queryTable''') 
        try:
            c.execute("""CREATE TABLE queryTable 
                     (id INTEGER PRIMARY KEY, ip, hostName, operatingSystem, systemType, macAddress, netbiosName, 
                     port INTEGER, service, protocol, severity, severityNumber INTEGER, pluginID, 
                     pluginName, pluginFamily, vulnerabilityPublicationDate, solution, riskFactor, 
                     description, pluginPublicationDate, cvssVector, synopsis, pluginType, 
                     patchPublicationDate, pluginModificationDate, stigSeverity, cvssBaseScore,	pluginVersion, 
                     sourceTool, exploit_available, exploit_framework_metasploit, exploitability_ease, metasploit_name, 
                     vulnerability_fixed, vulnerability_fixed_date, cvss_temporal_score DECMIAL, see_also, plugin_output, 
                     exploit_framework_canvas, canvas_package, compliance_info, compliance_result, compliance_actual_value,	
                     compliance_check_id, compliance_audit_file, compliance_check_name, fqdn, cve_numbers, 
                     bid_numbers, compliance_policy_value, ipSortValue INTEGER, cvss3Vector, Location, 
                     Path, Response, Request, IssueBackground, IssueDetail,	
                     RemediationBackground, RemediationDetail, Confidence, SerialNumber, Type, 
                     Name, cvss3BaseScore, osvdb_numbers, cvss3_temporal_score DECIMAL,	exploited_by_nessus, 
                     cpe, inTheNews, cvssTemporalVector, cvss3TemporalVector, merge_history)""")
        except:
            pass

    def insert(data):
        sql = """INSERT INTO queryTable 
            (id, ip, hostName, operatingSystem, systemType, macAddress, netbiosName, 
             port, service, protocol, severity, severityNumber, pluginID, 
             pluginName, pluginFamily, vulnerabilityPublicationDate, solution, riskFactor, 
             description, pluginPublicationDate, cvssVector, synopsis, pluginType, 
             patchPublicationDate, pluginModificationDate, stigSeverity, cvssBaseScore,	pluginVersion, 
             sourceTool, exploit_available, exploit_framework_metasploit, exploitability_ease, metasploit_name, 
             vulnerability_fixed, vulnerability_fixed_date, cvss_temporal_score, see_also, plugin_output, 
             exploit_framework_canvas, canvas_package, compliance_info, compliance_result, compliance_actual_value,	
             compliance_check_id, compliance_audit_file, compliance_check_name, fqdn, cve_numbers, 
             bid_numbers, compliance_policy_value, ipSortValue, cvss3Vector, Location, 
             Path, Response, Request, IssueBackground, IssueDetail,	
             RemediationBackground, RemediationDetail, Confidence, SerialNumber, Type, 
             Name, cvss3BaseScore, osvdb_numbers, cvss3_temporal_score,	exploited_by_nessus, 
             cpe, inTheNews, cvssTemporalVector, cvss3TemporalVector, merge_history)
             values(
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?
             )"""               
        c.execute(sql, data)

    def select(verbose=True):
        sql = "SELECT * FROM queryTable"
        recs = c.execute(sql)
        if verbose:
            for row in recs:
                print row


    db_path = r'nessus_data.sqlite'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    create()

    # Build Data Entries, creates rows
    for k,v in results.iteritems():
        print k
        row = []
        for header in namicsoft_headers.split(','):
            row.append(v.get('%s' % header.strip()))
        insert(row)

    conn.commit() #commit needed
    select()
    c.close()

#create_csv()
create_sqlite()
if flag: print('[*] Flag!')
exit()
