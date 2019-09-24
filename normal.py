import datetime
import time
import json
import traceback
import os


file_directory = './meta/'
meta_list = os.listdir(file_directory)

count = 0

cvss2_count = 0
cvss3_count = 0
cvssN_count = 0

def elemCheck(data,key):
    try:
        if data[key] is not None:
            return True
        else:
            return False
    except:
        return False

def readMetaFile(name):
    global count, cvss2_count, cvss3_count, cvssN_count
    json_data=open(file_directory+name, encoding='UTF8').read()
    json_data = json.loads(json_data)

    cve_list = [] 
    for data in json_data['CVE_Items']:

        cve_id = ''
        cwe = []
        desc = []
        cvss = '' 
        severity = ''
        publish_date = ''
        count = count + 1

        #CVE Number
        if elemCheck(data['cve'], 'CVE_data_meta'):
            cve_id = data['cve']['CVE_data_meta']['ID']
        
        #CWE
        if elemCheck(data['cve'], 'problemtype') and len(data['cve']['problemtype']['problemtype_data']) > 0:
            for cwe_list in data['cve']['problemtype']['problemtype_data']:
                for cwe_info in cwe_list['description']:
                    cwe.append(cwe_info['value'])

        
        #Description
        if elemCheck(data['cve'], 'description'):
            for desc_info in data['cve']['description']['description_data']:
                desc.append(desc_info['value'])

        #CVSS & Severity
        if elemCheck(data, 'impact') and (elemCheck(data['impact'], 'baseMetricV3') or elemCheck(data['impact'], 'baseMetricV2')  ):
            if elemCheck(data['impact'], 'baseMetricV3'):
                #cvss = data['impact']['baseMetricV3']
                cvss = '3.0'
                cvss3_count += 1
                severity = data['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            elif elemCheck(data['impact'], 'baseMetricV2'):
                #cvss = data['impact']['baseMetricV2']
                cvss = '2.0'
                cvss2_count += 1
                severity = data['impact']['baseMetricV2']['severity']
            else:
                cvssN_count += 1


        #publishedDate
        if elemCheck(data, 'publishedDate'):
            publish_date = data['publishedDate']
        
        cve_list.append({"cve_id":cve_id, "description" : desc, "severity":severity, "cvss":cvss ,"cwe":cwe})
    
    return cve_list


        


total_cve = []
for meta_name in meta_list:
    #print(meta_name)
    #meta_name = 'nvdcve-1.1-2019.json'
    total_cve.extend(readMetaFile(meta_name))
    #break


with open('./result/cve.json', 'w') as f:
    json.dump(total_cve, f)


print(count)
print("cvss2 : "+str(cvss2_count))
print("cvss3 : "+str(cvss3_count))
print("cvssN : "+str(cvssN_count))