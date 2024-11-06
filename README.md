# SARD_crawler
## SARD NIST 爬蟲程式 (crawler.py)
- 程式語言：JAVA
- 爬取範圍："CWE-22","CWE-23","CWE-35","CWE-59","CWE-200","CWE-201","CWE-219","CWE-264","CWE-275","CWE-276","CWE-284","CWE-285","CWE-352","CWE-359","CWE-377","CWE-402","CWE-425","CWE-441","CWE-497","CWE-538","CWE-540","CWE-548","CWE-552","CWE-566","CWE-601","CWE-639", "CWE-651","CWE-668","CWE-706","CWE-862","CWE-863","CWE-913","CWE-922","CWE-1275"
## progress.json 
- 蒐集過的連結存放點(進度條的概念)
## 資料集 (collect_code_all.csv / collect_code_all.json)
- cwe_id：cwe的id
- title：該網站對每個project的編號
- file_name：有漏洞之檔案名稱
- line：漏洞行在程式碼中的行數
- buggy_line：漏洞行
- code：完整程式碼
- label：0/1(正常/惡意)，目前只有惡意
