from getgauge.python import step, before_scenario, data_store, Messages
from zapv2 import ZAPv2 as ZAP
from time import sleep
import requests
import subprocess
import os
import datetime

# OWASP ZAP
port = "9090"
zap_proxies = {"http": "http://127.0.0.1:{0}".format(port), "https": "https://127.0.0.1:{0}".format(port)}
zap = ZAP(proxies = zap_proxies)

# OWASP Juice Shop
juice_shop_url = "http://192.168.99.100:3000"

@step("Start ZAP")
def start_zap():
    zap_cmd = "/usr/local/bin/zap.sh -daemon -config api.disablekey=true -port {0}".format(port)
    subprocess.Popen(zap_cmd.split(" "), stdout=open(os.devnull, "w"))
    while True:
        try:
            status_req = requests.get("http://127.0.0.1:{0}".format(port))
            if status_req.status_code == 200:
                break
            else:
                print("ZAP is starting")
                sleep(1)
        except:
            print("Waiting ZAP to start")
            sleep(5)
            pass
    zap.core.new_session(name="New Default Session", overwrite=True)
    zap.context.include_in_context("Default Context", "{0}/.*".format(juice_shop_url))
    print("ZAP is running now")

@step("Visit login page")
def visit_login_page():
    login_url = "{0}/#/login".format(juice_shop_url)
    requests.get(login_url, proxies=zap_proxies, verify=False)

@step("Login as user <username> with password <password>")
def login(username, password):
    login_url = "{0}/rest/user/login".format(juice_shop_url)
    login_data = {"email": username, "password": password}
    login = requests.post(login_url, proxies=zap_proxies, json=login_data, verify=False)
    print(login)
    if login.status_code == 200:
        resp_json = login.json()
        auth_token = resp_json['authentication']['token']
        data_store.spec['auth_token'] = auth_token
    else:
        print("Unable to login")
        raise Exception("Unable to login")

@step("Perform spider from <url>")
def zap_spider(url):
    spider_id = zap.spider.scan(url, recurse=False, subtreeonly=True)
    data_store.spec['spider_id'] = spider_id

@step("Get spider status")
def get_spider_status():
    status = 0
    while int(status) < 100:
        status = zap.spider.status(data_store.spec['spider_id'])
        print("spider status: " + status)
        sleep(1)

@step("Perform zap active scan against <target_url>")
def zap_active_scan(target_url):
    scan_id = zap.ascan.scan(target_url, recurse=True, inscopeonly=True)
    data_store.spec['scan_id'] = scan_id

@step("Get active scan status")
def zap_get_active_scan_status():
    scan_status = 0
    while int(scan_status) < 100:
        scan_status = zap.ascan.status(data_store.spec['scan_id'])
        print("Active scanning, {0}%".format(scan_status))
        sleep(1)

@step("Get alerts summary")
def get_alerts_summary():
    url = "{0}".format(juice_shop_url)
    zap_alerts_summary_for(url)

@step("Get alerts summary for <url>")
def zap_alerts_summary_for(url):
    summary = zap.alert.alerts_summary(url)
    print("Alerts summary: {0}".format(summary))

@step("Save scan report to <full_filename>")
def save_scan_report_to(full_filename):
    report = zap.core.htmlreport()
    with open(full_filename, "w") as file:
        file.write(report)
        print("Report saved to {0}".format(full_filename))

@step("Shutdown ZAP")
def shutdown_zap():
    zap.core.shutdown()
