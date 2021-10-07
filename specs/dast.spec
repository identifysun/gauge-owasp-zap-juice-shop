# Use ZAP to perform DAST

This is an executable specification file. This file follows markdown syntax.
Every heading in this file denotes a scenario. Every bulleted point denotes a step.

## Setup ZAP

* Start ZAP

## Login to the application

* Visit login page
* Login as user "user1@demo.com" with password "123456"

## Kick off the active scan

* Perform spider from "http://192.168.99.100:3000/rest/user/login"
* Get spider status
* Perform zap active scan against "http://192.168.99.100:3000/rest/user/login"
* Get active scan status
* Get alerts summary
* Save scan report to "reports/zap_scan_report.html"

## Shutdown ZAP

* Shutdown ZAP
