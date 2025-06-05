import csv
import datetime
import getpass
import sys
import requests
import pandas as pd
from lxml import etree
from io import StringIO
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def initialise_log():
    """
    """
    # Create csv for pages
    startTimestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    attach_report_log = f"approval_report_log_{startTimestamp}.csv"
    page_log = f"page_log_{startTimestamp}.csv"

    LOG_DEFS = {
         attach_report_log : ["timestamp", "url", "page_id", "success", "comment"],
         page_log : ["timestamp", "url", "page_id", "status", "comment"]
    }

    for filename, headers in LOG_DEFS.items():
        with open(filename, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    
    return attach_report_log, page_log

def append_to_log(filename, page_id, data):
    """
    """
    timeNow = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    url = f"https://confluence.service.anz/pages/viewpage.action?pageId={page_id} "
    log_entry = [timeNow, url, page_id] + data
    with open(filename, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(log_entry)


def get_credentials():
    """
    Prompts the user to enter their Confluence username and password.

    Returns:
        tuple: A tuple containing the username and password.
    """
    username = input("Enter your Confluence username: ")
    password = getpass.getpass("Enter your Confluence password: ")
    # password = input("Enter your Confluence password: ") # for api key
    return username, password

def attach_approval_report(page_id, attach_report_log, AUTH):
    # Attach approval macro report to page
    url = f"https://confluence.service.anz/rest/pageApprovals/1/report/attachCSV/{page_id}"

    response = requests.post(url, headers = {"X-Atlassian-Token": "no-check"}, auth=AUTH, verify=False)

    if response.status_code == 200 or response.status_code == 201:
        append_to_log(attach_report_log, page_id, ["Success"])
    else:
        append_to_log(attach_report_log, page_id, [f"Failed with status code {response.status_code}: {response.text}"])

def get_page_approval_macro(ns, tree, page_id, page_log):
    # f  the page approval macro and get all the approvers
        # //ac means it searches at every depth, /ac would only search at the root level
        approval_macro_list = tree.xpath("//ac:structured-macro[@ac:name='pageapproval']", namespaces=ns)

        if not approval_macro_list:
            # we have no page approval macro, so we cannot proceed
            append_to_log(page_log, page_id, ["Failed", "No page approval macro found"])
            return None

        elif len(approval_macro_list) > 1:
            # we have multiple page approval macros, so we log and do not proceed
            append_to_log(page_log, page_id, ["Failed", "Multiple page approval macros found"])
            return None

        else:
            return approval_macro_list[0]


def get_userkeys(ns, page_approval_macro, page_id, page_log):
    # get users parameter in the macro
    users_param = page_approval_macro.xpath('.//ac:parameter[@ac:name="users"]', namespaces=ns)
    if not users_param:
        append_to_log(page_log, page_id, ["Failed", "Users parameter not found in page approval macro"])
        return None

    users_param = users_param[0]  # get the first (and only) parameter element

    # get user elements in the users parameter
    user_elems = users_param.xpath(".//ri:user", namespaces=ns)
    if not user_elems:
        append_to_log(page_log, page_id, ["Failed", "User elements not found in page approval macro"])
        return None

    userkeys = [user.get('{http://atlassian.com/resource/identifier}userkey') for user in user_elems]
    if not userkeys:
        append_to_log(page_log, page_id, ["Failed", "User keys could not be extracted from user elements"])
        return None
    
    return userkeys

def get_page_approvers(ns, userkeys, user_cache, AUTH):
    # final list of page approvers
    page_approvers = []
    for userkey in userkeys:
        # check if userkey is in cache
        if userkey in user_cache:
            username = user_cache[userkey]

        else:
            # get the user details from the API
            get_user_url = f"https://confluence.service.anz/rest/api/user?key={userkey}"
            response = requests.get(get_user_url, auth=AUTH, verify=False)

            if response.status_code == 200:
                user_data = response.json()
                username = user_data.get("username", "Unknown User")
                user_cache[userkey] = username

        # add user to page approvers list
        page_approvers.append(username)

    # get total approvers on macro to check later
    num_approvers = len(page_approvers)

    return page_approvers, num_approvers, user_cache

def get_quorum(ns, num_approvers, page_approval_macro):
    # check if page approval macro has quorum
    quorum_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="quorum"]', namespaces=ns)
    # set quorum to all approvers if not set in macro, else get the quorum value
    quorum = num_approvers if not quorum_elem else int(quorum_elem[0].text)
    return quorum

def get_page_approval_report(page_id, page_log, AUTH):

        # get all attachments for the page
        get_attachments_url = f"https://confluence.service.anz/rest/api/content/{page_id}/child/attachment"
        response = requests.get(get_attachments_url,headers={"Accept": "application/json", "X-Atlassian-Token": "no-check"}, auth=AUTH, verify=False)

        # if status code is not 200, log the error and continue
        if response.status_code != 200:
            append_to_log(page_log, page_id, ["Failed", f"Failed to get attachments with status code {response.status_code}"])
            return None

        attachments = response.json().get("results", [])
        # if no attachments found, log and continue
        if not attachments:
            append_to_log(page_log, page_id, ["Failed", f"No attachments found for page {page_id}."])
            return None

        # print("attachments:\n", attachments)

        # filter attachments for age approval reports
        reports = [a for a in attachments if a["title"].startswith(f"PA_{page_id}_")]
        if not reports:
            append_to_log(page_log, page_id, ["Failed", f"No page approval reports found for page {page_id}."])
            return None
            
        # get report with latest attachment date
        latest_report_name = max(reports, key=lambda x: x["title"])["title"]

        # print("latest report name:\n", latest_report_name)

        # download the latest report
        report_download_url = f"https://confluence.service.anz/download/attachments/{page_id}/{latest_report_name}"
        # report_download_url = f"https://confluence.service.anz/download/attachments/3704357336/PA_3704357336_29-05-2025_15-42-03_1748497323105.csv"

        response = requests.get(report_download_url, auth=AUTH, verify=False)
        if response.status_code != 200:
            append_to_log(page_log, page_id, ["Failed", f"Failed to download report with status code {response.status_code}"])
            return None
        
        # read the report into a DataFrame
        report = pd.read_csv(StringIO(response.text))  
        report = report.map(lambda x: x.lstrip("'") if isinstance(x, str) else x)
        report.columns = report.columns.str.lstrip("'")

        return report

def get_expiry(ns, page_approval_macro, page_id):
    expire_after_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="expireafter"]', namespaces=ns)
    expire_after = expire_after_elem[0].text if expire_after_elem else None

    expiry_day_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="expiryday"]', namespaces=ns)
    expiry_day = expiry_day_elem[0].text if expiry_day_elem else None

    expiry_month_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="expirymonth"]', namespaces=ns)
    expiry_month = expiry_month_elem[0].text if expiry_month_elem else None

    return expire_after, expiry_day, expiry_month



def main(filename):

    username, password = get_credentials()
    AUTH = HTTPBasicAuth(username, password)

    attach_report_log, page_log = initialise_log()

    # List of page IDs to check
    with open(filename, "r") as file:
        page_ids = [line.strip() for line in file if line.strip()]

    ns= {
    'ac': 'http://atlassian.com/content',
    'ri': 'http://atlassian.com/resource/identifier'
    }
    
    # cache to store user id and username mappings
    user_cache = {}

    for page_id in page_ids:
        print(f"Processing page ID: {page_id}")

        # get the page body and the current version
        get_page_url = f"https://confluence.service.anz/rest/api/content/{page_id}?expand=body.storage,version"
        response = requests.get(get_page_url, headers={"Accept": "application/json"}, auth=AUTH, verify=False)

        # check if get request worked correctly
        if response.status_code != 200:
            if response.status_code == 403:
                append_to_log(page_log, page_id, ["No", "403: access not granted"])
            elif response.status_code == 404:
                append_to_log(page_log, page_id, ["No", "404: page does not exist or access not granted"])
            elif response.status_code == 502:
                append_to_log(page_log, page_id, ["No", "502: bad gateway, likely proxy error"])
            else:
                append_to_log(page_log, page_id, ["No", f"{response.status_code}: page not processed"])
            continue # do not go through rest of process
        
        data = response.json()
        current_body = data["body"]["storage"]["value"]
        latest_version = data["version"]["number"]

        # Creates an etree parser
        parser = etree.XMLParser(recover=True)

        # Turn our current body into an xml tree so we can process it
        tree = etree.fromstring(f"<root xmlns:ac='http://atlassian.com/content' xmlns:ri='http://atlassian.com/resource/identifier'>{current_body}</root>", parser=parser)

        print("Current tree:\n", etree.tostring(tree, pretty_print=True).decode()) # Just to test

        page_approval_macro = get_page_approval_macro(ns, tree, page_id, page_log)
        if not page_approval_macro:
            continue

        userkeys = get_userkeys(ns, page_approval_macro, page_id, page_log)
        if not userkeys:
            continue

        page_approvers, num_approvers, user_cache = get_page_approvers(ns, userkeys, user_cache, AUTH)
        if not page_approvers:
            continue

        quorum = get_quorum(ns, num_approvers, page_approval_macro)

        expireAfter, expiryDay, expiryMonth = get_expiry(ns, page_approval_macro, page_id)

        
        # attach the page approval report to the page
        # TODO: UNCOMMENT THIS LINE TO ACTUALLY ATTACH THE REPORT
        attach_approval_report(page_id, attach_report_log, AUTH)

        report = get_page_approval_report(page_id, page_log, AUTH)
        if report is None:
            continue

        

if len(sys.argv) != 2:
    print("Usage: python script.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

main(filename)