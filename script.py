import csv
from datetime import datetime
import getpass
import json
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
    startTimestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    page_log = f"page_log_{startTimestamp}.csv"
    output_report = f"output_report_{startTimestamp}.csv"

    LOG_DEFS = {
         page_log : ["timestamp", "url", "pageId", "status", "comment"],
         output_report : ["pageId", "url", "pageStatus", "pageApproversCount", "quorum", "allApprovers",  "approversWhoHaveApproved", "expireAfter", "expiryDay", "expiryMonth"]
    }

    for filename, headers in LOG_DEFS.items():
        with open(filename, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    
    return page_log, output_report

def append_to_log(filename, pageId, data, is_output_report=False):
    """
    """
    url = f"https://confluence.service.anz/pages/viewpage.action?pageId={pageId} "
    if is_output_report == False:
        timeNow = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = [timeNow, url, pageId] + data
    else:
        log_entry = [pageId, url] + data
    
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

def attach_approval_report(pageId, page_log, AUTH):
    # Attach approval macro report to page
    url = f"https://confluence.service.anz/rest/pageApprovals/1/report/attachCSV/{pageId}"

    response = requests.post(url, headers = {"X-Atlassian-Token": "no-check"}, auth=AUTH, verify=False)

    if response.status_code != 200 and response.status_code != 201:
        append_to_log(page_log, pageId, ["Failed", "Could not attach page approval report", f"Status code: {response.status_code}"])


def check_comala_workflow(pageId, AUTH, page_log):
    comalaURL = f"https://confluence.service.anz/rest/cw/1/content/{pageId}/status"

    response = requests.get(comalaURL, auth=AUTH, verify = False)
    if response.status_code == 200:
        append_to_log(page_log, pageId, ["Success", "Comala workflow already exists on page"])
        return True
    return False

def get_page_approval_macro(ns, tree, pageId, page_log):
    # f  the page approval macro and get all the approvers
        # //ac means it searches at every depth, /ac would only search at the root level
        approval_macro_list = tree.xpath("//ac:structured-macro[@ac:name='pageapproval']", namespaces=ns)

        if not len(approval_macro_list):
            # HANDLE CASE: No page approval macro found
            # we have no page approval macro, so we cannot proceed
            append_to_log(page_log, pageId, ["Failed", "No page approval macro found"])
            return None

        elif len(approval_macro_list) > 1:
            # HANDLE CASE: Multiple page approval macros found
            # we have multiple page approval macros, so we log and do not proceed
            append_to_log(page_log, pageId, ["Failed", "Multiple page approval macros found"])
            return None

        else:
            return approval_macro_list[0]


def get_userkeys(ns, page_approval_macro, pageId, page_log):
    # get users parameter in the macro
    users_param = page_approval_macro.xpath('.//ac:parameter[@ac:name="users"]', namespaces=ns)
    if not len(users_param):
        append_to_log(page_log, pageId, ["Failed", "Users parameter not found in page approval macro"])
        return None

    users_param = users_param[0]  # get the first (and only) parameter element

    # get user elements in the users parameter
    user_elems = users_param.xpath(".//ri:user", namespaces=ns)
    if not len(user_elems):
        append_to_log(page_log, pageId, ["Failed", "User elements not found in page approval macro"])
        return None

    userkeys = [user.get('{http://atlassian.com/resource/identifier}userkey') for user in user_elems]
    if not len(userkeys):
        append_to_log(page_log, pageId, ["Failed", "User keys could not be extracted from user elements"])
        return None
    
    print(userkeys)
    return userkeys

def get_allApprovers(ns, userkeys, user_cache, inactive_set, AUTH):
    numApprovers = len(userkeys)
    # final list of page approvers
    allApprovers = []
    for userkey in userkeys:
        # check if userkey is in cache
        if userkey in inactive_set:
            continue

        if userkey in user_cache:
            username = user_cache[userkey]

        else:
            # get the user details from the API
            get_user_url = f"https://confluence.service.anz/rest/api/user?key={userkey}"
            response = requests.get(get_user_url, auth=AUTH, verify=False)

            if response.status_code == 200:
                user_data = response.json()

                display_name = user_data.get("displayName", "")
                
                # Check for "Unknown User"
                if display_name.startswith("Unknown User"):
                    inactive_set.add(userkey)
                    continue

                username = user_data.get("username", "Unknown User")
                user_cache[userkey] = username

        # add user to page approvers list
        allApprovers.append(username)

    # get total approvers on macro to check later
    PageApproversCount = len(allApprovers)

    if len(allApprovers) == numApprovers:
        approvers_message = "all approvers are active"
    elif len(allApprovers) == 0:
        approvers_message = "no approvers are active"
    else:
        approvers_message = f"{len(allApprovers)} out of {numApprovers} approvers are active"

    return allApprovers, PageApproversCount, user_cache, inactive_set, approvers_message  

def get_quorum(ns, PageApproversCount, page_approval_macro):
    # check if page approval macro has quorum
    quorum_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="quorum"]', namespaces=ns)
    # set quorum to all approvers if not set in macro, else get the quorum value
    quorum = PageApproversCount if not len(quorum_elem) else int(quorum_elem[0].text)
    return quorum

def get_page_approval_report(pageId, page_log, AUTH):

        # get all attachments for the page
        get_attachments_url = f"https://confluence.service.anz/rest/api/content/{pageId}/child/attachment"
        response = requests.get(get_attachments_url,headers={"Accept": "application/json", "X-Atlassian-Token": "no-check"}, auth=AUTH, verify=False)

        # if status code is not 200, log the error and continue
        if response.status_code != 200:
            append_to_log(page_log, pageId, ["Failed", f"Failed to get attachments with status code {response.status_code}"])
            return None

        attachments = response.json().get("results", [])
        # if no attachments found, log and continue
        if not len(attachments):
            append_to_log(page_log, pageId, ["Failed", f"No attachments found for page {pageId}."])
            return None

        # print("attachments:\n", attachments)

        # filter attachments for age approval reports
        reports = [a for a in attachments if a["title"].startswith(f"PA_{pageId}_")]
        if not len(reports):
            append_to_log(page_log, pageId, ["Failed", f"No page approval reports found for page {pageId}."])
            return None
            
        # get report with lexicographically latest title
        # NOTE: This is an attempt to get the latest report based on the time stamp in the title but it is not always accurate if a report is uploaded the month before for example, with a later upload day
        latest_report_name = max(reports, key=lambda x: x["title"])["title"]

        # print("latest report name:\n", latest_report_name)

        # download the latest report
        report_download_url = f"https://confluence.service.anz/download/attachments/{pageId}/{latest_report_name}"
        # report_download_url = f"https://confluence.service.anz/download/attachments/3704357336/PA_3704357336_29-05-2025_15-42-03_1748497323105.csv"

        response = requests.get(report_download_url, auth=AUTH, verify=False)
        if response.status_code != 200:
            append_to_log(page_log, pageId, ["Failed", f"Failed to download report with status code {response.status_code}"])
            return None
        
        # read the report into a DataFrame
        report = pd.read_csv(StringIO(response.text))  
        report = report.map(lambda x: x.lstrip("'") if isinstance(x, str) else x)
        report.columns = report.columns.str.lstrip("'")

        return report

def get_expiry(ns, page_approval_macro, pageId):
    expire_after_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="expireafter"]', namespaces=ns)
    expire_after = expire_after_elem[0].text if expire_after_elem else "None"

    expiry_day_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="expiryday"]', namespaces=ns)
    expiry_day = expiry_day_elem[0].text if expiry_day_elem else "None"

    expiry_month_elem = page_approval_macro.xpath('.//ac:parameter[@ac:name="expirymonth"]', namespaces=ns)
    expiry_month = expiry_month_elem[0].text if expiry_month_elem else "None"

    return expire_after, expiry_day, expiry_month

# ALTERNATE CHECK PAGE STATUS FUNCTION
# def check_page_status(report_version, latest_version, latest_rows, quorum):
#     # check if latest version in report matches the latest version of the page
#     if report_version != latest_version:
#         approversWhoHaveApproved = []
#         PageStatus = "Not Approved"
#     else: 
#         approversWhoHaveApproved = list(latest_rows["Approver"])
#         if len(approversWhoHaveApproved) >= quorum:
#             PageStatus = "Page Approved"
#         else:
#             PageStatus = "Not Approved"

def check_page_status(body_view_tree, pageId, page_log):
    status_elem = body_view_tree.xpath('//span[@id="pastatus"]')
    if not status_elem:
        append_to_log(page_log, pageId, ["Failed", "Page status not found in body export view"])
        return None
    
    return status_elem[0].text

def get_latest_approval_date(df): 
    # Strip out the timezone (e.g., AEST)
    df['Approval Date Clean'] = df['Approval Date'].str.replace(r'\s[A-Z]{3,4}', '', regex=True)

    # Now parse without timezone
    df['Approval Date Parsed'] = pd.to_datetime(
        df['Approval Date Clean'],
        format="%a %b %d %H:%M:%S %Y",  # note: no %Z
        errors='coerce'
    )

    print("parsed date:", df['Approval Date Parsed'])

    # Get the latest date
    latest_date = df['Approval Date Parsed'].max()

    return latest_date

def get_expire_after(report, expireAfter):
    unit_to_ms = {
        'second': 1000,
        'minute': 60 * 1000,
        'hour':   60 * 60 * 1000,
        'day':    24 * 60 * 60 * 1000,
        'week':   7 * 24 * 60 * 60 * 1000,
        'month':  30.44 * 24 * 60 * 60 * 1000,   # average month
        'year':   365.25 * 24 * 60 * 60 * 1000   # average year
    }


    print("report:", report)

    quantity, unit = expireAfter.lower().strip().split()
    quantity = int(quantity)
    unit = unit.rstrip('s')  # e.g. "days" → "day"

    if unit not in unit_to_ms:
        return 0000000000000  # Invalid unit, return a placeholder
    
    # the number of milliseconds to add to the current time
    offset = quantity * unit_to_ms[unit]

    latest_date = get_latest_approval_date(report)  # Get the latest approval date from the report
    

    if not latest_date:
        return 0000000000000
    
    # convert date to datetime
    # latest_approval_date = datetime.strptime(latest_date, "%a %b %d %H:%M:%S %Z %Y")

    # convert datetime to ms
    date_ms = int(latest_date.timestamp() * 1000)

    expiry_date = date_ms + offset
    
    return expiry_date





def get_expiry_date(expiry_month, expiry_day, expireAfter, report, pageId, pageStatus, page_log):

    if expiry_month == expiry_day == expireAfter == "None":
        return None

    # if page is approved and we have expireAfter, we use that
    if pageStatus == "Page Approved" and expireAfter != "None":
        expiry_date = get_expire_after(report, expireAfter)
        if expiry_date == 0000000000000:
            append_to_log(page_log, pageId, ["Failed", "Could not calculate expiry date from expireAfter"])
        return expiry_date
    elif expiry_month != "None" and expiry_day != "None":
        today = datetime.today()
        year = today.year

        # Convert inputs to int if they are not None-like
        expiry_month = int(expiry_month)
        expiry_day = int(expiry_day) if expiry_day != "None" else 1  # Default to 1st

        # Construct the candidate expiry date
        candidate = datetime(year, expiry_month, expiry_day)

        # If date already passed, shift to next year
        if candidate < today:
            candidate = datetime(year + 1, expiry_month, expiry_day)

        # Return epoch millis
        return int(candidate.timestamp() * 1000)

    # in the case that there are no valid configs
    return None

def add_comala_workflow(page_log, pageId, quorum, AUTH):

    if quorum > 1:
        minApprovals = f"|minimum={quorum}"
    else:
        minApprovals = ""
        
    # markup to apply comala workflow
    markup = f"""
        {{workflow:name=Migration from page approval to Comala}} 
        {{description}}
            {{The Simple Approval Workflow has 2 states - Not Approved and Approved.}}
        {{description}}
        {{state:Not Approved|approved=Approved|colour=#ffab00|taskable=true}}
            {{approval:Review|assignable=true{minApprovals}}}
        {{state}}
        {{state:Approved|expired=Not Approved|final=true|changeduedate=true|updated=Not Approved}}
        {{state}}
    {{workflow}}
    """

    markup = markup.strip()

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Atlassian-Token": "no-check"
    }

    apply_workflow_url = f"https://confluence.service.anz/rest/cw/1/page/{pageId}"

    # format payload for post request
    payload = {
    "markup": markup
    }

    # print("payload: ", payload)
    
    # # TODO: GET RID OF THIS, ONLY FOR TESTING
    # delete_url = f"https://your-confluence-site/rest/cw/1/page/{pageId}"
    # delete_response = requests.delete(delete_url, headers=headers, auth=AUTH, verify=False)

    # Attach the workflow to the page
    response = requests.put(apply_workflow_url, headers=headers, auth=AUTH, json=payload, verify=False)

    if response.status_code != 200 and response.status_code != 201:
        append_to_log(page_log, pageId, ["Failed", f"Could not apply Comala workflow", f"Status code: {response.status_code}"])
        return False
    else:
        # print(f"Comala workflow applied to page {pageId} successfully.")
        return True

# def approve_comala_workflow(pageId, AUTH, page_log):
#     url = f"https://confluence.service.anz/rest/cw/1/content/{pageId}/approvals/approve"

#     body = {
#     "name": "Review"
#     }

#     headers = {
#         "Accept": "application/json",
#         "Content-Type": "application/json",
#         "X-Atlassian-Token": "no-check"
#     }

#     response = requests.patch(url, headers=headers, auth = AUTH, json=body, verify=False)
    
#     if response.status_code != 200 and response.status_code != 201:
#         append_to_log(page_log, pageId, ["Failed", f"Could not approve Comala workflow, Error {response.status_code}: {response.text}"])
#         return False
#     return True

def approve_comala_workflow(pageId, AUTH, page_log):
    url = f"https://confluence.service.anz/rest/cw/1/content/{pageId}/state"

    body = {
    "name": "Approved"
    }

    # print("body: ", body)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Atlassian-Token": "no-check"
    }

    # check_url = f"https://confluence.service.anz/rest/cw/1/content/{pageId}/status?expand=states,approvals"
    # check_response = requests.get(check_url, headers=headers, auth=AUTH, verify=False)

    # print(check_response.json())


    response = requests.put(url, headers=headers, auth = AUTH, json=body, verify=False)
    
    if response.status_code != 200 and response.status_code != 201:
        append_to_log(page_log, pageId, ["Failed", f"Could not approve Comala workflow, Error {response.status_code}: {response.text}"])
        return False
    # print(f"Workflow for page {pageId} approved successfully.")
    return True


def remove_pa_macro():
    pass

def add_approvers(pageId, allApprovers, AUTH, page_log):
    approversURL = f"https://confluence.service.anz/rest/cw/1/content/{pageId}/approvals/assign"

    assignees = [{"username": user} for user in allApprovers]

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Atlassian-Token": "no-check" 
    }

    payload = {
        "name": "Review",
        "assignees": assignees
    }

    response = requests.patch(approversURL, headers=headers, auth=AUTH, json=payload, verify=False)
    if response.status_code != 200 and response.status_code != 201:
        append_to_log(page_log, pageId, ["Failed", f"Could not add approvers to Comala workflow", f"Status code: {response.status_code}"])
        return False
    else:
        return True

def add_expiry_date(pageId, expiry_date, AUTH, page_log):
    expiryDateURL = f"https://confluence.service.anz/rest/cw/1/content/{pageId}/expirydate"

    response = requests.patch(expiryDateURL, headers={"X-Atlassian-Token": "no-check"}, auth=AUTH, json={"expiry": expiry_date}, verify=False)

    if response.status_code != 200 and response.status_code != 201 and response.status_code != 204:
        append_to_log(page_log, pageId, ["Failed", f"Could not add expiry date to Comala workflow", f"Status code: {response.status_code}"])
        return False
    
    return True


def main(filename):

    username, password = get_credentials()
    AUTH = HTTPBasicAuth(username, password)

    page_log, output_report = initialise_log()

    # List of page IDs to check
    with open(filename, "r") as file:
        pageIds = [line.strip() for line in file if line.strip()]

    ns= {
    'ac': 'http://atlassian.com/content',
    'ri': 'http://atlassian.com/resource/identifier'
    }
    
    # cache to store user id and username mappings
    user_cache = {}

    # set to store inactive users
    inactive_set = set()

    for pageId in pageIds:
        print(f"Processing page ID: {pageId}")

        # get the page body and the current version
        # get_page_url = f"https://confluence.service.anz/rest/api/content/{pageId}?expand=body.storage,version"
        get_page_url = f"https://confluence.service.anz/rest/api/content/{pageId}?expand=body.export_view,body.storage,version"
        # response = requests.get(get_page_url, headers={"Accept": "application/json"}, auth=AUTH, verify=False)
        response = requests.get(get_page_url, headers={"Accept": "application/json"}, auth=AUTH, verify=False)

        # check if get request worked correctly
        if response.status_code != 200:
            if response.status_code == 403:
                append_to_log(page_log, pageId, ["Failed", "403: access not granted"])
            elif response.status_code == 404:
                # HANDLE CASE: Page does not exist/incorrect pageId
                # HANDLE CASE: View Restrictions on page
                append_to_log(page_log, pageId, ["Failed", "404: page does not exist or access not granted"])
            elif response.status_code == 502:
                append_to_log(page_log, pageId, ["Failed", "502: bad gateway, likely proxy error"])
            else:
                append_to_log(page_log, pageId, ["Failed", f"{response.status_code}: page not processed"])
            continue # do not go through rest of process

        # check if there is already a comala workflow on the page
        is_comala_workflow = check_comala_workflow(pageId, AUTH, page_log)
        if is_comala_workflow:
            continue

        
        data = response.json()
        current_body = data["body"]["storage"]["value"]
        body_view = data["body"]["export_view"]["value"]
        latest_version = data["version"]["number"]

        # print("Current body:\n", body_view)  # Just to test

        # Creates an etree parser
        parser = etree.XMLParser(recover=True)

        # Turn our current body into an xml tree so we can process it
        body_storage = etree.fromstring(f"<root xmlns:ac='http://atlassian.com/content' xmlns:ri='http://atlassian.com/resource/identifier'>{current_body}</root>", parser=parser)
        body_view_tree = etree.fromstring(f"<root xmlns:ac='http://atlassian.com/content' xmlns:ri='http://atlassian.com/resource/identifier'>{body_view}</root>", parser=parser)

        # print("Current tree:\n", etree.tostring(tree, pretty_print=True).decode()) # Just to test

        page_approval_macro = get_page_approval_macro(ns, body_storage, pageId, page_log)
        if page_approval_macro is None:
            continue

        userkeys = get_userkeys(ns, page_approval_macro, pageId, page_log)
        if userkeys is None:
            continue
        
        # approvers message is a string telling us whether all approvers are active or not
        allApprovers, PageApproversCount, user_cache, inactive_set, approvers_message = get_allApprovers(ns, userkeys, user_cache, inactive_set, AUTH)

        quorum = get_quorum(ns, PageApproversCount, page_approval_macro)

        expireAfter, expiryDay, expiryMonth = get_expiry(ns, page_approval_macro, pageId)
        
        # attach the page approval report to the page
        # TODO: UNCOMMENT THIS LINE TO ACTUALLY ATTACH THE REPORT
        attach_approval_report(pageId, page_log, AUTH)

        report = get_page_approval_report(pageId, page_log, AUTH)
        if report is None:
            continue

        # print("Report:\n", report)  # Just to test

        # Ensure version column is numeric
        report["Page Version"] = pd.to_numeric(report["Page Version"], errors="coerce")

        # Find the latest version number
        report_version = report["Page Version"].max()

        # Filter rows where version equals the latest
        latest_rows = report[report["Page Version"] == report_version]

        if report_version != latest_version:
            approversWhoHaveApproved = []
        else: 
            approversWhoHaveApproved = list(latest_rows["Approver"])

        # CALL TO ALTERNATE CHECK PAGE STATUS FUNCTION
        # pageStatus = check_page_status(report_version, latest_version, latest_rows, quorum)
        pageStatus = check_page_status(body_view_tree, pageId, page_log)
        if pageStatus is None:
            continue
        
        # print("Page status:", pageStatus)
        #TODO: get page status from body export view
        
        append_to_log(output_report, pageId, [pageStatus, PageApproversCount, quorum, allApprovers,  approversWhoHaveApproved, expireAfter, expiryDay, expiryMonth], True)

        # add comala workflow to page
        comala_workflow_added = add_comala_workflow(page_log, pageId, quorum, AUTH)
        if not comala_workflow_added:
            continue
        
        # if page is approved, make approval status True
        if pageStatus == "Page Approved":
            page_approved = approve_comala_workflow(pageId, AUTH, page_log)
            if not page_approved:
                continue
        else:
            approvers_added = add_approvers(pageId, allApprovers, AUTH, page_log)
            if not approvers_added:
                continue
        
        expiry_date = get_expiry_date(expiryMonth, expiryDay, expireAfter, report, pageId, pageStatus, page_log)
        # None means no date, 0000000000000 means could not get date
        if expiry_date == 0000000000000:
            # HANDLE CASE: Could not get expiry date
            append_to_log(page_log, pageId, ["Failed", "Could not get expiry date"])
            continue

        if expiry_date is not None:
            expiry_date_added = add_expiry_date(pageId, expiry_date, AUTH, page_log)
            if not expiry_date_added:
                continue


        append_to_log(page_log, pageId, ["Success", "Page processed successfully, " + approvers_message])


if len(sys.argv) != 2:
    print("Usage: python script.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

main(filename)