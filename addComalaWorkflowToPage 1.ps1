# Change working directory to location of current script
Set-Location $PSScriptRoot -ErrorAction Stop

$baseUrl = "http://psdca20l.unix.anz:8094"
#$baseUrl = "https://confluence.service.anz"
$username = "confluenceadmin"
$password = "SX5JNU5QPCI6VNZE2BBSBMWOYG5PDDFMRFBPM64FUJJ4QW3FFQTWPFZW3IRN77B5W4A3R4IMZVQEL5AFONTPCZAHNAXRKCE5BGHD2XQ5BAOBRZW73HM7JQPIPJLU5SRO"

# Convert username and password to Base64 for Basic Authentication
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))

$PageInfoFilePath = 'pageInfo.csv'
$PageMigrationResultsFilePath = 'pageMigrationResults.csv'
$pages = Import-Csv -Path $PageInfoFilePath

foreach ($page in $pages) {
    try {
        if($page.pageId -eq '') {
            throw "PageID is empty"
        }
        
        $pageId = $page.pageId
        "PageId: $pageId"
        #$expiryDate = [datetime]::Parse($page.expiryDate).ToString('yyyy-MM-dd hh:mm')
        $expireAfter = $page.expireAfter
        $pageStatus = $page.pageStatus
        $approvers = $page.pageApprovers
        $approversCount = $Page.pageApproversCount
        $approval = $null
        if($approvers -ne '' -and $approversCount -gt 0) {
            $approval = "{approval:Review|minimum=$($approversCount)|user=$($approvers)}"
        }

        try {   

            # Set proper headers
            $headers = @{
                'Accept' = 'application/json'
                'Content-Type' = 'application/json'
                'Authorization' = "Basic $base64AuthInfo"
            }

            # Specify HTTP method
            $method = "PUT"

            # Construct the REST API URL to add page workflow
            $pageUrl = "$baseUrl/rest/cw/1/page/$pageId"

            $body = @{
"markup"= @"
{workflow:name=Migration from page approval to Comala }
    {description}
        The Simple Approval Workflow has 2 states - Not Approved and Approved.
    {description}
    {state:Not Approved|approved=Approved|colour=#ffab00|taskable=true}
        $approval
    {state}
    {state:Approved|expired=Not Approved|final=true|duedate=$($expireAfter)|updated=Not Approved}
    {state}
{workflow}
"@
} | ConvertTo-Json

            # Send HTTP request
            $response = Invoke-RestMethod -Uri $pageUrl -Method $method -Headers $headers -Body $body -ErrorAction Stop
            if($response.message) {
                throw $response.message
            }
            "Page added with comola workflow"
        }
        catch {
            throw "Page with id: ContentId{id=$pageId} failed while adding comola workflow, Error: $($_.Exception.Message)"
        }
        
        $pageState = $null
        if($pageStatus -eq 'Page Approved') {
            $pageState = 'Approved'
        } else {
            $pageState = 'Not Approved'
        }

        try {
            # Set proper headers
            $headers = @{
                'Accept' = 'application/json'
                'Content-Type' = 'application/json'
                'Authorization' = "Basic $base64AuthInfo"
            }

            # Specify HTTP method
            $method = "PUT"

            # Construct the REST API URL to transition to Approved state
            $pageUrl = "$baseUrl/rest/cw/1/content/$pageId/state"

            $body = @{
                'name' = $pageState
            } 

            # Send HTTP request
            $response = Invoke-RestMethod -Uri $pageUrl -Method $method -Headers $headers -Body $body -ErrorAction Stop

            if($response.message) {
                throw $response.message
            } elseif($response.state.name -ne $pageState) {
                throw "Page state failed to transition to $pageState, Current value: $($response.state.name)"
            }

            "Page state set to $pageState"
        }
        catch {
            throw "Page with id: ContentId{id=$pageId} failed while transitioning to $pageState state, Error: $($_.Exception.Message)"
        }

        try {
            # Set proper headers
            $headers = @{
                'Accept' = 'application/json'
                'Authorization' = "Basic $base64AuthInfo"
            }

            # Specify HTTP method
            $method = "get"

            # Construct the REST API URL to get approval data
            $pageUrl = "$baseUrl/rest/cw/1/content/$pageId/status"+"?expand=states,approvals"

            # Send HTTP request
            $response = Invoke-RestMethod -Uri $pageUrl -Method $method -Headers $headers -ErrorAction Stop

            if($response.message) {
                throw $response.message
            }

            $response.states | ForEach-Object {
                if($_.name -eq 'Approved') {
                    if($_.dueDate -ne $expireAfter.ToUpper() -and $expireAfter -ne '') {
                        throw "Page duedate not set to $expireAfter, Current value: $($_.dueDate)"
                    } else {
                        "Page duedate: $expireAfter"
                    }
                } elseif($_.name -eq 'Not Approved') {
                    if($approval -ne '' -and $_.approvals.count -gt 0) {
                        if($_.approvals.name -ne 'Review') {
                            throw "Page not added with approval 'Review', Current value: $($_.approvals.name)"
                        } else {
                            "Page approval name: $($_.approvals.name)"
                        }
                    } else {
                        "Page do not need approvals to be configured" 
                    }
                }
            }
        }
        catch {
            throw "Page with id: ContentId{id=$pageId} failed to get comola workflow info, Error: $($_.Exception.Message)"
        }

        $page | Add-Member -MemberType NoteProperty -Name "migrationStatus" -Value 'Successful'
    }
    catch {
        Write-Host -Object $_.Exception -ForegroundColor DarkRed
        $page | Add-Member -MemberType NoteProperty -Name "migrationStatus" -Value $_.Exception
    }
}

$pages | Export-Csv -Path $PageMigrationResultsFilePath -NoTypeInformation