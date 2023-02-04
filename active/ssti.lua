SCAN_TYPE = 2

local function send_report(url,parameter,payload,matching_error)
    VulnReport:setName("Template Injection")
    VulnReport:setDescription("https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection")
    VulnReport:setRisk("high")
    VulnReport:setUrl(url)
    VulnReport:setParam(parameter)
    VulnReport:setAttack(payload)
    VulnReport:setEvidence(matching_error)
    print_vuln_report(VulnReport)
end

SSTI_PAYLOADS = {
    "lot{{2*2}}us",
    "lot${2*2}us",
    "lot${% 2*2 %}us",
    "lot{% 2*2 %}us",
    "lot<%= 2*2 %>us"
}

function scan_ssti(param_name,payload)
    local new_url = HttpMessage:setParam(param_name,payload)
    local resp_status,resp = pcall(function ()
        return http:send("GET",new_url) -- Sending a http request to the new url with GET Method
    end)
        if resp_status == true then
            local out = {}
            local body = resp.body -- Get the response body as string
            out["body"] = body
            out["url"] = resp.url
            out["param_name"] = param_name
            out["payload"] = payload
            return out
        end
end

function ssti_callback(data)
    if data == nil then
        return -- avoid nil cases
    end
    url = data["url"]
    body = data["body"]
    payload = data["payload"]
    param_name = data["param_name"]
    local match_status, match = pcall(function () 
        -- Matching with the response and the targeted regex
        -- we're using pcall here to avoid regex errors (and panic the code)
        return str_contains(body, "lot4us")
    end)
    if match_status == true then
        if match == true then
            send_report(url,param_name,payload,"lot4us")
            Reports:addVulnReport(VulnReport)
        end
    end
end

function main()
    for _,param in ipairs(HttpMessage:getParams()) do
        ParamScan:add_scan(param,SSTI_PAYLOADS, scan_ssti,ssti_callback, 5)
        ParamScan:start_scan()
    end
end
