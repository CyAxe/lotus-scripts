SCAN_TYPE = 2
local SQLI_MATCH = readfile(JOIN_SCRIPT_DIR("txt/sqli_errs.txt"))

local function send_report(url,parameter,payload,matching_error)
    VulnReport:setName("SQL INJECTION")
    VulnReport:setDescription("https://owasp.org/www-community/attacks/SQL_Injection")
    VulnReport:setRisk("high")
    VulnReport:setUrl(url)
    VulnReport:setParam(parameter)
    VulnReport:setAttack(payload)
    VulnReport:setEvidence(matching_error)
    Reports:addVulnReport(VulnReport)
    print_vuln_report(VulnReport)
end

SQLI_ERRORS_PAYLOADS = {
    "'",
    '"',
    'sTring',
    'gso',
    '424',
    '*/-'
}


function scan_sqlerr(param_name,payload)
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

function sqlerr_callback(data)
    local url = data["url"]
    local body = data["body"]
    local payload = data["payload"]
    local param_name = data["param_name"]
    for match_regex,_ in SQLI_MATCH:gmatch("([^\n]*)\n?") do
        local match_status, matched = pcall(function ()
            -- Matching with the response and the targeted regex
            -- we're using pcall here to avoid regex errors (and panic the code)
            return is_match(match_regex,body)
        end)
        if match_status == true then
            if matched == true then
                send_report(url,param_name,payload,match_regex)
                Reports:addVulnReport(VulnReport)
                ParamScan:stop_scan()
                break
            end
        end
    end
end

function main()
    for _,param in ipairs(HttpMessage:Params()) do
        ParamScan:start_scan()
        ParamScan:add_scan(param,SQLI_ERRORS_PAYLOADS, scan_sqlerr,sqlerr_callback, FUZZ_WORKERS)
    end
end
