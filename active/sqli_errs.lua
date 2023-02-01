SQLI_ERRORS = readfile(JOIN_SCRIPT_DIR("txt/sqli_errs.txt"))
SCAN_TYPE = 2 -- ACCEPT FULL TARGET URL 

PAYLOADS = {
    "'123",
    "''123",
    "`123",
    "\")123",
    "\"))123",
    "`)123",
    "`))123",
    "'))123",
    "')123\"123",
    "[]123",
    "\"\"123",
    "'\"123",
    "\"'123",
    "\123",
}

local function send_report(url,parameter,payload,matching_error)
    VulnReport:setName("SQL Injection")
    VulnReport:setDescription("https://owasp.org/www-community/attacks/SQL_Injection")
    VulnReport:setRisk("high")
    VulnReport:setUrl(url)
    VulnReport:setParam(parameter)
    VulnReport:setAttack(payload)
    VulnReport:setEvidence(matching_error)
    print_vuln_report(VulnReport)
end

local function matcher(payload)
    for _, param_name in pairs(HttpMessage:getParams()) do 
        local new_url = HttpMessage:setParam(param_name,payload)
        local resp_status,resp = pcall(function ()
            return http:send("GET",new_url)
        end)
        if resp_status == true then
            local body = resp.body:GetStrOrNil()
            for sqlerror_match in SQLI_ERRORS:gmatch("[^\n]+") do
                local status, match = pcall(function () 
                    return is_match(sqlerror_match,body)
                end)
                if status == true then
                    if match == true then
                        send_report(resp.url:GetStrOrNil(),param_name,payload,sqlerror_match)
                        Reports:addVulnReport(VulnReport)
                        break
                    end

                end
            end
        end
    end
end

function main() 
    ParamScan:add_scan(PAYLOADS, matcher, 5)
end
