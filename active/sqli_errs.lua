SQLI_ERRORS = read(JOIN_SCRIPT_DIR("txt/sqli_errs.txt"))

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
    print_report(VulnReport)
end

function matcher(param_name)
    STOP_PARAM = false
    for payload_index, payload in pairs(PAYLOADS) do 
        local new_url = HttpMessage:setParam(param_name,payload)
        local resp = http:send("GET",new_url)
        local body = resp.body:GetStrOrNil()
        if STOP_PARAM == true then
            break
        end
        for sqlerror_match in SQLI_ERRORS:gmatch("[^\n]+") do
                local match = is_match(sqlerror_match,body)
                if ( match == false or match == nil) then
                        -- NOTHING
                else
                    send_report(resp.url:GetStrOrNil(),param_name,payload,sqlerror_match)
                    Reports:addVulnReport(VulnReport)
                    STOP_PARAM = true
                    break
                end
        end
    end
end

function main(url) 
    LuaThreader:run_scan(HttpMessage:getParams(), matcher, 30)
end
