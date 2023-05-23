-- AUTHOR: Mohamed Tarek @0xr00t3d
-- Reference: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion

SCAN_TYPE = 2

local LFI_PAYLOADS = readfile(join_script_dir("txt/lfi.txt"))
-- this list of regex patterns can be extended,but to keep it simple this just matches for /etc/passwd
local PATTERNS = {
    "root:.*:0:0:",
}

function scan(target_param, target_payload)
    local new_url = HttpMessage:param_set(target_param, target_payload, true)
    local status, resp = pcall(function()
        return http:send { url = new_url }
    end)

    if status ~= true then
        return
    end

    local body = resp["body"]

    for _, pattern in ipairs(PATTERNS) do
        if Matcher:is_match(pattern, body) then
            local report = {
                url = new_url,
                param = target_param,
                risk = "High",
                payload = target_payload
            }

            return report
        end
    end
end

local function make_str_iter()
    local payloads = {}
    for payload in LFI_PAYLOADS:gmatch("[^\r\n]+") do
        table.insert(payloads, payload)
    end
    return payloads
end

function scan_callback(report_data)
    local url = report_data["url"]
    local param = report_data["param"]
    local risk = report_data["risk"]
    local payload = report_data["payload"]

    Reports:add {
        name = "[LFI] Local File Inclusion",
        url = url,
        parameter = param,
        risk = risk,
        payload = payload
    }
end

function main()
    for _, param_name in ipairs(HttpMessage:param_list()) do
        ParamScan:add_scan(param_name, make_str_iter(), scan, scan_callback, FUZZ_WORKERS)
    end
end
