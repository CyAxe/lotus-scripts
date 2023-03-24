-- Constants
SCAN_TYPE = 2 -- FULL URL INPUT 
local MATCH_HOST = "exdata.so"
local REDIRECT_PAYLOADS = readfile(JOIN_SCRIPT_DIR("txt/redirect.txt"))

-- Libraries
local urlparse = require "libs.net.url"

-- Define a function to send a vulnerability report
local function send_report(url, param_name, payload, matching_error)
    local report = {
        name = "Open Redirect",
        description = "https://www.zaproxy.org/docs/alerts/10028/",
        url = url,
        parameter = param_name,
        attack = payload,
        evidence = matching_error,
    }
    Reports:add(report)
end

-- Define a function to scan for Open Redirect vulnerabilities
local function scan_redirect(param_name, payload)
    local new_url = HttpMessage:setParam(param_name, payload, true)
    local resp_status, resp = pcall(function()
        -- Sending an HTTP request to the new URL with GET method
        return http:send{url = new_url, redirect = 1}
    end)
    if resp_status and resp.headers["location"] then
        local location_host = urlparse.parse(resp.headers["location"]).host
        return {
            location = location_host,
            url = resp.url,
            param_name = param_name,
            payload = payload
        }
    end
end

-- Define a function to handle SQL injection vulnerabilities
local function redirect_callback(data)
    if data.location == MATCH_HOST then
        -- Send a vulnerability report and stop the parameter scan
        send_report(data.url, data.param_name, data.payload, data.location)
        ParamScan:stop_scan()
    end
end

-- Define the main function to initiate the parameter scan
function main()
    local payloads = {}
    for redirect_payload in REDIRECT_PAYLOADS:gmatch("[^\r\n]+") do
        table.insert(payloads, redirect_payload)
    end
    for _, param in ipairs(HttpMessage:Params()) do
        ParamScan:start_scan()
        ParamScan:add_scan(param, payloads, scan_redirect, redirect_callback, FUZZ_WORKERS)
    end
end
