-- Define constant values
SCAN_TYPE = 2 -- FULL URL INPUT 
local urlparse = require "libs.net.url"
local MATCH_HOST = "exdata.so"
local REDIRECT_PAYLOADS = readfile(JOIN_SCRIPT_DIR("txt/redirect.txt"))

-- Define a function to send a vulnerability report
local function send_report(url, parameter, payload, matching_error)
    local report = {
        name = "Open Redirect",
        description = "https://www.zaproxy.org/docs/alerts/10028/",
        url = url,
        parameter = parameter,
        attack = payload,
        evidence = matching_error,
    }
    Reports:add(report)
end

local function table_payloads()
    PAYLOADS = {}
    for redirect_payload in REDIRECT_PAYLOADS:gmatch("[^\r\n]+") do
        table.insert(PAYLOADS,redirect_payload)
    end
    return PAYLOADS
end
-- Define a function to scan for Open Redirect vulnerabilities
local function scan_redirect(param_name, payload)
   local new_url = HttpMessage:setParam(param_name, payload,true)
   local resp_status, resp = pcall(function ()
      -- Sending an HTTP request to the new URL with GET method
      return http:send{url = new_url, redirect=1}
   end)
   if resp_status == true then
      -- Get the response body as a string
      local location = resp.headers["location"]
      if location ~= nil then
          local location_host = urlparse.parse(location).host
          local out = {
             location = location_host,
             url = resp.url,
             param_name = param_name,
             payload = payload
          }
          return out
      end
   end
end

-- Define a function to handle SQL injection vulnerabilities
local function redirect_callback(data)
   local url = data.url
   local location = data.location
   local payload = data.payload
   local param_name = data.param_name
   if location == MATCH_HOST then
     -- Send a vulnerability report and stop the parameter scan
     send_report(url, param_name, payload, location)
     ParamScan:stop_scan()
   end
end

-- Define the main function to initiate the parameter scan
function main()
   local PAYLOADS = table_payloads()
   for _, param in ipairs(HttpMessage:Params()) do
      ParamScan:start_scan()
      ParamScan:add_scan(param, PAYLOADS, scan_redirect, redirect_callback, FUZZ_WORKERS)
   end
end
