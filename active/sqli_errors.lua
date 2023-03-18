-- Define constant values
SCAN_TYPE = 2 -- FULL URL INPUT 
local SQLI_MATCH = readfile(JOIN_SCRIPT_DIR("txt/sqli_errs.txt"))

-- Define a function to send a vulnerability report
local function send_report(url, parameter, payload, matching_error)
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

-- Define a function to scan for SQL injection vulnerabilities
local function scan_sqli(param_name, payload)
   local new_url = HttpMessage:setParam(param_name, payload)
   local resp_status, resp = pcall(function ()
      -- Sending an HTTP request to the new URL with GET method
      return http:send{url = new_url}
   end)
   if resp_status == true then
      -- Get the response body as a string
      local out = {
         body = resp.body,
         url = resp.url,
         param_name = param_name,
         payload = payload
      }
      return out
   end
end

-- Define a function to handle SQL injection vulnerabilities
local function sqli_callback(data)
   local url = data.url
   local body = data.body
   local payload = data.payload
   local param_name = data.param_name
   -- Iterate through the SQL injection patterns and try to match them in the response body
   for sql_regex in SQLI_MATCH:gmatch("[^\r\n]+") do
      local match_status, match = pcall(function ()
         -- Matching with the response and the targeted regex
         -- we're using pcall here to avoid regex errors (and panic the code)
         return is_match(sql_regex, body)
      end)
      if match_status == true and match == true then
         -- Send a vulnerability report and stop the parameter scan
         send_report(url, param_name, payload, sql_regex)
         ParamScan:stop_scan()
      end
   end
end

-- Define the main function to initiate the parameter scan
function main()
   local payloads = {"'", '"'}
   for _, param in ipairs(HttpMessage:Params()) do
      ParamScan:start_scan()
      ParamScan:add_scan(param, payloads, scan_sqli, sqli_callback, FUZZ_WORKERS)
   end
end
