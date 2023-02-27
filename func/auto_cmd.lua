
-- Generate XSS Payloads based on the location of the payload
-- for example: Location = AttrValue, payload = " onerror=alert(1)
function XSSGenerate(payload_location, response, payload)

end

-- CveReport 
function CveReport()end

function Reports()end
function HttpMessage()end
function http()end
function ResponseMatcher()end

-- pathjoin
-- path join function can be used for urlpath join to avoid duplicates output 
function pathjoin(current_path, new_path)end


-- base64encode
function base64encode(data)
    
end

-- base64decode 
function base64decode(b64data)
    
end

-- Print the report in CLI
function print_report(report)
    
end

-- Sending http request
-- * `method` http method
-- * `url` target url
-- * `body` request body
-- * `headers` request headesr in table
--
-- Example:
--
-- ```lua
-- local status, resp = pcall(function() 
--      return http:send("GET","http://example.com/",nil,{"X-API": "123"})
--end)
--
-- ```
function http.send(self,method, url,body, headers)

end


-- Set Custom http Proxy url for the script
-- * `proxy_url` String
--
-- Example: 
--
-- `http:set_proxy('http:set_proxy('http://localhost:8080/')')`
function http.set_proxy(self, proxy_url)
    
end

-- Set the max http redirects
-- * `many_redirects` integer
-- Example: 
--
-- `http:set_redirects(3)`
function http.set_redirects(self,many_redirects)
    
end
    

-- Set CVE Report Risk
-- * `setRisk` ["high","medium","low"]
function CveReport:setRisk(self,risk)
    
end


-- Set CVE Report Name
-- * `setName` String
function CveReport:setName(self, setName)
    
end


-- Set CVE Report Description
-- * `setDescription` String
function CveReport:setDescription(self, description)
    
end

-- is this text matched with Regex Pattern
-- * `text` String
-- * `regex` String
function is_match() end

-- Print The CveReport in the console
-- * `CVE_REPORT` - CveReport Class
function print_cve_report(CVEREPORT)end

-- Saving the CVE Report in the JSON output
-- * `CVE_REPORT` - CveReport Class
function Reports:addCveReport(self, CVEREPORT)end

-- Saving the VULN Report in the JSON output
-- * `VULN_REPORT` - VulnReport Class
function Reports:addVulnReport(self, VULNREPORT)end

-- Add CVE Report Matchers
-- You can use this with multiaple lines to add all matches in one list
--```lua
--  CveReport:addMatcher("MATCHED_DATA", MATCH_ID)
--
--```
-- 1 = RawResponse (full response)
--
--
-- 2 = Response Headers
--
--
-- 3 = Reponse Body
--
--
-- 4 = Status Code
--
--
-- above 4 = General
function CveReport:addMatcher(self,match_string, match_id)end

-- Set CVE Report URL
-- * `url` String
function CveReport:setUrl(self, url)end

-- Print new line above the progress bar
function println(text)end
    
-- Set Delay for the script
function sleep(delay_time)end

-- reading files
function read(file_path)end

-- error log
function log_error(txt)end

-- info log
function log_info(txt)end

-- warn log
function log_warn(txt)end

-- debug log
function log_debug(txt)end


-- Regex matching
function is_match(pattern, text)
    
end

-- Generate CSS Selector Pattern for XSS Payloads
function generate_css_selector(payload)
    
end


-- Searching in HTML for the location of custom payload
-- for example, html_search("<h1 align='righthacker'>yes</h1>","hacker") -> Location:AttrValue
function html_parse(html_data, payload)
    
end

-- Searching in HTML with CSS Selector Pattern
-- Return `String`
function html_search(html_data, css_pattern)
    
end



-- Making sure that the response body matches the list by the `and` condition
-- * `body` String
-- * `text_list` table
function ResponseMatcher:match_body(self,body, txt) end


-- is the string startswith X or not
-- * `txt` - String
-- * `txt2` - String
-- Example
--
-- ```lua
-- str_startswith("Hello World","Hello")
--```
function str_startswith(text, txt2)end

-- is the string contains X or not
-- * `txt` - String
-- * `txt2` - String
-- Example
--
-- ```lua
-- str_contains("Hello World, WE ARE USING LUA FOR WEB Security YAYYYYYYy","USING")
--```
function str_contains(text,txt2)end
