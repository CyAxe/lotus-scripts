-- JOIN PATH TO SCRIPT PATH
function join_script_dir(path)end

Reports = {}
http = {}
Matcher = {}

function pathjoin(current_path, new_path)end

-- base64encode
function base64encode(data)end

-- base64decode 
function base64decode(b64data)
    
end

-- Sending http request
-- * `method` http method
-- * `url` target url
-- * `body` request body
-- * `headers` request headesr in table
-- * `redirects` number of redirects for this request
--
-- Example:
--
-- ```lua
-- local status, resp = pcall(function() 
--      return http:send{method = "POST" ,url = "http://example.com/", headers = {"X-API": "123"})
--end)
--
-- ```
function http.send(self,request_opts)
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


-- is this text matched with Regex Pattern
-- * `text` String
-- * `regex` String
function Matcher.is_match(self,regex, text) end

-- Saving the Report in the JSON output
function Reports:add(self, report_table)end

-- Print new line above the progress bar
function println(text)end
    
-- Set Delay for the script
function sleep(delay_time)end

-- reading files
function readfile(file_path)end

-- error log
function log_error(txt)end

-- info log
function log_info(txt)end

-- warn log
function log_warn(txt)end

-- debug log
function log_debug(txt)end




-- Ensures that the response body matches the specified list based on the 'and' condition
-- Parameters:
-- * `body` (String)
-- * `text_list` (table)
function Matcher:match_body(self, body, text_list) end

-- Checks if the response matches with any one item from the specified strings list
-- Parameters:
-- * `body` (String)
-- * `text_list` (Table)
-- * `is_regex` (boolean)
function Matcher:match_body_once(self, body, text_list, is_regex) end

-- Replaces a string with another one using regular expressions
-- Parameters:
-- * `body` (String)
-- * `regex` (String)
-- * `replacement` (String)
function Matcher:replace(self, body, regex, replacement) end

-- Extracts a substring from the response that matches the specified regular expression
-- Parameters:
-- * `regex` (String)
-- * `response` (String)
function Matcher:extract(self, regex, response) end

-- Sets options for the regular expression matcher
-- Parameters:
-- * `regex_opts_table` (table)
function Matcher:options(self, regex_opts_table) end

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


function ParamScan() end

function ParamScan:start_scan(self)end
function ParamScan:add_scan(self,shared_item, shared_iterator, target_function, callback_function, workers_number)end
function ParamScan:is_stop(self)end
