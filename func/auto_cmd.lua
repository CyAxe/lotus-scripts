
-- Generate XSS Payloads based on the location of the payload
-- for example: Location = AttrValue, payload = " onerror=alert(1)
function XSSGenerate(payload_location, response, payload)

end

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
function http.send(self,method, url,body, headers)

end
    

-- Print new line above the progress bar
function println(text)
end
    
-- Delay
function sleep(delay_time)
end

-- reading files
function read(file_path)
end

-- error log
function log_error(txt)
    
end

-- info log
function log_info(txt)
    
end

-- warn log
function log_warn(txt)
    
end

-- debug log
function log_debug(txt)
    
end


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


