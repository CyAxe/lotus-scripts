-- require("../func/auto_cmd")
PAYLOADS = read(string.format("%s/txt/xss.txt",SCRIPT_PATH))
local function send_report(url,parameter,payload)
    VulnReport:setName("reflected cross site scripting")
    VulnReport:setDescription("https://owasp.org/www-community/attacks/xss/")
    VulnReport:setRisk("medium")
    VulnReport:setUrl(url)
    VulnReport:setParam(parameter)
    VulnReport:setAttack(payload)
    VulnReport:setEvidence(generate_css_selector(payload))
    print_report(VulnReport)
end

local function gethtmlLocation(the_location)
    if the_location:GetAttrValueOrNil() ~= nil then
        return the_location:GetAttrValueOrNil() 
    end
    if the_location:GetAttrNameOrNil() ~= nil then
        return the_location:GetAttrNameOrNil()
    end
    if the_location:GetTextOrNil() ~= nil then
        return the_location:GetTextOrNil()
    end

    if the_location:GetCommentOrNil() ~= nil then
        return the_location:GetCommentOrNil()
    end
end

function main(url)
    local resp = http:send("GET",HttpMessage:getUrl())
    if resp.errors:GetErrorOrNil() then
        local log_msg = string.format("[RXSS] Connection Error: %s",new_url)
        log_error(log_msg)
        return
    end

    local body = resp.body:GetStrOrNil()
    local headers = resp.headers:GetHeadersOrNil()
    local content_type = headers["content-type"]
    if content_type ~= nil then
        if string.find(content_type,"html") then
            for payload in PAYLOADS:gmatch("[^\n]+") do
                new_querys = HttpMessage:setAllParams("testxss")
                for param_name, pay_url in pairs(new_querys) do
                    -- Generate Css Selector pattern to find the xss payload in the page
                    local body = http:send("GET",pay_url).body:GetStrOrNil()
                    if body ~= nil then
                        local ref_html = html_parse(body,"testxss")
                        for index, value in ipairs(ref_html) do
                            local ref_location = gethtmlLocation(value)
                            local generated_payload = XSSGenerator(body, value, "testxss")
                            for index, value in pairs(generated_payload) do
                                local xss_urlquery = HttpMessage:setParam(param_name,value.payload)
                                local req = http:send("GET", xss_urlquery)
                                local body = req.body:GetStrOrNil() 
                                local searcher = html_search(body,value.search)
                                if string.len(searcher) > 0 then
                                    send_report(req.url:GetStrOrNil(),param_name,value.payload)
                                    Reports:addReport(VulnReport)
                                    break
                                end
                            end
                        end
                    end
                    --[[
                    local css_pattern = generate_css_selector(payload)
                    if string.len(css_pattern) > 0 then
                        -- Search in the response body with the Css Selector pattern of the payload
                        local resp = http:send("GET", pay_url)
                        local body = resp.body:GetStrOrNil()
                        local searcher = html_search(body,css_pattern)
                        if string.len(searcher) > 0 then
                            send_report(resp.url:GetStrOrNil(),param_name,payload)
                            Reports:addReport(VulnReport)
                        end

                    end
                    --]]
                end
            end
        end
    end
end
