-- waybackurls target.com | lotus scan extractfromjs.lua 
SCAN_TYPE = 3
local REGEX_PATTENR = [[(?:"|')(\/[\w\d\xA0-\xFF?/&=#.!:_-]*?)(?:"|')]]

function removeFirstAndLastChar(str)
    local the_str = str:sub(2, -2)
    if ENV["urljoin"] ~= true then
        return the_str
    else
        url_parse = HttpMessage:clone()
        return url_parse:urljoin(the_str)
    end
end

function removeDuplicates(list)
    local uniqueValues = {}
    local result = {}

    for _, value in ipairs(list) do
        if not uniqueValues[value] then
            uniqueValues[value] = true
            table.insert(result, value)
        end
    end

    return result
end

function main()
    local status,resp = pcall(function ()
        return http:send{ method = "GET", url = HttpMessage:url()}
    end)
    if status ~= false then
        local extracts = removeDuplicates(Matcher:extract(REGEX_PATTENR,resp["body"]))
        local results = {}

        for _, value in ipairs(extracts) do
            table.insert(results,removeFirstAndLastChar(value))
        end
        if #results == 0 then
            -- Nothing
        else
            Reports:add {
                endpoint = HttpMessage:url(),
                full_results = results
            }
        end
    end
end
