-- waybackurls target.com | lotus scan extractfromjs.lua 
SCAN_TYPE = 3
local REGEX_PATTENR = [[(?:"|')(\/[\w\d\xA0-\xFF?/&=#.!:_-]*?)(?:"|')]]

function removeFirstAndLastChar(str)
    return str:sub(2, -2)
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
        Reports:add{
            results = results
        }
    end
end
