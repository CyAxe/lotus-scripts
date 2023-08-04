-- AUTHOR: Mohamed Tarek @0xr00t3d
-- Reference: https://hackerone.com/reports/403402

SCAN_TYPE = 2

PAYLOADS = {
    "/script/",
}

MATCHERS = {
    "println(Jenkins.instance.pluginManager.plugins)",
    "Script Console",
    "Scriptconsole"
}

function main()
    for _, path in pairs(PAYLOADS) do
        local new_url = HttpMessage:urlJoin(path)
        local status, resp = pcall(function()
            return http:send { url = new_url }
        end)

        local body = resp["body"]
        local status_code = resp["status"]

        for _, matcher in ipairs(MATCHERS) do
            if str_contains(body, matcher) and status_code == 200 then
                Reports:add {
                    name = "[RCE] Unsecure Jenkins Instance",
                    url = new_url,
                    risk = "critical",
                    description = "remote code execution vulnerability due to accessible script functionality.",
                    evidence = new_url,
                }
                break
            end
        end
    end
end
