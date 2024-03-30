-- Author: Mohamed Tarek @0xr00t3d

SCAN_TYPE = 2
BODY_MATCH = { "branches", "listing", "Index of" }

function main()
    local url = HttpMessage:urljoin(".git/")
    local status, resp = pcall(function()
        return http:send { url = url }
    end)

    local body = resp["body"]

    if
        status == true
        and resp.status == 200
        and Matcher:match_body_once(body, BODY_MATCH)
    then
        Reports:add {
            name = "Git repository found",
            url = url,
            risk = "High",
            description = "https://www.acunetix.com/vulnerabilities/web/git-repository-found/",
        }
    end
end
