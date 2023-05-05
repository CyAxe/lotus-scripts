SCAN_TYPE = 3
PHPINFO = {
    "php.php",
    "phpinfo.php",
    "info.php",
    "infophp.php",
    "php_info.php",
    "test.php",
    "i.php",
    "asdf.php",
    "pinfo.php",
    "phpversion.php",
    "time.php",
    "index.php",
    "temp.php",
    "old_phpinfo.php",
    "infos.php",
    "linusadmin-phpinfo.php",
    "php-info.php",
    "dashboard/phpinfo.php",
    "_profiler/phpinfo.php",
    "_profiler/phpinfo",
    "?phpinfo=1"
}


function send_report(url,matches)
    Reports:add {
        name = "PHPinfo Page - Detect",
        risk = "low",
        description = "PHPinfo page was detected. The output of the phpinfo() command can reveal sensitive and detailed PHP environment information",
        matches = matches,
        url = url
    }
end
function find_phpinfo(phpinfo_path)
    local new_path = HttpMessage:urljoin(phpinfo_path)
    local resp = http:send {
        url = new_path
    }
    local body = resp.body
    local re = [[>PHP Version ([0-9.]+)]]
    local is_matching = Matcher:match_body(body,{"PHP Extension","PHP Version"})
    local extracted_re = Matcher:extract(re,body)
    if resp.status == 200 and #extracted_re > 0 and is_matching == true then
        send_report(new_path, extracted_re)
        LuaThreader:stop_scan()
    end
end

function main()
    LuaThreader:run_scan(PHPINFO,find_phpinfo,FUZZ_WORKERS)
end
