SCAN_TYPE = 2
local TIMEBASED_PAYLOADS = readfile(join_script_dir("txt/timebased_sql.txt"))


function do_scan(target_param, target_payload)
    local new_url = HttpMessage:param_set(target_param, string.format(" %s",target_payload))
    local before_scan = os.time()

    local resp_status,resp = pcall(function ()
        return http:send{
            url = new_url,
        }
    end)
    if resp_status == true then
        return nil
    end
    local after_scan = os.time() - before_scan
    if after_scan > 4 then
        local report = {
            url = new_url,
            delay = after_scan,
            param = target_param,
            payload = target_payload
        }
        return report
    end
end

function scan_callback(report_data)
    local url = report_data["url"]
    local delay = report_data["delay"]
    local param = report_data["param"]
    local payload = report_data["payload"]
    Reports:add {
        name = "TimeBased SQL Injection",
        url = url,
        parameter = param,
        payload = payload,
        delay = delay
    }

end

local function make_str_iter()
    local payloads = {}
    for payload in TIMEBASED_PAYLOADS:gmatch("[^\r\n]+") do
        table.insert(payloads,payload)
    end
    return payloads
end

function main()
    for _, param_name in ipairs(HttpMessage:param_list()) do
        ParamScan:add_scan(param_name, make_str_iter(), do_scan, scan_callback, FUZZ_WORKERS)
    end
end
