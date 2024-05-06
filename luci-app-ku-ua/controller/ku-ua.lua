module("luci.controller.ku-ua", package.seeall)

function index()
	entry({"admin", "services", "ku-ua"},alias("admin", "services", "ku-ua","config"), _("KU-UA配置"))
	entry({"admin", "services", "ku-ua", "config"},cbi("ku-ua"), _("基本功能"), 10).leaf = true
	entry({"admin", "services", "ku-ua", "log"}, call("kn_log"), _("日志"), 20).leaf = true
end

function kn_log()
    local logread_cmd = io.popen('logread')
    local syslog = logread_cmd:read('*a')
    logread_cmd:close()

    local ku_ua_lines = {}
    for line in syslog:gmatch("[^\n]+") do
        if line:find("ku") then
            table.insert(ku_ua_lines, line)
        end
    end

    local all_ku_ua_logs = table.concat(ku_ua_lines, '\n')

    luci.template.render("admin_status/syslog", {syslog=all_ku_ua_logs})
end
