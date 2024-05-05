m = Map("ku-ua", translate("KU-UA"), translate("这是一个用于统一用户代理“UA”的内核模块，请求改之前确定你知道自己在做什么（如果宕机了作者不背锅）"))
s = m:section(TypedSection, "ku-ua",translate(""))
s.anonymous = true

g = s:option(Value, "predefined_ua", translate("自定义ua"))
g.description = translate([[
当前浏览器ua为：<pre id="ua-string"></pre><script>document.getElementById('ua-string').innerText = navigator.userAgent;</script>
]])

local apply=luci.http.formvalue("cbi.apply")
if apply then
    luci.util.exec("/etc/init.d/ku-ua start &")
end

return m