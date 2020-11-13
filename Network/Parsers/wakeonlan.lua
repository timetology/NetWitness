--Identifies the Magic Packet for Wake on Lan
--https://en.wikipedia.org/wiki/Wake-on-LAN#Magic_packet

local wakeonlan = nw.createParser("WakeOnLan-parser", "Wake On Lan Parser")

wakeonlan:setKeys({
	nwlanguagekey.create("analysis.service", nwtypes.Text),
})

function wakeonlan:IOC(token, first, last)
	local service = nw.getAppType()
	if not service or service == 0 then
		nw.createMeta(self.keys["analysis.service"], "wake on lan") --If we haven't identified a service, we can log this as wake on lan.
	end
end

wakeonlan:setCallbacks({
	["^\255\255\255\255\255\255"] = wakeonlan.IOC, --FF FF FF FF FF FF Magic Packet indicator

})
