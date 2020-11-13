--Identified the Magic Packet for Wake on Lan
--https://en.wikipedia.org/wiki/Wake-on-LAN#Magic_packet

-- Step 1 - Create parser
local wakeonlan = nw.createParser("WakeOnLan-parser", "Wake On Lan Parser")

-- Step 2 - Define meta keys to write meta into
wakeonlan:setKeys({
	nwlanguagekey.create("analysis.service", nwtypes.Text),
})

-- Step 4 - Do SOMETHING once your token matched
function wakeonlan:IOC(token, first, last)
	local service = nw.getAppType()
	if not service or service == 0 then
		nw.createMeta(self.keys["analysis.service"], "wake on lan")
	end
end

-- Step 3 - Define tokens that get you close to what you want
wakeonlan:setCallbacks({
	["^\255\255\255\255\255\255"] = wakeonlan.IOC,

})
