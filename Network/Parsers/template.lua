-- Step 1 - Create parser
local template = nw.createParser("template-parser", "Template Parser")

--[[
This is a template parser.  It is intended to server as a template for simple ioc idenftification and as a learning tool.

This parser uses the hunting guide meta keys Indicators of Compromise, Behaviors of Compromise, & Enablers of Compromise. 

Extracting the host header is also used as an example, but should not be implemented.

Concentrator: index-concentrator-custom.xml
	<key description="ioc" level="IndexValues" name="eoc" valueMax="1000" format="Text"/>
 	<key description="boc" level="IndexValues" name="eoc" valueMax="1000" format="Text"/>
 	<key description="eoc" level="IndexValues" name="eoc" valueMax="1000" format="Text"/>
--]]

-- Step 2 - Define meta keys to write meta into
-- declare the meta keys we'll be registering meta with
template:setKeys({
	nwlanguagekey.create("ioc", nwtypes.Text),
	nwlanguagekey.create("boc", nwtypes.Text),
	nwlanguagekey.create("eoc", nwtypes.Text),
	nwlanguagekey.create("hostheader", nwtypes.Text),
	nwlanguagekey.create("alias.host.len",nwtypes.UInt16)
})

-- Optional Step - Initialize State Tracking Variables on session begin
function template:sessionBegin()
	self.state = nil
end

-- Step 4 - Do SOMETHING once your token matched

function template:IOC(token, first, last)
	nw.createMeta(self.keys["ioc"], token .. " rat") -- If we have a match (because this function was called) create a meta in ioc with the value of the matched token concatenated with " rat"
end

function template:BOC(token, first, last)
	nw.createMeta(self.keys["boc"], "Proxy Block Virus/Spyware") -- If we have a match create meta in boc meta key.
end

function template:EOC(token, first, last)
	--Use state to track that meta token is only matched and written once
	if self.state = nil
		nw.createMeta(self.keys["boc"], "Teamviewer") -- If we have a match create meta in boc meta key.
		self.state = 1
	end
end

function template:tokenReadDataExample(token, first, last)
	local payload = nw.getPayload(last+1, last+1+4096) -- Get 4096 bytes after the last character of match
	if payload then -- if that succeeded and we got a valid payload
		local endmatch = payload:find('\13\10') -- Find End of Line marker CR NL,0x0D 0x0A, \13\10 in Decimal
		if endmatch then  -- If we found the end
			local hostheader = payload:tostring(1, endmatch-1)  -- Convert the payload between those two markers to a string
			if hostheader then  -- If we got that string
				nw.createMeta(self.keys["hostheader"], hostheader) -- Write that as meta in the hostheader metakey
			end
		end
	end
end

function template:MetaCallback(index, host)
	local hostLength = string.len(host)
	if hostLength then
		nw.createMeta(self.keys["alias.host.len"], hostLength)
	end
end

-- Step 3 - Define tokens that get you close to what you want
-- Declare what tokens and events we want to match.  
-- These do not have to be exact matches but just get you close to the data you want.
template:setCallbacks({
	[nwevents.OnSessionBegin] = template.sessionBegin,
	["^gh0st"] = template.IOC,
	["<title>Virus/Spyware Download Blocked</title>"] = template.BOC,
	["Dyngate"] = template.EOC,
--	["^Host: "] = template.tokenReadDataExample,
--	["^host: "] = template.tokenReadDataExample,
	[nwlanguagekey.create("alias.host")] = template.MetaCallback,
})




















