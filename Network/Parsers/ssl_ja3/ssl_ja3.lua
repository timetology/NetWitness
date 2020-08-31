--[[
Date:	14Jan2019
Author:	RSA - firstresponse@rsa.com

References:
JA3
https://github.com/salesforce/ja3
https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41
https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967

SSL Fingerprinting - https://github.com/LeeBrotherston/tls-fingerprinting

Initial fingerprint DB - https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json

GREASE - https://tools.ietf.org/html/draft-davidben-tls-grease-00

MD5 in Lua - https://github.com/kikito/md5.lua

Notes:

TODO: 


]]--

local parserName = "ssl_ja3"
local parserVersion = "2019.01.09.1-ep+multivalue+ja3_unknwon"
local ssl_ja3 = nw.createParser(parserName, "JA3 Hash SSL Fingerprinting" .. ": " .. parserVersion)

nw.logDebug(parserName .. " " .. parserVersion)

local debugParser = false

-- define options
    local options = ({
        ["ja3hashlist"] = ({
            ["name"] = "JA3 Hash to Client List",
            ["description"] = "JA3 Hash List for Client Identification",
            ["type"] = "table",
            ["default"] = nil
        }),
	})
-- set options DON'T MODIFY THIS SECTION
    pcall(function()
        local optionsModule = parserName .. "_options"
        optionsModule = require(optionsModule)
        for name,parameters in pairs(options) do
            if optionsModule[name] then
                parameters.value = optionsModule[name]()
            end
        end
    end)
    for name,parameters in pairs(options) do
        -- if the value was put in quotes, get the intended value not a string
        -- e.g., "100"  -> 100
        --       "true" -> true
        if parameters.type == "number" then
            parameters.value = tonumber(parameters.value)
        elseif parameters.type == "boolean" then
            if parameters.value == "false" then
                parameters.value = false
            elseif parameters.value == "true" then
                parameters.value = true
            end
        end
        -- make sure the type of value is correct, use default value if not
        -- e.g., expected a number but got "hello world" so use default instead
        if type(parameters.value) ~= parameters.type then
            parameters.value = parameters.default
        -- make sure number values fall within minimum and maximum
        elseif parameters.type == "number" then
            -- if the definition didn't provide a minimum, use 0
            parameters.minimum = (parameters.minimum and parameters.minimum > 0 and parameters.minimum) or 0
            -- if the definition didn't provide a maximum, use 4294967295
            parameters.maximum = (parameters.maximum and parameters.maximum < 4294967295 and parameters.maximum) or 4294967295
            parameters.value =
               (parameters.value < parameters.minimum and parameters.minimum) or
               (parameters.value > parameters.maximum and parameters.maximum) or
                parameters.value
        elseif parameters.type == "string" then
            -- make sure we don't use an empty string
            if string.len(parameters.value) == 0 then
                parameters.value = parameters.default
            end
        end
    end
-- end options
local ja3hashlist = {}

if options.ja3hashlist.value then
    for i,j in pairs(options.ja3hashlist.value) do
        ja3hashlist[i] = j
    end
else
	ja3hashlist = nil
end


ssl_ja3:setKeys({
	nwlanguagekey.create("ssl.ja3"),
    -- added for string output of raw ja3 hash for research
	-- nwlanguagekey.create("ssl.ja3.str"),                                                      
	nwlanguagekey.create("client"),
	nwlanguagekey.create("analysis.service"),
})

function toHexString(myPayload)
	local hexout = ''
	for i=1, myPayload:len() do
		hexout = hexout .. bit.tohex(myPayload:uint8(i),2) .. ' '
	end
	return hexout
end
local md5={ff=tonumber('ffffffff',16),consts={}}

string.gsub([[ d76aa478 e8c7b756 242070db c1bdceee
    f57c0faf 4787c62a a8304613 fd469501
    698098d8 8b44f7af ffff5bb1 895cd7be
    6b901122 fd987193 a679438e 49b40821
    f61e2562 c040b340 265e5a51 e9b6c7aa
    d62f105d 02441453 d8a1e681 e7d3fbc8
    21e1cde6 c33707d6 f4d50d87 455a14ed
    a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
    fffa3942 8771f681 6d9d6122 fde5380c
    a4beea44 4bdecfa9 f6bb4b60 bebfbc70
    289b7ec6 eaa127fa d4ef3085 04881d05
    d9d4d039 e6db99e5 1fa27cf8 c4ac5665
    f4292244 432aff97 ab9423a7 fc93a039
    655b59c3 8f0ccc92 ffeff47d 85845dd1
    6fa87e4f fe2ce6e0 a3014314 4e0811a1
    f7537e82 bd3af235 2ad7d2bb eb86d391
    67452301 efcdab89 98badcfe 10325476 ]],"(%w+)", function (s) table.insert(md5.consts, tonumber(s,16)) end)
    --67452301 efcdab89 98badcfe 10325476 ]],"(%w+)", function (s) tinsert(md5.consts,tonumber(s,16)) end)

function md5.transform(A,B,C,D,X)
  local f=function (x,y,z) return bit.bor(bit.band(x,y),bit.band(-x-1,z)) end
  local g=function (x,y,z) return bit.bor(bit.band(x,z),bit.band(y,-z-1)) end
  local h=function (x,y,z) return bit.bxor(x,bit.bxor(y,z)) end
  local i=function (x,y,z) return bit.bxor(y,bit.bor(x,-z-1)) end
  local z=function (f,a,b,c,d,x,s,ac)
        a=bit.band(a+f(b,c,d)+x+ac,md5.ff)
        -- be *very* careful that left shift does not cause rounding!
        return bit.bor(bit.lshift(bit.band(a,bit.rshift(md5.ff,s)),s),bit.rshift(a,32-s))+b
      end
  local a,b,c,d=A,B,C,D
  local t=md5.consts

  a=z(f,a,b,c,d,X[ 0], 7,t[ 1])
  d=z(f,d,a,b,c,X[ 1],12,t[ 2])
  c=z(f,c,d,a,b,X[ 2],17,t[ 3])
  b=z(f,b,c,d,a,X[ 3],22,t[ 4])
  a=z(f,a,b,c,d,X[ 4], 7,t[ 5])
  d=z(f,d,a,b,c,X[ 5],12,t[ 6])
  c=z(f,c,d,a,b,X[ 6],17,t[ 7])
  b=z(f,b,c,d,a,X[ 7],22,t[ 8])
  a=z(f,a,b,c,d,X[ 8], 7,t[ 9])
  d=z(f,d,a,b,c,X[ 9],12,t[10])
  c=z(f,c,d,a,b,X[10],17,t[11])
  b=z(f,b,c,d,a,X[11],22,t[12])
  a=z(f,a,b,c,d,X[12], 7,t[13])
  d=z(f,d,a,b,c,X[13],12,t[14])
  c=z(f,c,d,a,b,X[14],17,t[15])
  b=z(f,b,c,d,a,X[15],22,t[16])

  a=z(g,a,b,c,d,X[ 1], 5,t[17])
  d=z(g,d,a,b,c,X[ 6], 9,t[18])
  c=z(g,c,d,a,b,X[11],14,t[19])
  b=z(g,b,c,d,a,X[ 0],20,t[20])
  a=z(g,a,b,c,d,X[ 5], 5,t[21])
  d=z(g,d,a,b,c,X[10], 9,t[22])
  c=z(g,c,d,a,b,X[15],14,t[23])
  b=z(g,b,c,d,a,X[ 4],20,t[24])
  a=z(g,a,b,c,d,X[ 9], 5,t[25])
  d=z(g,d,a,b,c,X[14], 9,t[26])
  c=z(g,c,d,a,b,X[ 3],14,t[27])
  b=z(g,b,c,d,a,X[ 8],20,t[28])
  a=z(g,a,b,c,d,X[13], 5,t[29])
  d=z(g,d,a,b,c,X[ 2], 9,t[30])
  c=z(g,c,d,a,b,X[ 7],14,t[31])
  b=z(g,b,c,d,a,X[12],20,t[32])

  a=z(h,a,b,c,d,X[ 5], 4,t[33])
  d=z(h,d,a,b,c,X[ 8],11,t[34])
  c=z(h,c,d,a,b,X[11],16,t[35])
  b=z(h,b,c,d,a,X[14],23,t[36])
  a=z(h,a,b,c,d,X[ 1], 4,t[37])
  d=z(h,d,a,b,c,X[ 4],11,t[38])
  c=z(h,c,d,a,b,X[ 7],16,t[39])
  b=z(h,b,c,d,a,X[10],23,t[40])
  a=z(h,a,b,c,d,X[13], 4,t[41])
  d=z(h,d,a,b,c,X[ 0],11,t[42])
  c=z(h,c,d,a,b,X[ 3],16,t[43])
  b=z(h,b,c,d,a,X[ 6],23,t[44])
  a=z(h,a,b,c,d,X[ 9], 4,t[45])
  d=z(h,d,a,b,c,X[12],11,t[46])
  c=z(h,c,d,a,b,X[15],16,t[47])
  b=z(h,b,c,d,a,X[ 2],23,t[48])

  a=z(i,a,b,c,d,X[ 0], 6,t[49])
  d=z(i,d,a,b,c,X[ 7],10,t[50])
  c=z(i,c,d,a,b,X[14],15,t[51])
  b=z(i,b,c,d,a,X[ 5],21,t[52])
  a=z(i,a,b,c,d,X[12], 6,t[53])
  d=z(i,d,a,b,c,X[ 3],10,t[54])
  c=z(i,c,d,a,b,X[10],15,t[55])
  b=z(i,b,c,d,a,X[ 1],21,t[56])
  a=z(i,a,b,c,d,X[ 8], 6,t[57])
  d=z(i,d,a,b,c,X[15],10,t[58])
  c=z(i,c,d,a,b,X[ 6],15,t[59])
  b=z(i,b,c,d,a,X[13],21,t[60])
  a=z(i,a,b,c,d,X[ 4], 6,t[61])
  d=z(i,d,a,b,c,X[11],10,t[62])
  c=z(i,c,d,a,b,X[ 2],15,t[63])
  b=z(i,b,c,d,a,X[ 9],21,t[64])

  return A+a,B+b,C+c,D+d
end

-- convert little-endian 32-bit int to a 4-char string
local function leIstr(i)
  local f=function (s) return string.char(bit.band(bit.rshift(i,s),255)) end
  return f(0)..f(8)..f(16)..f(24)
end

  -- convert raw string to big-endian int
  local function beInt(s)
    local v=0
    for i=1,string.len(s) do v=v*256+string.byte(s,i) end
    return v
  end
  -- convert raw string to little-endian int
  local function leInt(s)
    local v=0
    for i=string.len(s),1,-1 do v=v*256+string.byte(s,i) end
    return v
  end
  -- cut up a string in little-endian ints of given size
  local function leStrCuts(s,...)
    local o,r=1,{}
    for i=1,#arg do
      table.insert(r,leInt(string.sub(s,o,o+arg[i]-1)))
      o=o+arg[i]
    end
    return r
  end

function md5.Calc(s)
  local msgLen=string.len(s)
  local padLen=56- msgLen % 64
  if msgLen % 64 > 56 then padLen=padLen+64 end
  if padLen==0 then padLen=64 end
  s=s..string.char(128)..string.rep(string.char(0),padLen-1)
  s=s..leIstr(8*msgLen)..leIstr(0)
  assert(string.len(s) % 64 ==0)
  local t=md5.consts
  local a,b,c,d=t[65],t[66],t[67],t[68]
  for i=1,string.len(s),64 do
    local X=leStrCuts(string.sub(s,i,i+63),4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4)
    assert(#X==16)
    X[0]=table.remove(X,1) -- zero based!
    a,b,c,d=md5.transform(a,b,c,d,X)
  end
  local swap=function (w) return beInt(leIstr(w)) end
  return string.format("%08x%08x%08x%08x",swap(a),swap(b),swap(c),swap(d))
end


function ssl_ja3:init()
-- GREASE   https://tools.ietf.org/html/draft-davidben-tls-grease-00
self.GREASE =
{
      [2570] = true,
      [6682] = true,
      [10794] = true,
      [14906] = true,
      [19018] = true,
      [23130] = true,
      [27242] = true,
      [31354] = true,
      [35466] = true,
      [39578] = true,
      [43690] = true,
      [47802] = true,
      [51914] = true,
      [56026] = true,
      [60138] = true,
      [64250] = true
};
end

function ssl_ja3:tlsHandshake(token, first, last)
	--Check if Client Hello
	local helloPayload = nw.getPayload(last + 3, last + 4)
	if helloPayload then
		local helloPayloadInt = helloPayload:uint8()
		--nw.logInfo("***helloPayloadInt:" .. tonumber(helloPayloadInt))
		if helloPayloadInt == 1 then
			if nw.isRequestStream() then
				--We are in the Handshake and Client Hello
				--nw.logInfo("Client Hello!")
				nw.createMeta(self.keys["analysis.service"], "ssl client hello")
				
				--Get small payload to get length of TLS Section
				local payload = nw.getPayload(last + 1, last + 2)
				if payload then
					--Length of the TLS section
					local payloadShort = nwpayload.uint16
					local tlsLength = payloadShort(payload, 1)
					if tlsLength then
						--nw.logInfo("tlsLength: " .. tonumber(tlsLength))
						-- get a payload object of just the TLS section (in its entirety)
						payload = nw.getPayload(last + 3, last + 3 + tlsLength - 1)
						if payload then
							local position = 1
							local handshake = payload:uint8(position)
							position = position + 1
							-- length = 3 bytes 
							position = position + 3 
							local version = payload:uint16(position)
							position  = position + 2
							
							--Verify SSL/TLS Versions are good.
							if (tonumber(version) == 768 or tonumber(version) == 769 or tonumber(version) == 770 or tonumber(version) == 771) then
								-- random = 32 bytes
								position = position + 32
								-- session id length
								local sessionIdLength = payload:uint8(position)
								position = position + 1 + sessionIdLength
								
								-- cipher suites
								local cipherSuitesLength = payload:uint16(position)
								position = position + 2
								--local cipherSuitesTable = {}
								local cipherSuites = ''
								if cipherSuitesLength and cipherSuitesLength > 0 and position < payload:len() then
									for i=1,cipherSuitesLength/2 do
										cipherSuite = payload:uint16(position)
										--nw.logInfo("cipherSuite: " .. cipherSuite)
										if not self.GREASE[cipherSuite] then
											cipherSuites = cipherSuites .. cipherSuite .. '-'
										end
										position = position + 2
									end

									--nw.logInfo("handshake: " .. tonumber(handshake))
									--nw.logInfo("version: " .. tonumber(version))
									--nw.logInfo("version: " .. tostring(bit.tohex(version,4)))
									--nw.logInfo("cipherSuitesLength: " .. tonumber(cipherSuitesLength))
									--nw.logInfo("cipherSuitesLength: " .. tostring(bit.tohex(cipherSuitesLength,4)))

									cipherSuites = cipherSuites:sub(1,-2) --Trim trailing -
									--nw.logInfo("cipherSuites: ".. cipherSuites)
								end
								
								--CompressionMethods  (Not used in JA3 Hash)
								local CompressionMethodsLength = payload:uint8(position)
								position = position + 1
								if CompressionMethodsLength and CompressionMethodsLength > 0 and position < payload:len() then
									--nw.logInfo("CompressionMethodsLength: " .. tonumber(CompressionMethodsLength))
									--local CompressionMethodsTable = {}
									for i=1,CompressionMethodsLength do
										--CompressionMethodsTable[i] = payload:uint8(position)
										position = position + 1
									end
								end
								
								--SSLExtensions
								local SSLExtensionTableLength = payload:uint16(position)
								position = position + 2
								--nw.logInfo("SSLExtensionTableLength: " .. tonumber(SSLExtensionTableLength))
								local SSLExtensionTypes = ''
								local ECC = ''
								local EllipticCurvePointFormat = ''
								if SSLExtensionTableLength and SSLExtensionTableLength > 0 then

									local ExtensionPosition = 1
									local ExtensionCount = 1
									local ExtType = nil
									while ExtensionPosition < SSLExtensionTableLength do
										--Read in ExtensionType
										ExtType = payload:uint16(position)
										position = position + 2
										ExtensionPosition = ExtensionPosition + 2
										--nw.logInfo("ExtType: " .. ExtType)
										--Read in SSLExtensionLength
										local SSLExtensionLength = payload:uint16(position)
										position = position + 2
										ExtensionPosition = ExtensionPosition + 2
										--Check for GREASE Extensions
										if not self.GREASE[ExtType] then
											--nw.logInfo("GREASE PASSED " .. ExtType)
											SSLExtensionTypes = SSLExtensionTypes .. ExtType .. '-'

											--nw.logInfo("ExtensionCount: " .. tonumber(ExtensionCount))
											--nw.logInfo("ExtensionType: " .. tonumber(SSLExtensionTypeTable[ExtensionCount]))
											--nw.logInfo("SSLExtensionLength: " .. tonumber(SSLExtensionLength))
											--nw.logInfo("ExtensionPosition: " .. tonumber(ExtensionPosition))
											
											--Handle EllipticCurve
											--if SSLExtensionTypeTable[ExtensionCount] == 10 then
											if ExtType == 10 then
												local EllipticCurveLength = payload:uint16(position)
												position = position + 2
												ExtensionPosition = ExtensionPosition + 2
												--nw.logInfo("EllipticCurveLength: " .. tonumber(EllipticCurveLength))
												
												for i=1, EllipticCurveLength/2 do
													if not self.GREASE[payload:uint16(position)] then
														ECC = ECC .. payload:uint16(position) .. '-'
													end
													position = position + 2
													ExtensionPosition = ExtensionPosition + 2
												end
												ECC = ECC:sub(1,-2) --Trim trailing -

												--nw.logInfo("NextWord: " .. bit.tohex(payload:uint16(position),4))
												--nw.logInfo("hexoutfunction: " .. toHexString(ECCPayload))
												
											--Handle EllipticCurvePointFormat	
											--elseif SSLExtensionTypeTable[ExtensionCount] == 11 then
											elseif ExtType == 11 then
											
												local EllipticCurvePointFormatLength = payload:uint8(position)
												--nw.logInfo("EllipticCurvePointFormatLength: " .. tonumber(EllipticCurvePointFormatLength))
												
												position = position + 1
												ExtensionPosition = ExtensionPosition + 1
												
												for i=1, EllipticCurvePointFormatLength do
													EllipticCurvePointFormat = EllipticCurvePointFormat .. payload:uint8(position) .. '-'
													position = position + 1
													ExtensionPosition = ExtensionPosition + 1
												end
												EllipticCurvePointFormat = EllipticCurvePointFormat:sub(1,-2)

											else
												--Skip over it
												position = position + SSLExtensionLength
												ExtensionPosition = ExtensionPosition + SSLExtensionLength
											end
										end
										ExtensionCount = ExtensionCount + 1
									end
									
								
									--nw.logInfo("SSLExtensionTypes: ".. SSLExtensionTypes)
									SSLExtensionTypes = SSLExtensionTypes:sub(1,-2) --Trim trailing -
									--nw.logInfo("SSLExtensionTypes: ".. SSLExtensionTypes)
								end
								
								
								--Create FingerPrint
								local sslFingerprint = tostring(tonumber(version)) .. ',' .. cipherSuites .. ',' .. SSLExtensionTypes .. ',' .. ECC .. ',' .. EllipticCurvePointFormat
								--nw.logInfo("LOG: " .. nwsession.getSource() .. " -> " .. nwsession.getDestination()) 
								--nw.logInfo("sslFingerprint: " .. sslFingerprint)
                                -- write the ja3 hash raw to ssl.ja3.str
                                -- nw.createMeta(self.keys["ssl.ja3.str"], sslFingerprint)                                        
								
								--Calc ja3 hash and create meta
								local ja3md5 = md5.Calc(sslFingerprint)
								--nw.logInfo("md5: " .. ja3md5)
								nw.createMeta(self.keys["ssl.ja3"], ja3md5)
								
								if ja3hashlist then
									if ja3hashlist[ja3md5] then
										--nw.logInfo("client: " .. ja3hashlist[ja3md5])
                                        
                                        -- disable this strict writing in favour of the fancier method below
										--nw.createMeta(self.keys["client"], ja3hashlist[ja3md5])
                                        
                                        for list_value_split in string.gmatch(ja3hashlist[ja3md5], "[^,]+") do
                                            -- iterate over the potential list of match and split on comma to get individual options where collisions might happen
                                            -- ["20dd18bdd3209ea718989030a6f93364"] = "used by many programs,slack,postman,spotify,browser: chrome",
                                            -- ["1a6ef47ab8325fbb42c447048cea9167"] = "applewebkit/533.1 (khtml like gecko) version/4.0,browser: mobile safari/533.1",

                                            nw.createMeta(self.keys["client"], list_value_split)
                                        end
									else 
										--nw.logInfo("client: " .. "unknown")
										nw.createMeta(self.keys["client"], "ja3_unknown")
                                    
									end
								end
							end
						end
					end
				end
			end
		end
	end
end

ssl_ja3:setCallbacks({
	--[nwevents.OnSessionBegin] = ssl_ja3.SessionBegin,
	[nwevents.OnInit] = ssl_ja3.init,
	["\022\003\000"] = ssl_ja3.tlsHandshake,   -- SSL 3.0 0x160300
    ["\022\003\001"] = ssl_ja3.tlsHandshake,   -- TLS 1.0 0x160301
    ["\022\003\002"] = ssl_ja3.tlsHandshake,   -- TLS 1.1 0x160302
    ["\022\003\003"] = ssl_ja3.tlsHandshake,   -- TLS 1.2 0x160303
})
