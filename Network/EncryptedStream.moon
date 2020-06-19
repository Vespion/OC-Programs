net = require("minitel")
serialization = require("serialization")
component = require("component")
data = component.data

export class DataPacket
  new: (type, data, status, insecure) =>
    @packetType = type
    @data = data
    @status = status
    @insecure = insecure

export class EncryptedStream
  new: (port) =>
    @targetPort = port
    @publicKey, @privateKey = data.generateKeyPair()
    @IV = data.random(16)

  Listen: (listener) =>
    @netStream = net.listen(@targetPort)
    while true do
      packet = @Receive()
      if packet.packetType == "upgrade_insecure" then
        @sharedKey = data.ecdh(@privateKey, packet.data.publicKey)
        @IV = packet.data.IV
        @Send({publicKey: @publicKey}, "upgrading_insecure", 200, true)
      elseif packet.packetType == "upgrading_insecure" then
        --NO OP
        continue
      else
        listener(packet)
      end
    end
    

  Connect: (target) =>
    @target = target
    @netStream = net.open(@target, @targetPort)
    @Send({publicKey: @publicKey, IV: @IV}, "upgrade_insecure", nil, true)
    responsePacket = @Receive()
    while responsePacket.packetType ~= "upgrading_insecure" do
      responsePacket = @Receive()
    end
    @sharedKey = data.ecdh(@privateKey, responsePacket.publicKey.data)

  Send: (data, datatype, statusCode, insecure) =>
    dataType = dataType or "data"
    local encryptedStr
    if insecure ~= true then
      encryptedStr = data.encrypt(serialization.serialize(data), @sharedKey, @IV)
    else
      encryptedStr = serialization.serialize(data)
    end
    packet = DataPacket(dataType, encryptedStr .. "<end>", statusCode, insecure)
    @netStream:send(packet .. "<end>")

  Receive: =>
    while line == nil        
      line = sock:read("<end>")
    end
    packet = serialization.deserialize(line)
    if packet.insecure ~= true then
      packet.data = data.decrypt(packet.data, @sharedKey, @IV)
    end
    return DataPacket(packet.packetType, packet.data, packet.status, packet.insecure)
