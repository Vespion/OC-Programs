net = require("minitel")
serialization = require("serialization")
component = require("component")
data = component.data

class DataPacket
  new: (type, data) =>
    @packetType = type
    @data = data

export class EncryptedStream
  new: (target, port) =>
    @target = target
    @targetPort = port
    @publicKey, @privateKey = data.generateKeyPair()
    @IV = data.random(16)

  connect: =>
    setupStream = net.open(@target, 443)
    setupStream:send(serialization.serialize(new DataPacket("setup_encryption", {publicKey: @publicKey, IV: @IV})))
    responsePacket = setupStream:read("<end>")
    @sharedKey = data.ecdh(@privateKey, responsePacket.data)
    @netStream = net.open(@target, @targetPort)
    

  send: (data) =>
    packet = new DataPacket("data", data)
    encryptedStr = data.encryt(serialization.serialize(data), @sharedKey, @IV)
    @netStream:send(encryptedStr .. "<end>")

  reiceve: =>
    encryptedStr = @netStream:read("<end>")
    packet = data.decryt(encryptedStr, @sharedKey, @IV)
    return serialization.deserialize(packet).data
    
