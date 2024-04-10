// BOS server lol

const logger = require("./modules/logger");
const mysql = require("./modules/mysql");
const FLAP = require("./modules/FLAP")
const SNAC = require("./modules/SNAC")
const TLV = require("./modules/TLV")
const net = require("net");

const users = []
const authlist = []

function sendUser(json) {
    // this allows the auth and bos server to communicate
    authlist.push(json)
}

function checkList(key) {
    var find = authlist.find((element) => element.authorization == key)
    if (find) {
        return find
    } else {
        // i didn't find the specified authkey....
        return false
    }
}

logger.info(`BOS server launched on port ${5191}`)

net.createServer(function (socket) { // start listening
    var flapSequence = 0x0000
    var localUser = {}
    var lastSnacSent = Math.floor(Date.now() / 1000)
    var currentAvg = 2

    socket.write(FLAP.constructFLAP(0x01, flapSequence += 1, "00000001"))

    socket.on('data', function (data) {
        function syncRateLimit() {
            var windowSize = 5
            var newSnacTime = Math.floor(Date.now() / 1000)
            var differenceInSeconds = (newSnacTime * 1000 - lastSnacSent * 1000) / 1000
            lastSnacSent = newSnacTime
            if (currentAvg > 5) {
                currentAvg = 5
            } else {
                currentAvg = Math.round(((currentAvg * (windowSize - 1)) + differenceInSeconds) / windowSize)
            }
        }

        async function handleData() {
            try {
                // BOS MOMENT
                var flapData = await FLAP.decodeFLAP(data)
                switch (flapData.type) {
                    case 1:
                        var loginflapData = await FLAP.decodeFLAP(data)
                        var tlvData = await TLV.decodeTLV(loginflapData.data.slice(8, loginflapData.data.length)) // dirty hack, assumes the flap packet begins with 00000001
                        var authKeyCheck = await checkList(tlvData.authorizationkey)
                        if (authKeyCheck) {
                            localUser.username = authKeyCheck.username
                            localUser.socket = socket
                            socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0001, 0x0003, 0x0000, 0x00000000, "00010002000300040017")))
                            authlist.splice(authlist.indexOf(authKeyCheck), 1)
                            logger.info(`'${authKeyCheck.username}' was successfully authenticated.`)
                        } else {
                            // our auth key didn't match
                            console.log(`woops`)
                        }
                        break;
                    case 2:
                        // FLAP__FRAME_DATA
                        var snacData = await SNAC.decodeSNAC(flapData.data)
                        //var tlvData = await TLV.decodeTLV(snacData.data)
                        syncRateLimit()

                        async function subgroup(subgroup) {
                            switch (subgroup) {
                                case 0x0017:
                                    // OSERVICE CLIENT VERSIONS
                                    localUser.capabilities = snacData.data
                                    socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0001, 0x0018, 0x0000, 0x00000000, localUser.capabilities)))
                                    break;
                                case 0x0006:
                                    // OSERVICE RATE PARAMS QUERY
                                    var rateLimitArray = [{
                                        classID: 1,
                                        windowSize: 2,
                                        clearLvl: 4,
                                        alertLvl: 2,
                                        limitLvl: 1,
                                        dscLevel: 0,
                                        curLevel: 4,
                                        maxLvl: 5,
                                        lstTime: 5,
                                        currentState: 1,
                                    }]
                                    
                                    rateLimitArray.forEach((element) => {
                                        var rateHeader = new Buffer.alloc(40);
                                        var rateID = new Buffer.alloc(2);
                                        rateID.writeUint16BE(element.classID)

                                        rateHeader.writeUint32BE(element.windowSize)
                                        rateHeader.writeUint32BE(element.clearLvl, 4)
                                        rateHeader.writeUint32BE(element.alertLvl, 8)
                                        rateHeader.writeUint32BE(element.alertLvl, 12)
                                        rateHeader.writeUint32BE(element.limitLvl, 16)
                                        rateHeader.writeUint32BE(element.dscLevel, 20)
                                        rateHeader.writeUint32BE(element.curLevel, 24)
                                        rateHeader.writeUint32BE(element.maxLvl, 28)
                                        rateHeader.writeUint32BE(element.lstTime, 32)
                                        rateHeader.writeUint32BE(element.currentState, 36)
                                        
                                        // ;_; maybe i'll do this later
                                    });

                                    socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0001, 0x0007, 0x0000, 0x00000000, "0005000100000050000009C4000007D0000005DC0000032000000D6900001770000000000000020000005000000BB8000007D0000005DC000003E800001770000017700000F90B00000300000014000013EC0000138800000FA000000BB8000011470000177000005CD8000004000000140000157C000014B40000106800000BB80000177000001F400000F90B0000050000000A0000157C000014B40000106800000BB80000177000001F400000F90B00000100910001000100010002000100030001000400010005000100060001000700010008000100090001000A0001000B0001000C0001000D0001000E0001000F000100100001001100010012000100130001001400010015000100160001001700010018000100190001001A0001001B0001001C0001001D0001001E0001001F0001002000010021000200010002000200020003000200040002000600020007000200080002000A0002000C0002000D0002000E0002000F000200100002001100020012000200130002001400020015000300010003000200030003000300060003000700030008000300090003000A0003000B0003000C00040001000400020004000300040004000400050004000700040008000400090004000A0004000B0004000C0004000D0004000E0004000F0004001000040011000400120004001300040014000600010006000200060003000800010008000200090001000900020009000300090004000900090009000A0009000B000A0001000A0002000A0003000B0001000B0002000B0003000B0004000C0001000C0002000C00030013000100130002001300030013000400130005001300060013000700130008001300090013000A0013000B0013000C0013000D0013000E0013000F001300100013001100130012001300130013001400130015001300160013001700130018001300190013001A0013001B0013001C0013001D0013001E0013001F0013002000130021001300220013002300130024001300250013002600130027001300280015000100150002001500030002000600030004000300050009000500090006000900070009000800030002000200050004000600040002000200090002000B00050000                                    ")))
                                    break;
                                case 0x000e:
                                    var username = Buffer.from(localUser.username)
                                    var dataTLVs = TLV.constructTLV([
                                        { type: 0x0001, value: 0x00000000 }, { type: 0x0006, value: 0x00000000 }, { type: 0x000A, value: "192.168.0.94" },
                                        { type: 0x000F, value: 0x00000000 }, { type: 0x000F, value: 0x00000000 }, { type: 0x0005, value: 0x00000000 }, { type: 0x001E, value: 0x00000000 }
                                    ])

                                    socket.write(FLAP.constructFLAP(0x02, flapSequence += 1, SNAC.constructSNAC(0x0001, 0x000F, 0x0000, 0x00000000, dataTLVs)))
                                    break;
                                default:
                                    logger.error(`unknown subgroup :P | ${subgroup.toString(16).padStart(4, 0)}`)
                                    break;
                            }
                        }

                        switch (snacData.foodgroup) {
                            case 0x0001:
                                // BUCP
                                subgroup(snacData.subgroup)
                                break;
                            default:
                                logger.error(`unknown foodgroup :P | ${snacData.foodgroup.toString(16).padStart(4, 0)}`)
                                break;
                        }
                        break;
                    case 0x0003:
                        // FLAP__FRAME_ERROR 
                        // todo
                        break;
                    case 0x0004:
                        // FLAP__FRAME_SIGNOFF
                        // todo
                        break;
                    case 0x0003:
                        // FLAP__FRAME_KEEP_ALIVE 
                        // todo (although there shouldn't be really much to handle here because the server shouldn't respond)
                        break;
                    default:
                        logger.error(`unknown flap type :P | ${flapData.type.toString(16).padStart(4, 0)}`)
                        break;
                }
            } catch (err) {
                logger.error(err)
            }
        }

        handleData()
    });
}).listen(5191, `192.168.0.94`);


process.on('uncaughtException', function (err) {
    logger.error(err.stack);
});

module.exports = {
    sendUser,
};