// handles SNAC packets
const { Buffer } = require('node:buffer');

function decodeSNAC(packet) {
    // this decodes SNAC data
    return new Promise((resolve, reject) => {
        var snacData = new Buffer.from(packet, 'hex')
        resolve({
            foodgroup: snacData.readUint16BE(0),
            subgroup: snacData.readUint16BE(2),
            flags: snacData.readUint16BE(4),
            requestid: snacData.readUint32BE(6),
            data: snacData.slice(10, snacData.length)
        })
    })
};

function constructSNAC(foodgroup, subgroup, flags, requestid, data) {
    // this constructs SNAC data
    var snacHeader = new Buffer.alloc(10, 1);
    var snacData = new Buffer.from(data, 'hex');

    snacHeader.writeUint16BE(foodgroup); // foodgroup
    snacHeader.writeUint16BE(subgroup, 2); // subgroup
    snacHeader.writeUInt16BE(flags, 4); // flags
    snacHeader.writeUint32BE(requestid, 6); // requestid


    var snacResult = Buffer.concat([snacHeader, snacData]);
    return snacResult;
};

module.exports = {
    decodeSNAC,
    constructSNAC,
};