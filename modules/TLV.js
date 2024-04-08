// handles TLV data
const { Buffer } = require('node:buffer');

function decodeTLV(packet) {
    // this decodes TLV data
    return new Promise((resolve, reject) => {
        var tlvData = new Buffer.from(packet, 'hex')
        var tlv = []

        let offset = 0;
        while (offset < tlvData.length) {
            const type = tlvData.readUInt16BE(offset);
            offset += 2;
    
            const length = tlvData.readUInt16BE(offset);
            offset += 2;
    
            const value = tlvData.slice(offset, offset + length);
            offset += length;
    
            tlv.push({ type, length, value });
        }
        
        resolve(tlv)
    })
};

function constructTLV(type, value, length) {
    // this constructs TLVS
};

module.exports = {
    decodeTLV,
    constructTLV,
};