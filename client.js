const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const keyosCpixSdk = require('./sdk/keyos-cpix-sdk');
const fs = require('fs');
require('dotenv').config()
 
const USER_PVK_KEY_PATH = './keys/test-keyos-user-private-key.pem';
const USER_PUB_CERT_PATH = './keys/test-keyos-user-public-cert.pem';
const KEYOS_CPIX_PUB_CERT_PATH = './keys/pub-cert-keyos-cpix-api.pem';
 
// List of Key IDs you wish to get Content Keys for (usually it is only one Key ID) and intended track type.
// By default, if the track type is not provided, the service assumes it is SD.
let keyIds = [];
keyIds.push({ 'kid': uuidv4(), 'trackType': 'SD' });
 
// The name of the asset you are packaging
let mediaId = 'my first stream';
 
// Set to 'cbcs' for HLS + FairPlay or CMAF and to 'cenc' for Dash + Widevine/Playready
let commonEncryptionScheme = 'cenc';
 
// Set desired DRM systems to true; note that FP will not work with cenc
let drmSystemList = {
    "PR" : true,
    "WV" : true,
    "FP" : false
};
 
try {
    // Create a CPIX request XML
    let requestXml = keyosCpixSdk.createCpixRequest(keyIds, mediaId, commonEncryptionScheme, drmSystemList, USER_PVK_KEY_PATH, USER_PUB_CERT_PATH);
 
    // Send the request to the API
    axios.post('https://cpix-dev.licensekeyserver.com/cpix/v3.0/', requestXml)
        .then((res) => {
            // Verify the response by checking its format and the signature
            let cpixResponse = keyosCpixSdk.verifyResponse(res.data, KEYOS_CPIX_PUB_CERT_PATH);
 
            // Verify MAC values for every content key
            keyosCpixSdk.verifyMacValues(cpixResponse, USER_PVK_KEY_PATH);
 
            // Get list of content keys:key id objects. The content key is a hex and the key id is in GUID / UUID
            let contentKeys = keyosCpixSdk.decryptContentKeys(cpixResponse, USER_PVK_KEY_PATH);
 
            // Get corresponding PSSH boxes for decrypted content keys
            let psshBoxes = keyosCpixSdk.getPsshBoxes(contentKeys, cpixResponse);
 
            console.log(psshBoxes);
        }).catch((err) => {
            console.error(err);
            fs.writeFileSync("res.json", JSON.stringify(err));
        });
 
} catch (error) {
    console.error(error)
}