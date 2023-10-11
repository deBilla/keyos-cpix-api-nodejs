const xml2js = require('xml2js');
const SignedXml = require('xml-crypto').SignedXml;
const FileKeyInfo = require('xml-crypto').FileKeyInfo;
const crypto = require('crypto');
const fs = require('fs');
 
/**
 * Creates CPIX request XML
 *
 * @param {Array} keyIds array of objects. Each object contains the 'kid' and the 'trackType'
 * @param {string} mediaId the name of the content
 * @param {string} privateKeyPath Path to the KeyOS customer's/ESP Partner's private key
 * @param {string} publicCertPath Path to the KeyOS customer's/ESP Partner's public certificate
 * @param {string} secondaryPrivateKeyPath Path to the ESP Partner's End-user private key
 * @param {string} secondaryPublicCertPath Path to the ESP Partner's End-user public certificate
 * @returns string
 */
exports.createCpixRequest = function(keyIds, mediaId, commonEncryptionScheme, drmSystemList, privateKeyPath, publicCertPath, secondaryPrivateKeyPath, secondaryPublicCertPath) {
    let privateKey = fs.readFileSync(privateKeyPath);
    let publicCert = fs.readFileSync(publicCertPath);
    publicCert = publicCert.toString().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/[\r\n]+/gm, '');
 
    let secondaryPrivateKey = '';
    let secondaryPublicCert = '';
    if (secondaryPrivateKeyPath && secondaryPublicCertPath) {
        secondaryPrivateKey = fs.readFileSync(secondaryPrivateKeyPath);
        secondaryPublicCert = fs.readFileSync(secondaryPublicCertPath);
        secondaryPublicCert = secondaryPublicCert.toString().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/[\r\n]+/gm, '');
    }
 
    let root = {
        'cpix:CPIX': {
            $: {
                'name': mediaId,
                'xsi:schemaLocation': 'urn:dashif:org:cpix cpix.xsd',
                'xmlns:xenc': 'http://www.w3.org/2001/04/xmlenc#',
                'xmlns:pskc': 'urn:ietf:params:xml:ns:keyprov:pskc',
                'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                'xmlns:cpix': 'urn:dashif:org:cpix',
                'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#'
            }
        }
    };
 
    // Delivery data list
    let deliveryDataList = {
        'cpix:DeliveryData': {
            'cpix:DeliveryKey': {
                'ds:X509Data': {
                    'ds:X509Certificate': publicCert
                }
            }
        }
    };
 
    root['cpix:CPIX']['cpix:DeliveryDataList'] = deliveryDataList;
 
    // Content key list
    let contentKeyList = { 'cpix:ContentKey': [] };
 
    // Content key usage rules
    let contentKeyUsageList = { 'cpix:ContentKeyUsageRule': [] };
 
    // DRM systems list
    let drmSystemListElement = { 'cpix:DRMSystem': [] };
 
    keyIds.forEach(data => {
        contentKeyList['cpix:ContentKey'].push({
            $: {
                'kid': data['kid'],
                'commonEncryptionScheme' : commonEncryptionScheme // Other possible values are: cbcs, cens, cbc1
            }
        });
 
        contentKeyUsageList['cpix:ContentKeyUsageRule'].push({
            $: {
                'kid': data['kid'],
                'intendedTrackType': data['trackType']
            }
        });
 
        if (drmSystemList['PR']){
            drmSystemListElement['cpix:DRMSystem'].push({
                $: {
                    'kid': data['kid'],
                    'systemId': '9a04f079-9840-4286-ab92-e65be0885f95'
                }
            });
        }
        if (drmSystemList['WV']){
            drmSystemListElement['cpix:DRMSystem'].push({
                $: {
                    'kid': data['kid'],
                    'systemId': 'edef8ba9-79d6-4ace-a3c8-27dcd51d21ed'
                }
            });
        }
        if (drmSystemList['FP']){
            drmSystemListElement['cpix:DRMSystem'].push({
                $: {
                    'kid': data['kid'],
                    'systemId': '94ce86fb-07ff-4f43-adb8-93d2fa968ca2'
                }
            });
        }
    });
 
    root['cpix:CPIX']['cpix:ContentKeyList'] = contentKeyList;
    root['cpix:CPIX']['cpix:ContentKeyUsageRuleList'] = contentKeyUsageList;
    root['cpix:CPIX']['cpix:DRMSystemList'] = drmSystemListElement;
 
    let builder = new xml2js.Builder({ headless: true, renderOpts: { pretty: false } });
    let xml = builder.buildObject(root);
 
    let keyInfo = function () {
        this.getKeyInfo = function (key, prefix) {
            return `<X509Data><X509Certificate>${publicCert}</X509Certificate></X509Data>`;
        }
    }
 
    // Signing document with KeyOS User's/ESP Partner's private key
    let sig = new SignedXml();
    sig.keyInfoProvider = new keyInfo()
    sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    sig.addReference('//*[local-name(.)="CPIX"]', ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], 'http://www.w3.org/2001/04/xmlenc#sha512', '', '', '', true);
    sig.signingKey = privateKey;
    sig.computeSignature(xml);
 
    let rootSigned = sig.getSignedXml();
 
    // In case ESP Partner's End-user's certificate provided, add it into the CPIX request
    // and sign it.
    if (secondaryPublicCert) {
        let secondaryKeyInfo = function () {
            this.getKeyInfo = function (key, prefix) {
                return `<X509Data><X509Certificate>${secondaryPublicCert}</X509Certificate></X509Data>`;
            }
        }
 
        // Adding end user's signature to the already signed root
        let secondarySig = new SignedXml();
        secondarySig.keyInfoProvider = new secondaryKeyInfo()
        secondarySig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
        secondarySig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        secondarySig.addReference('//*[local-name(.)="CPIX"]', ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], 'http://www.w3.org/2001/04/xmlenc#sha512', '', '', '', true);
        secondarySig.signingKey = secondaryPrivateKey;
        secondarySig.computeSignature(xml);
 
        rootSigned = rootSigned.replace('</cpix:CPIX>', `${secondarySig.getSignatureXml()}</cpix:CPIX>`);
    }
 
    return rootSigned;
}
 
/**
 * Verifies the CPIX response by checking its type (string vs XML) and its signature.
 *
 * @param {string} cpixResponse response returned by the KeyOS CPIX API
 * @param {string} publicCpixApiCertPath path to the KeyOS CPIX API's Public Certificate
 * @returns Object parsed KeyOS CPIX API response
 */
exports.verifyResponse = function(cpixResponse, publicCpixApiCertPath) {
    let parsedResponse = '';
 
    let builder = new xml2js.Builder({ headless: true, renderOpts: { pretty: false } });
    let parser = new xml2js.Parser();
    parser.parseString(cpixResponse, function (err, result) {
        if (err)
            throw `Error parsing the response. Error: ${err} Response: ${result}`
 
        parsedResponse = result;
    });
 
    // Get response signature
    let signature = builder.buildObject({ 'Signature': parsedResponse['cpix:CPIX']['Signature'][0] });
 
    // Create the verifier
    let sig = new SignedXml()
 
    // KeyOS public certificate for CPIX response signature validation
    sig.keyInfoProvider = new FileKeyInfo(publicCpixApiCertPath);
 
    sig.loadSignature(signature);
 
    // Verify signature of the response
    if (!sig.checkSignature(cpixResponse))
        throw sig.validationErrors;
 
    return parsedResponse;
}
 
/**
 * Verifies MAC values for all the Content Keys.
 *
 * @param {Object} cpixResponse The CPIX response XML object
 * @param {String} privateKey Path to the KeyOS customer's private key.
 */
exports.verifyMacValues = function(cpixResponse, privateKeyPath) {
    let privateKey = fs.readFileSync(privateKeyPath);
    let macMethod = cpixResponse['cpix:CPIX']['cpix:DeliveryDataList'][0]['cpix:DeliveryData'][0]['cpix:MACMethod'][0];
    let macKey = macMethod['cpix:Key'][0]['enc:CipherData'][0]['enc:CipherValue'][0];
    let macKeyBytes = Buffer.from(macKey, 'base64');
 
    let macKeyPlainBytes = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        macKeyBytes
    )
 
    // Generate MAC Value for every key returned to check validity
    let contentkeys = cpixResponse['cpix:CPIX']['cpix:ContentKeyList'];
    contentkeys.forEach((key) => {
        let cekSecret = key['cpix:ContentKey'][0]['cpix:Data'][0]['pskc:Secret'][0];
        let cek = cekSecret['pskc:EncryptedValue'][0]['enc:CipherData'][0]['enc:CipherValue'][0];
        let cekBytes = Buffer.from(cek, 'base64');
        let cekMacValue = cekSecret['pskc:ValueMAC'][0];
 
        // Get HMAC value
        let hmac = crypto.createHmac('sha512', macKeyPlainBytes)
        hmac.update(cekBytes)
 
        let macValueHex = hmac.digest('base64')
 
        if (macValueHex != cekMacValue)
            throw `MAC values don't match for CEK: ${cek}`;
    });
}
 
/**
 * Decrypts content keys returned by the CPIX APIs
 *
 * @param {Object} cpixResponse parsed KeyOS CPIX API response
 * @param {String} privateKey Path to the KeyOS customer's private key.
 * @returns {Array} List of decrypted Content Keys in hex and corresponding Key IDs in UUID/GUID format
 */
exports.decryptContentKeys = function(cpixResponse, privateKeyPath) {
    let privateKey = fs.readFileSync(privateKeyPath);
    let documentKey = cpixResponse['cpix:CPIX']['cpix:DeliveryDataList'][0]['cpix:DeliveryData'][0]['cpix:DocumentKey'][0];
    let documentKeyBytes = Buffer.from(documentKey['cpix:Data'][0]['pskc:Secret'][0]['pskc:EncryptedValue'][0]['enc:CipherData'][0]['enc:CipherValue'][0], 'base64');
 
    // Decrypt document key using own private key
    let documentKeyPlainBytes = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        documentKeyBytes
    )
 
    let contentKeysPlain = [];
 
    // Decrypt content keys
    let contentkeys = cpixResponse['cpix:CPIX']['cpix:ContentKeyList'];
    contentkeys.forEach((key) => {
        let kid = key['cpix:ContentKey'][0].$['kid'];
        let cekSecret = key['cpix:ContentKey'][0]['cpix:Data'][0]['pskc:Secret'][0];
 
        // iv(16 bytes) + encrypted content key(32 bytes)
        let cekValueBytes = Buffer.from(cekSecret['pskc:EncryptedValue'][0]['enc:CipherData'][0]['enc:CipherValue'][0], 'base64');
 
        // By default, the AES.block_size is 16 bytes
        // First 16 bytes are the IV bytes
        let cekIvBytes = cekValueBytes.slice(0, 16);
 
        // Whatever goes after the 16th byte are content key bytes(32 bytes)
        let cekBytes = cekValueBytes.slice(16);
 
        // Decrypt content key using the document key
        let decipher = crypto.createDecipheriv('aes-256-cbc', documentKeyPlainBytes, cekIvBytes);
        let dec = decipher.update(cekBytes, 'bytes', 'hex');
        dec += decipher.final();
 
        contentKeysPlain.push({ 'cek': dec, 'kid': kid });
    });
 
    return contentKeysPlain;
}
 
/**
 * Get PSSH boxes for corresponding Content Keys
 *
 * @param {Array} contentKeys
 * @param {Object} cpixResponse
 * @returns Array of PSSH boxes for different DRM systems for corresponding Content Keys
 */
exports.getPsshBoxes = function(contentKeys, cpixResponse) {
    let drmSystemList = cpixResponse['cpix:CPIX']['cpix:DRMSystemList'][0]['cpix:DRMSystem'];
    let psshBoxes = [];
 
    contentKeys.forEach((cekKid) => {
        drmSystemList.forEach((drmSystem) => {
            if (cekKid['kid'] === drmSystem.$['kid']) {
                let o = { 'cek': cekKid['cek'], 'kid': cekKid['kid'] };
 
                if (drmSystem.$['systemId'] === '9a04f079-9840-4286-ab92-e65be0885f95') {
                    o.playready = {};
                    o.playready.psshBase64 = drmSystem['cpix:PSSH'][0];
                    o.playready.psshHex = Buffer.from(o.playready.psshBase64, 'base64').toString('hex');
                }
                else if (drmSystem.$['systemId'] === 'edef8ba9-79d6-4ace-a3c8-27dcd51d21ed') {
                    o.widevine = {};
                    o.widevine.psshBase64 = drmSystem['cpix:PSSH'][0];
                    o.widevine.psshHex = Buffer.from(o.widevine.psshBase64, 'base64').toString('hex');
                }
                else if (drmSystem.$['systemId'] === '94ce86fb-07ff-4f43-adb8-93d2fa968ca2') {
                    o.fairplay = {};
 
                    // Fairplay doesn't need any pssh boxes. But some encoders/packagers may require it
                    // so one of the ways to create it is the following.
                    let kidHex = cekKid['kid'].replace(/-/g, '');
                    o.fairplay.psshHex = `00000034707373680100000029701fe43cc74a348c5bae90c7439a4700000001${kidHex}00000000`;
                }
 
                psshBoxes.push(o);
            }
        });
    });
 
    return psshBoxes;
}